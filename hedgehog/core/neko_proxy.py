"""§ctl-neko: прокси к браузерному MCP-серверу neko (@playwright/mcp) для ctl-ручки.

neko — ОТДЕЛЬНЫЙ MCP-сервер (streamable-HTTP, http://hedgehog-neko:9250/mcp), не
наши in-process хендлеры. Под omniroute имена `mcp__neko_browser__*` коверкает
шлюз → нативно недоступны. Проксируем их через ctl-ручку: ctl_server зовёт
NekoProxy.call(tool, args), тот — реальный tools/call у neko, результат в stdout.

Почему ПОСТОЯННАЯ сессия на чат (не per-call):
  - neko запущен с `--shared-browser-context` → наша MCP-сессия драйвит ТУ ЖЕ
    вкладку, что видит пользователь (проверено вживую);
  - но snapshot-refs (`ref=eN`) привязаны к сессии — per-call сессия ломала бы
    snapshot→click. Поэтому держим одну сессию и переиспользуем.

Почему actor-таска: streamablehttp_client/ClientSession — anyio-context-менеджеры,
их надо входить И выходить в ОДНОЙ таске (иначе «cancel scope in a different
task»). Поэтому всё I/O к neko живёт в одной таске `_run`, а call()/aclose()
общаются с ней через очередь. Всё на главном event-loop, без нитей.
"""
from __future__ import annotations

import asyncio

import structlog

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

log = structlog.get_logger("neko_proxy")

_HANDSHAKE_TIMEOUT = 10.0     # initialize + list_tools
_CALL_TIMEOUT = 180.0        # потолок одного tools/call (> playwright nav 60с)


class NekoProxy:
    """Постоянный MCP-клиент к neko; всё I/O — в одной actor-таске."""

    def __init__(self, url: str):
        self._url = url
        self._q: asyncio.Queue = asyncio.Queue()
        self._task: asyncio.Task | None = None
        self.catalog: dict[str, dict] = {}   # name -> {description, input_schema}

    def _ensure_task(self) -> None:
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self._run(), name="neko-proxy")

    async def call(self, tool: str | None, args: dict,
                   timeout: float = _CALL_TIMEOUT):
        """Выполнить tools/call (tool=None → только прогреть соединение+каталог).
        Возвращает mcp CallToolResult (или None для прогрева)."""
        self._ensure_task()
        fut: asyncio.Future = asyncio.get_running_loop().create_future()
        await self._q.put((tool, args, fut))
        return await asyncio.wait_for(fut, timeout)

    async def list_tools(self, timeout: float = _HANDSHAKE_TIMEOUT) -> dict:
        """Каталог neko-тулов (коннектится при необходимости)."""
        if not self.catalog:
            await self.call(None, {}, timeout)
        return self.catalog

    async def aclose(self) -> None:
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except BaseException:  # noqa: BLE001 — вкл. (Base)ExceptionGroup от anyio
                pass
            self._task = None
        # Дренируем очередь: НЕзабранные запросы иначе висели бы до своего таймаута.
        while not self._q.empty():
            try:
                _, _, fut = self._q.get_nowait()
            except asyncio.QueueEmpty:
                break
            if not fut.done():
                fut.cancel()

    async def _run(self) -> None:
        # Owns enter/exit обоих контекст-менеджеров В ЭТОЙ таске. Внешний цикл —
        # переподключение после сбоя транспорта (shared-context переживает).
        while True:
            tool, args, fut = await self._q.get()    # ждём первый запрос (ленивый коннект)
            try:
                async with streamablehttp_client(
                        self._url, timeout=_HANDSHAKE_TIMEOUT,
                        sse_read_timeout=300) as (reader, writer, _):
                    async with ClientSession(reader, writer) as s:
                        await asyncio.wait_for(s.initialize(), _HANDSHAKE_TIMEOUT)
                        lt = await asyncio.wait_for(s.list_tools(), _HANDSHAKE_TIMEOUT)
                        self.catalog = {t.name: {"description": t.description or "",
                                                 "input_schema": t.inputSchema or {}}
                                        for t in lt.tools}
                        log.info("neko.connected", tools=len(self.catalog))
                        while True:                  # обслуживаем, пока жив транспорт
                            try:
                                if tool is None:
                                    if not fut.done():
                                        fut.set_result(None)   # прогрев
                                else:
                                    res = await s.call_tool(tool, args)
                                    if not fut.done():
                                        fut.set_result(res)
                            except asyncio.CancelledError:
                                raise
                            except Exception as e:   # noqa: BLE001 — сбой вызова
                                if not fut.done():
                                    fut.set_exception(e)
                                raise                # транспорт в неизвестном сост. → реконнект
                            tool, args, fut = await self._q.get()
            except BaseException as e:   # noqa: BLE001
                # anyio task-group заворачивает ошибки в (Base)ExceptionGroup:
                # отмену (cancel из aclose) — пробрасываем и гасим fut; транспортный
                # сбой — фейлим fut понятным текстом и реконнектимся следующим запросом.
                cancelled = isinstance(e, asyncio.CancelledError) or (
                    isinstance(e, BaseExceptionGroup)
                    and e.subgroup(asyncio.CancelledError) is not None)
                if not fut.done():
                    if cancelled:
                        fut.cancel()
                    else:
                        fut.set_exception(
                            RuntimeError(f"neko browser unavailable: {e!r}"))
                if cancelled:
                    raise
                log.warning("neko.transport_error", err=repr(e))
