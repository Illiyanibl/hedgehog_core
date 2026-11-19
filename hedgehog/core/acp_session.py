"""Общий каркас ACP-сессий (Antigravity, Grok): initialize → resume/load/new →
настройка модели; поток session/update → фреймы Ёжика; ответ на
session/request_permission через политику; ход с прерыванием.

Подкласс задаёт отличия хуками (см. ниже) и остаётся короче на ~150 строк.
CTL_GATE=True: эти CLI не спрашивают разрешение на MCP-инструменты Ёжика, их
вызовы гейтит ctl_server (§18.8, §21.3).
"""

from __future__ import annotations

import asyncio
from typing import Any

import structlog

from ..ids import new_ulid
from .acp_client import AcpClient, AcpRpcError
from .acp_common import acp_mcp_servers, pick_option, tool_output
from .agent_session_base import AgentSessionBase
from .hedgehog_mcp import BUILTIN_MCP_NAME
from .permissions import ToolRequest, extract_paths

log = structlog.get_logger("acp_session")


class AcpSessionBase(AgentSessionBase):
    CTL_GATE = True
    LOG_TAG = "acp"                 # префикс событий лога (agy/grok)
    # Пользовательские MCP-серверы идут через гейтящий мост Ёжика. Нужно CLI, у
    # которого нет собственных правил прав на MCP (Antigravity); у Grok правило
    # `ask = MCPTool(*)` в управляемом GROK_HOME делает то же нативно.
    PROXY_USER_MCP = False

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._suppress = False      # глушим session/update при resume/load

    # ---------- хуки подкласса ----------

    def _tool_identity(self, upd: dict) -> tuple[str, str]:
        """(каноническое имя инструмента, сырое имя) из tool_call/запроса прав."""
        raise NotImplementedError

    def _tool_input(self, upd: dict) -> Any:
        raise NotImplementedError

    def _new_session_params(self, mcp: list[dict]) -> dict:
        return {"cwd": self.meta.cwd, "mcpServers": mcp}

    def _on_new_session(self, res: dict) -> None:
        """Сессия создана заново (не resume): первые ходы, кэши и т.п."""

    async def _apply_settings(self, client: AcpClient, sid: str) -> None:
        """Модель/уровень рассуждения после открытия сессии."""

    async def _on_ext_notification(self, method: str, params: dict,
                                   upd: dict) -> None:
        """Уведомления кроме session/update (расширения вендора)."""

    def _prepare_prompt(self, prompt: str) -> str:
        return prompt

    def _turn_finished(self, finished: bool) -> None:
        """Ход закончился (в т.ч. отменой) — до публикации agent_done."""

    async def _inspect_turn_text(self, text: str) -> None:
        """Итоговый текст хода (CLI иногда отдаёт ошибки обычным текстом)."""

    async def _usage(self, result: dict, finished: bool) -> dict:
        usage = (result or {}).get("usage") or {}
        return {"input_tokens": usage.get("inputTokens", 0),
                "output_tokens": usage.get("outputTokens", 0)}

    def _turn_reset(self) -> None:
        """Начало хода: сброс счётчиков подкласса."""

    # ---------- открытие сессии ----------

    def _acp_mcp_list(self) -> list[dict]:
        # имя встроенного сервера зарезервировано: пользовательский MCP с таким
        # именем не подменяет мост (как у Claude: builtin перекрывает)
        user: list[dict] = []
        for name, cfg in self._mcp_servers.items():
            if name == BUILTIN_MCP_NAME:
                continue
            if (name == "neko_browser" or self.PROXY_USER_MCP) \
                    and self.ensure_mcp_proxy(name) is not None:
                # §H1: CLI не спрашивает разрешение на MCP — сервер идёт через
                # мост `--server NAME` и гейтится в ctl_server
                user.append(self._bridge_entry(name))
                continue
            user += acp_mcp_servers({name: cfg})
        return user + [self._bridge_entry()]

    async def _open_session(self, client: AcpClient) -> None:
        init = await client.request("initialize", {
            "protocolVersion": 1, "clientCapabilities": {}}, timeout=30)
        caps = (init or {}).get("agentCapabilities") or {}
        sess_caps = caps.get("sessionCapabilities") or {}
        mcp = self._acp_mcp_list()
        sid = self._saved_session_id()
        opened = False
        if sid:
            self._suppress = True      # resume/load не должен перерисовать ленту
            try:
                for method, ok in (("session/resume", "resume" in sess_caps),
                                   ("session/load", bool(caps.get("loadSession")))):
                    if ok:
                        await client.request(method, {
                            "sessionId": sid, "cwd": self.meta.cwd,
                            "mcpServers": mcp}, timeout=60)
                        opened = True
                        break
            except AcpRpcError as e:
                log.info(f"{self.LOG_TAG}.resume_failed",
                         chat=self.meta.chatId, err=str(e))
            finally:
                self._suppress = False
        if not opened:
            res = await client.request(
                "session/new", self._new_session_params(mcp), timeout=60)
            sid = res["sessionId"]
            self._on_new_session(res)
            if self._on_session_id is not None:
                self._on_session_id(sid)
        self._session_id = sid
        await self._apply_settings(client, sid)
        log.info(f"{self.LOG_TAG}.connected", chat=self.meta.chatId, session=sid)

    # ---------- входящее от CLI ----------

    async def _on_notification(self, method: str, params: dict) -> None:
        if self._suppress:
            return
        if params.get("sessionId") not in (None, self._session_id):
            return
        upd = params.get("update") or {}
        if method != "session/update":
            await self._on_ext_notification(method, params, upd)
            return
        kind = upd.get("sessionUpdate")
        if kind == "agent_message_chunk":
            text = (upd.get("content") or {}).get("text") or ""
            if text:
                self._turn_text.append(text)
                await self._emit_delta(text, self._agent_msg_id)
        elif kind == "tool_call":
            tid = upd.get("toolCallId")
            if tid and tid not in self._seen_tools:
                self._seen_tools.add(tid)
                await self._flush_delta()       # хвост текста — до карточки тула
                name, raw = self._tool_identity(upd)
                await self._publish("tool_use", {
                    "tool_use_id": tid, "tool": name, "rawName": raw,
                    "input": self._tool_input(upd)})
        elif kind == "tool_call_update":
            tid = upd.get("toolCallId")
            status = upd.get("status")
            if tid and status in ("completed", "failed") \
                    and tid not in self._done_tools:
                self._done_tools.add(tid)
                await self._publish("tool_result", {
                    "tool_use_id": tid, "output": tool_output(upd),
                    "is_error": status == "failed"})

    async def _on_request(self, method: str, params: dict) -> Any:
        if method == "session/request_permission":
            return await self._handle_permission(params)
        raise AcpRpcError(-32601, f"method not found: {method}")

    async def _handle_permission(self, params: dict) -> dict:
        call = params.get("toolCall") or {}
        options = params.get("options") or []
        name, _raw = self._tool_identity(call)
        req = ToolRequest(name=name, kind=call.get("kind"),
                          input=self._tool_input(call), paths=extract_paths(call))
        ans = await self._decide(req)
        if ans == "cancel":
            return {"outcome": {"outcome": "cancelled"}}
        allow, always = ans in ("allow", "allow_always"), ans == "allow_always"
        oid = pick_option(options, allow, always)
        if oid is None:                      # нет подходящего варианта — отмена
            return {"outcome": {"outcome": "cancelled"}}
        if allow and name.startswith("mcp__"):
            self._mcp_grants[name] = self._mcp_grants.get(name, 0) + 1
        return {"outcome": {"outcome": "selected", "optionId": oid}}

    # ---------- ход ----------

    async def _turn(self, prompt: str) -> tuple[str, bool]:
        # clear ДО старта процесса: прерывание, пришедшее во время запуска CLI,
        # не должно теряться
        self._interrupt_evt.clear()
        client = await self._ensure_client()
        self._turn_text.clear()
        self._stream_red.reset()
        self._seen_tools.clear()          # id уникальны в рамках хода; без роста
        self._done_tools.clear()
        self._mcp_grants.clear()           # «да» действует в пределах хода
        self._turn_reset()
        text_in = self._prepare_prompt(prompt)
        prompt_task = asyncio.create_task(client.request("session/prompt", {
            "sessionId": self._session_id,
            "prompt": [{"type": "text", "text": text_in}]}))
        wait_evt = asyncio.create_task(self._interrupt_evt.wait())
        try:
            await asyncio.wait({prompt_task, wait_evt},
                               return_when=asyncio.FIRST_COMPLETED)
            if not prompt_task.done():         # прерывание новым сообщением
                await client.notify("session/cancel",
                                    {"sessionId": self._session_id})
                try:
                    await asyncio.wait_for(asyncio.shield(prompt_task),
                                           self.INTERRUPT_TIMEOUT)
                except asyncio.TimeoutError:
                    log.warning(f"{self.LOG_TAG}.cancel_timeout",
                                chat=self.meta.chatId)
                    prompt_task.cancel()
                    await self._drop_client()
            finished = prompt_task.done() and not prompt_task.cancelled()
            result = prompt_task.result() if finished else {}
        finally:
            wait_evt.cancel()
            if not prompt_task.done():
                prompt_task.cancel()
        result = result or {}
        self._turn_finished(finished)
        text = "".join(self._turn_text)
        await self._inspect_turn_text(text)
        await self._flush_delta()
        await self._publish("agent_done", {
            "result": text, "usage": await self._usage(result, finished)})
        self._agent_msg_id = new_ulid()
        return text, finished and result.get("stopReason") in ("end_turn", None)
