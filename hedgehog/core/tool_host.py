"""§multi-cli: общая база сессий агента — вспомогательные методы, на которые
опираются встроенные MCP-тулы Ёжика (core/hedgehog_mcp.py): окна (views),
серверные хендлеры, KV, отправка файлов в чат, ask_ui, notify, режим формул.

Вынесено из ClaudeSession без изменения логики, чтобы ту же базу использовала
AntigravitySession (и будущие CLI): тулы живут в одном месте. Миксин ожидает от
класса: `meta`, `_config`, `_publish`, `request()`, `handle_user_msg()` и
`_client_caps`/`_caps_sticky`.
"""

from __future__ import annotations

import asyncio
import json
import mimetypes
import re
import shutil
from pathlib import Path
from typing import Any

import structlog

from ..fileserver import _safe_name
from ..ids import new_ulid
from ..store import handlers_registry
from ..store import views_registry

log = structlog.get_logger("tool_host")


class HedgehogToolHost:
    # Живые возможности рендера клиента (set_client_caps); sticky — последний
    # непустой набор (cron-ход без подписчиков).
    _client_caps: frozenset = frozenset()
    _caps_sticky: frozenset = frozenset()
    # §multi-cli: приём новых сообщений закрыт (set_cli/stop) — handle_user_msg
    # бросает SessionClosed, а не оживляет остановленную сессию.
    _intake_closed: bool = False

    def close_intake(self) -> None:
        self._intake_closed = True

    def take_queued(self) -> list[tuple[str, Any]]:
        """§multi-cli (§18.5): забрать необработанную очередь user_msg
        (content, on_result) — при смене CLI/рестарте она переезжает в новую
        сессию. Идущий СЕЙЧАС ход сюда не входит (он прерывается остановкой)."""
        out: list[tuple[str, Any]] = []
        while True:
            try:
                out.append(self._queue.get_nowait())
            except asyncio.QueueEmpty:
                return out

    def pending_request_ids(self) -> list[str]:
        """id ожидающих ответа *_request (permission/picker/ui): сервер помнит
        их, чтобы поздний ответ после смены CLI тихо игнорировать."""
        return [k for k, fut in self._pending.items() if not fut.done()]

    def set_client_caps(self, caps) -> None:
        """Обновить ЖИВЫЕ возможности рендера клиента. Зовётся из wss-слоя при
        client_hello/client_caps_update и при подписке/отписке (hub.caps_for_chat
        → union подписанных).

        Значение читает тул formula_mode В МОМЕНТ отрисовки формулы — поэтому
        сессию НЕ пересобираем (прежний rebuild+resume «замораживал» режим на
        старте, Fable Б1). Просто обновляем поле. Пустой набор (нет подписчиков)
        НЕ сбрасывает — держим sticky последний непустой (cron-ход без клиентов)."""
        caps = frozenset(caps)
        if caps:
            self._caps_sticky = caps
            self._client_caps = caps
        else:
            self._client_caps = self._caps_sticky or frozenset()

    def formula_mode(self) -> str:
        """Живой режим рендера формул для тула mcp__hedgehog__formula_mode:
        latex (клиент типографит $$…$$), webview (ui_open+MathJax), text."""
        caps = self._client_caps
        if "math" in caps:
            return "latex"
        if "webview" in caps:
            return "webview"
        return "text"

    async def _notify(self, title: str, body: str) -> bool:
        """§notify: общий путь для MCP-тула notify и текстового протокола
        (_run_text_tools) — чтобы поведение не расходилось. Триммим+обрезаем,
        пустое пропускаем. True, если отправлено."""
        title = str(title or "").strip()[:200]
        body = str(body or "").strip()[:1000]
        if not title and not body:
            return False
        await self._publish("notification", {"title": title, "body": body})
        log.info("notify.sent", chat=self.meta.chatId,
                 title=title[:40], size=len(body))
        return True

    # §views: тонкие обёртки над реестром окон (data_dir/views.json). Реестр —
    # источник правды «какое окно запущено» + история явных закрытий; на нём
    # держится детерминированный пушер переоткрытия (клиентский ui_reopen) и
    # интроспекция агентом (ui_current). Ошибки реестра не должны ронять тул.
    def _view_open(self, *, title: str, html: str, allow_external: bool,
                   kind: str = "app") -> dict | None:
        try:
            return views_registry.record_open(
                self._config.data_dir, self.meta.chatId,
                title=title, html=html, persistent=True,
                allow_external=allow_external, kind=kind)
        except OSError as e:
            log.warning("views.open_failed", chat=self.meta.chatId, err=str(e))
            return None

    def _view_update(self, html: str) -> None:
        try:
            views_registry.record_update(
                self._config.data_dir, self.meta.chatId, html)
        except OSError as e:
            log.warning("views.update_failed", chat=self.meta.chatId, err=str(e))

    def _view_close(self) -> None:
        try:
            views_registry.record_close(self._config.data_dir, self.meta.chatId)
        except OSError as e:
            log.warning("views.close_failed", chat=self.meta.chatId, err=str(e))

    def _view_snapshot(self) -> dict:
        try:
            return views_registry.get(self._config.data_dir, self.meta.chatId)
        except OSError:
            return {"current": None, "history": []}

    def _view_reopen(self, view_id: str) -> dict | None:
        try:
            return views_registry.reopen(
                self._config.data_dir, self.meta.chatId, view_id)
        except OSError:
            return None

    def _view_get(self, view_id: str) -> dict | None:
        try:
            return views_registry.get_view(
                self._config.data_dir, self.meta.chatId, view_id)
        except OSError:
            return None

    def _chat_file_path(self, file_id: str) -> str | None:
        """§draw: fileId → абсолютный путь файла в хранилище чата (для Read)."""
        if not file_id or not file_id.isalnum():
            return None
        files_dir = self._config.chats_dir / self.meta.chatId / "files"
        try:
            matches = sorted(files_dir.glob(f"{file_id}__*")) \
                if files_dir.exists() else []
        except OSError:
            return None
        return str(matches[0]) if matches else None

    # §handlers Ф-2: тонкие обёртки над реестром ручек (data_dir/handlers.json).
    def _handler_register(self, name: str, script: str,
                          view_id: str | None) -> dict | None:
        try:
            return handlers_registry.register(
                self._config.data_dir, self.meta.chatId, name, script, view_id)
        except OSError as e:
            log.warning("handler.register_failed", chat=self.meta.chatId, err=str(e))
            return None

    def _handler_list(self) -> list[dict]:
        try:
            return handlers_registry.list_(self._config.data_dir, self.meta.chatId)
        except OSError:
            return []

    def _handler_get(self, name: str) -> dict | None:
        try:
            return handlers_registry.get(
                self._config.data_dir, self.meta.chatId, name)
        except OSError:
            return None

    def _handler_unregister(self, name: str) -> bool:
        try:
            return handlers_registry.unregister(
                self._config.data_dir, self.meta.chatId, name)
        except OSError:
            return False

    # §ui Ф-1: общий per-server key-value стор (data_dir/kv.json) — состояние
    # между окнами и чатами (счётчики и т.п.). Один процесс Ёжика, async
    # single-thread → read-modify-write без гонок.
    def _kv_path(self):
        return self._config.data_dir / "kv.json"

    def _kv_load(self) -> dict:
        try:
            data = json.loads(self._kv_path().read_text())
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def _kv_set(self, key: str, value: str) -> None:
        if not key:
            return
        data = self._kv_load()
        data[key] = value
        self._config.data_dir.mkdir(parents=True, exist_ok=True)
        tmp = self._kv_path().with_suffix(".json.tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False))
        tmp.replace(self._kv_path())

    def _kv_get(self, key: str) -> str:
        return str(self._kv_load().get(key, ""))

    async def handle_ui_event(self, data: str) -> None:
        """§ui async: действие в постоянном окне (hedgehog.notify) → полноценный
        ход агента, как обычное сообщение. Claude может делать что угодно."""
        log.info("ui.event", chat=self.meta.chatId, size=len(data or ""))
        await self.handle_user_msg(data or "(empty ui event)")

    async def _ask_ui(self, html: str, title: str) -> str:
        """§ui: показать интерактивный HTML в чате и дождаться ответа юзера.
        Тем же round-trip, что picker/permission (_pending future).

        S2-M2: окно интерактивное — юзер может думать дольше permission_timeout
        (300с), поэтому ждём по большому ui_timeout. И перехватываем таймаут: без
        этого asyncio.TimeoutError вылетал из тела тула (в отличие от permission-
        пути) → тул падал ошибкой, окно висело с мёртвым related. Теперь тул
        возвращает человекочитаемый текст, агент продолжает штатно."""
        try:
            data = await self.request(
                "ui_request", {"html": html, "title": title},
                timeout=self._config.ui_timeout)
        except asyncio.TimeoutError:
            log.info("ui.timeout", chat=self.meta.chatId,
                     after=int(self._config.ui_timeout))
            return (f"(no answer: the interactive window timed out after "
                    f"{int(self._config.ui_timeout)}s)")
        log.info("ui.answered", chat=self.meta.chatId, size=len(data or ""))
        return data or "(the user closed the window without answering)"

    async def _attach_file_to_chat(self, path: str) -> str:
        p = Path(path)
        if not p.is_absolute():
            p = Path(self.meta.cwd) / path
        if not p.is_file():
            return f"file not found: {path}"
        files_dir = self._config.chats_dir / self.meta.chatId / "files"
        files_dir.mkdir(parents=True, exist_ok=True)
        file_id = new_ulid()
        # Если путь указывает на файл из хранилища чата (<ulid>__имя), отрезаем
        # служебный ulid-префикс — пользователю показываем чистое имя.
        display = re.sub(r"^[0-9A-HJKMNP-TV-Z]{26}__", "", p.name)
        safe = _safe_name(display)
        dest = files_dir / f"{file_id}__{safe}"
        try:
            shutil.copy2(p, dest)
        except OSError as e:
            return f"failed to copy file: {e}"
        size = dest.stat().st_size
        mime = mimetypes.guess_type(safe)[0] or "application/octet-stream"
        await self._publish("agent_file", {
            "fileId": file_id, "name": safe, "mime": mime, "size": size,
        })
        log.info("agent.file_sent", chat=self.meta.chatId, file=file_id,
                 name=safe, size=size)
        return f"file '{safe}' sent to the user in the chat"

    async def _attach_bytes_to_chat(self, name: str, data: bytes,
                                    mime: str | None = None) -> str:
        """§image: доставить СЫРЫЕ байты (сгенерированная картинка) карточкой в
        чат — тем же путём, что _attach_file_to_chat (agent_file-фрейм), но без
        файла-источника: пишем сразу в files_dir (без temp и двойного копирования
        многомегабайтных байтов). `name` — осмысленное имя с расширением."""
        files_dir = self._config.chats_dir / self.meta.chatId / "files"
        files_dir.mkdir(parents=True, exist_ok=True)
        file_id = new_ulid()
        safe = _safe_name(name) or "image.png"
        dest = files_dir / f"{file_id}__{safe}"
        try:
            dest.write_bytes(data)
        except OSError as e:
            return f"failed to write image: {e}"
        size = dest.stat().st_size
        if not mime:
            mime = mimetypes.guess_type(safe)[0] or "application/octet-stream"
        await self._publish("agent_file", {
            "fileId": file_id, "name": safe, "mime": mime, "size": size,
        })
        log.info("agent.file_sent", chat=self.meta.chatId, file=file_id,
                 name=safe, size=size, src="bytes")
        return f"image '{safe}' sent to the user in the chat"
