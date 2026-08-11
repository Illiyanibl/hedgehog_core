"""ClaudeSession — чат с Claude через claude-agent-sdk. Без PTY.

Поток (docs/broker-audit.md, раздел «Связь с Claude Agent SDK»):
    user_msg → ClaudeSDKClient.query() → receive_response():
        AssistantMessage/TextBlock  → text_delta
        AssistantMessage/ToolUseBlock → tool_use
        UserMessage/ToolResultBlock → tool_result
        ResultMessage               → agent_done

Permission-flow: SDK-callback `can_use_tool` шлёт permission_request и
ждёт asyncio.Future, которую резолвит permission_response от клиента
(§4.5). `allow_always` запоминается на время жизни сессии чата (§3.2).

AskUserQuestion → picker_request тем же механизмом (§4.6): отвечаем SDK
PermissionResultAllow с updated_input, где в каждый question дописан
"answer" с выбранным label. Формат answer-поля в SDK формально не
задокументирован — валидируется e2e-тестом Phase 1a.

Сообщения пользователя обрабатываются строго последовательно через
внутреннюю очередь: второй user_msg во время работы агента не теряется,
а ждёт завершения текущей итерации.
"""

from __future__ import annotations

import asyncio
import json
import mimetypes
import re
import shutil
import time
from collections import deque
from pathlib import Path
from typing import Any

import structlog
from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    ClaudeSDKClient,
    PermissionResultAllow,
    PermissionResultDeny,
    ResultMessage,
    SystemMessage,
    TextBlock,
    ToolPermissionContext,
    ToolResultBlock,
    ToolUseBlock,
    UserMessage,
    create_sdk_mcp_server,
    tool,
)

from ..config import Config
from ..fileserver import _safe_name
from ..ids import new_ulid
from ..protocol import Err, make_error
from ..store.chats import ChatMeta
from ..store import views_registry
from ..store import handlers_registry
from . import handler_runner
from .session_base import PublishFn

log = structlog.get_logger("claude_session")

# Маркеры auth-ошибок SDK/CLI (логаут, протухший/отозванный токен) —
# такие падения классифицируются как AUTH_REQUIRED, а не AGENT_CRASH.
_AUTH_ERROR_MARKERS = (
    "invalid api key",
    "please run /login",
    "authentication_error",
    "oauth token has expired",
    "oauth token is invalid",
    "not logged in",
)


def is_auth_error(err_text: str) -> bool:
    low = err_text.lower()
    return any(marker in low for marker in _AUTH_ERROR_MARKERS)


# Маркеры «resume не удался» (файл сессии CLI удалён/недоступен) — такой
# ход повторяется в свежей сессии, а не падает AGENT_CRASH'ем.
_RESUME_ERROR_MARKERS = (
    "no conversation found",
    "session not found",
    "unknown session",
)


def is_resume_error(err_text: str) -> bool:
    low = err_text.lower()
    return any(marker in low for marker in _RESUME_ERROR_MARKERS)


class ClaudeSession:
    def __init__(self, meta: ChatMeta, publish: PublishFn,
                 send_chat_error, config: Config,
                 mcp_servers: dict[str, dict] | None = None,
                 on_auth_required=None, on_session_id=None, on_status=None):
        self.meta = meta
        self._publish = publish
        self._send_chat_error = send_chat_error  # (code, message) → journal+fanout
        self._config = config
        # Разрешённые MCP-серверы (имя→конфиг SDK) — резолвит wss-слой из
        # реестра при создании сессии (§12).
        self._mcp_servers = mcp_servers or {}
        # Зовётся при падении SDK с auth-ошибкой — wss-слой запускает
        # авто-авторизацию (AuthManager, §13).
        self._on_auth_required = on_auth_required
        # Персист session_id CLI в meta.json (sync-callback wss-слоя) —
        # основа resume контекста после рестарта Ёжика.
        self._on_session_id = on_session_id
        # Событие смены статуса busy⇄idle (async-callback wss-слоя) —
        # глобальный broadcast chat_status + будущий хук пушей. Шлём только
        # на РЕАЛЬНОЙ смене (дедуп по _last_status).
        self._on_status = on_status
        self._last_status = "idle"
        # id, с которым реально резюмили текущий клиент (для фолбэка).
        self._resumed_from: str | None = None
        # Хвост stderr CLI: исключение SDK generic («exit code 1»), причина
        # (напр. «No conversation found») видна только в stderr.
        self._stderr_tail: deque[str] = deque(maxlen=20)

        self._client: ClaudeSDKClient | None = None
        self._queue: asyncio.Queue[str] = asyncio.Queue()
        self._worker: asyncio.Task | None = None
        # True, пока агент обрабатывает user_msg (для get_status, §3.7c).
        self._busy = False
        # related frame id → (future решения, контекст для маппинга ответа)
        self._pending: dict[str, tuple[asyncio.Future, dict]] = {}
        # Ответы, пришедшие раньше регистрации future: publish() уже отдал
        # фрейм в сокет, а _wait_answer ещё не выполнился (гонка при
        # мгновенном авто-ответе тестового клиента).
        self._early_answers: dict[str, str] = {}
        self._always_allowed: set[str] = set()

    # ---------- lifecycle ----------

    async def start(self):
        if self._worker is None:
            self._worker = asyncio.create_task(self._run(), name=f"claude:{self.meta.chatId}")

    async def stop(self):
        if self._worker:
            self._worker.cancel()
            try:
                await self._worker
            except (asyncio.CancelledError, Exception):
                pass
            self._worker = None
        await self._disconnect()
        for fut, _ in self._pending.values():
            if not fut.done():
                fut.cancel()
        self._pending.clear()

    async def _disconnect(self):
        if self._client is not None:
            try:
                await self._client.disconnect()
            except Exception as e:
                log.info("sdk.disconnect_failed", chat=self.meta.chatId, err=str(e))
            self._client = None

    # ---------- входящие фреймы ----------

    async def handle_user_msg(self, content: str) -> bool:
        """Поставить сообщение в очередь. Всегда возвращает False.

        Каждое сообщение — отдельный ход строго по очереди: воркер читает ответ
        ПОЛНОСТЬЮ (receive_response до ResultMessage), затем берёт следующее.
        Порядок «сообщение→ответ» гарантирован (без гонки idle-grace, которая
        ломала старый досыл через query() в тот же ход).

        §btw-interrupt (A1): если агент СЕЙЧАС занят ходом — ПРЕРЫВАЕМ текущий
        ход (client.interrupt()), чтобы досланное сообщение поехало СЛЕДУЮЩИМ
        ходом с полным контекстом (та же сессия). Так «стой»/уточнение доходят
        сразу, а не ждут конца длинного хода. Ходы остаются раздельными:
        прерванный отдаёт свой ResultMessage, воркер берёт из очереди наше.
        """
        await self.start()
        await self._queue.put(content)
        # A1: любое сообщение при занятом агенте прерывает текущий ход.
        if self._busy and self._client is not None:
            await self._interrupt_current()
        await self._emit_status()  # idle→busy при первом сообщении
        return False

    async def _interrupt_current(self) -> None:
        """Прервать текущий ход (§btw-interrupt A1) — best-effort, не роняет
        обработчик. interrupt() работает только в streaming-режиме SDK
        (--input-format stream-json), где мы и живём."""
        client = self._client
        if client is None:
            return
        try:
            await client.interrupt()
            log.info("agent.interrupt", chat=self.meta.chatId)
        except Exception as e:  # noqa: BLE001
            log.warning("agent.interrupt_failed", chat=self.meta.chatId,
                        err=repr(e))

    def resolve_permission(self, related: str, decision: str) -> bool:
        return self._resolve(related, decision)

    def resolve_picker(self, related: str, option_id: str) -> bool:
        return self._resolve(related, option_id)

    def resolve_ui(self, related: str, data: str) -> bool:
        """§ui: результат взаимодействия с интерактивным HTML (ask_ui)."""
        return self._resolve(related, data)

    def _resolve(self, related: str, answer: str) -> bool:
        entry = self._pending.pop(related, None)
        if entry is None:
            # Ответ обогнал регистрацию future — придержим (см. __init__).
            if len(self._early_answers) > 256:
                self._early_answers.clear()  # мусор от битых related
            self._early_answers[related] = answer
            return True
        fut, _ = entry
        if not fut.done():
            fut.set_result(answer)
        return True

    # ---------- worker ----------

    async def _run(self):
        while True:
            prompt = await self._queue.get()
            self._busy = True
            try:
                await self._one_turn(prompt)
            except asyncio.CancelledError:
                raise
            except Exception as e:
                err_text = repr(e) + " " + " ".join(self._stderr_tail)
                if is_auth_error(err_text):
                    log.warning("agent.auth_required", chat=self.meta.chatId,
                                err=err_text[-300:])
                    await self._send_chat_error(
                        Err.AUTH_REQUIRED,
                        "Claude на сервере не авторизован — открой ссылку "
                        "авторизации и пришли код (auth_code)")
                    if self._on_auth_required is not None:
                        await self._on_auth_required()
                else:
                    log.error("agent.crash", chat=self.meta.chatId, err=repr(e))
                    await self._send_chat_error(Err.AGENT_CRASH,
                                                f"Claude SDK failed: {e}")
                # Свежее подключение на следующий user_msg.
                await self._disconnect()
            finally:
                self._busy = False
                await self._emit_status()  # busy→idle, когда очередь пуста

    @property
    def status(self) -> str:
        """§3.7c: busy — агент работает или в очереди есть сообщения."""
        return "busy" if self._busy or not self._queue.empty() else "idle"

    async def _emit_status(self):
        """Сообщить wss-слою о РЕАЛЬНОЙ смене статуса (busy⇄idle)."""
        s = self.status
        if s == self._last_status:
            return
        self._last_status = s
        if self._on_status is None:
            return
        try:
            await self._on_status(s)
        except Exception as e:  # noqa: BLE001 — broadcast не должен ронять воркер
            log.warning("status.emit_failed", chat=self.meta.chatId, err=repr(e))

    # ---------- отправка файлов агентом в чат (§7, обратное направление) ----------

    def _make_hedgehog_mcp(self):
        """In-process MCP-сервер: инструмент attach_file — агент отправляет
        файл ПОЛЬЗОВАТЕЛЮ в текущий чат (карточка в ленте)."""
        session = self

        @tool(
            "attach_file",
            "Send a file to the USER in the current chat — it appears as a card "
            "they can open/save. Call this after generating a file "
            "(PDF, image, document, etc.). path — absolute path or "
            "relative to the working directory.",
            {"path": str},
        )
        async def attach_file(args: dict[str, Any]) -> dict[str, Any]:
            text = await session._attach_file_to_chat(str(args.get("path", "")))
            return {"content": [{"type": "text", "text": text}]}

        @tool(
            "ask_ui",
            "Show the USER an interactive window (WebView) in the chat and WAIT "
            "for their action. The phone renders the HTML itself, locally, offline. "
            "\n\nHTML — a COMPLETE self-contained document (inline CSS/JS, no "
            "external resources). Build REAL mini-apps with their own "
            "state and logic in JS: games, trainers, counters, forms, buttons, "
            "drawing tools. Example: a word-pair trainer (e.g. two languages) with a "
            "correct/incorrect COUNTER on top — all matching logic and the score live "
            "in the page's JS, not via questions. Dark theme, large touch targets.\n\n"
            "LINK BACK TO YOU: in the HTML call `hedgehog.submit(data)` — data (a "
            "string or JSON) is returned as the result of this tool, unblocking "
            "you. The window STAYS OPEN: the next ask_ui call REPLACES its "
            "content (same window, no flicker).\n\n"
            "LIVE LOOP (react to every action): if you need to respond to "
            "EVERY tap with your own content — loop it: show ask_ui → the user "
            "taps → submit returns the event to you → you come up with NEW content → "
            "ask_ui again, and so on until the user closes the window (then an empty "
            "string is returned — finish). Example: a big red button; on each click you "
            "come up with a new joke about the red button and show it via the "
            "same ask_ui. title — a short window title.",
            {"html": str, "title": str},
        )
        async def ask_ui(args: dict[str, Any]) -> dict[str, Any]:
            answer = await session._ask_ui(
                str(args.get("html", "")),
                str(args.get("title", "") or "Interactive"))
            return {"content": [{"type": "text", "text": answer}]}

        @tool(
            "ui_open",
            "Open a PERSISTENT interactive window (WebView) in the chat and "
            "return control IMMEDIATELY (does NOT block the turn). The window lives "
            "until you close it (ui_close) or the user does. User actions arrive "
            "ASYNCHRONOUSLY: in the HTML call `hedgehog.notify(data)` — it arrives "
            "to you as a REGULAR chat message, and you can react with anything "
            "(text in chat, bash, docker, any tool) and/or update the window "
            "via ui_update. Do local effects (change color, etc.) "
            "right in the JS without notify. Example: a mouse with a button on its "
            "tail — on click the JS colors the mouse + notify('button pressed') → you "
            "write a fact about mice in the chat. Or a red button → notify('spin up a "
            "random container') → you do it. There's also `hedgehog.submit(data)`, but "
            "that's for the blocking ask_ui; for a persistent window use notify. html — "
            "a self-contained document; title — the window title. "
            "\n\nSDK inside the window (a ready-made pattern, don't invent your own): "
            "`hedgehog.notify(data)` — event → your turn; "
            "`hedgehog.action(id, data)` — a named action (you route by id); "
            "`hedgehog.chat(text)` — text straight to the chat; "
            "`hedgehog.open(url)` — open a link in the system browser. "
            "Shared state across windows/chats — the kv_set/kv_get tools "
            "(e.g. a mouse counter). allow_external=true → the window is ALLOWED "
            "external network (embed YouTube/a site in an iframe); by default it's an "
            "offline sandbox.",
            {"html": str, "title": str, "allow_external": bool},
        )
        async def ui_open(args: dict[str, Any]) -> dict[str, Any]:
            html = str(args.get("html", ""))
            title = str(args.get("title", "") or "Interactive")
            allow_external = bool(args.get("allow_external", False))
            # §views: сперва фиксируем окно в реестре (получаем стабильный id),
            # затем пушим — чтобы клиент СРАЗУ знал view_id (для §draw).
            # Тот же title при повторном ui_open обновляет ТО ЖЕ окно.
            rec = session._view_open(
                title=title, html=html, allow_external=allow_external)
            vid = (rec or {}).get("id", "")
            await session._publish("ui_request", {
                "html": html,
                "title": title,
                "persistent": True,
                "allow_external": allow_external,
                "view_id": vid,
                "kind": "app",
            })
            return {"content": [{"type": "text", "text":
                f"Window opened (view_id={vid}). Change its content via "
                "ui_update (the same title in ui_open also updates this window), "
                "close it with ui_close. Actions from the window — hedgehog.notify/"
                "action/chat/open. Data from a DB — handler_register + hedgehog.call "
                "(the handler binds to this window right away). State — kv_set/get."}]}

        @tool(
            "ui_update",
            "Replace the content of an OPEN window (ui_open) with new HTML — the "
            "phone redraws the same WebView. html — a complete self-contained document.",
            {"html": str},
        )
        async def ui_update(args: dict[str, Any]) -> dict[str, Any]:
            html = str(args.get("html", ""))
            # §views надёжность: кадр ui_update ИГНОРИРУЕТСЯ клиентом, если окно
            # на нём закрыто/пропало (pendingUI=nil). Поэтому пушим ui_request —
            # его клиент показывает ВСЕГДА: открыто → перерисуется на месте (тот
            # же webview), свёрнуто → бейдж, закрыто/пропало → покажется заново.
            snap = session._view_snapshot()
            cur = snap.get("current")
            src = cur if isinstance(cur, dict) else None
            if src is None:
                hist = snap.get("history") or []
                src = hist[0] if hist and isinstance(hist[0], dict) else {}
            title = src.get("title", "Interactive")
            kind = src.get("kind", "app")
            allow_ext = bool(src.get("allow_external", False))
            # reuse-by-title → стабильный id (у current сохраняется kind).
            rec = session._view_open(title=title, html=html,
                                     allow_external=allow_ext, kind=kind)
            vid = (rec or {}).get("id", "")
            await session._publish("ui_request", {
                "html": html, "title": title, "persistent": True,
                "allow_external": allow_ext, "view_id": vid, "kind": kind,
            })
            return {"content": [{"type": "text", "text": "Window updated."}]}

        @tool(
            "ui_close",
            "Close the open interactive window (ui_open).",
            {},
        )
        async def ui_close(args: dict[str, Any]) -> dict[str, Any]:
            await session._publish("ui_close", {})
            session._view_close()   # §views: явное закрытие → в историю чата
            return {"content": [{"type": "text", "text": "Window closed."}]}

        @tool(
            "ui_current",
            "Find out which interactive window (view) is currently running in THIS "
            "chat and a list of recently closed ones (id + title). You can reopen "
            "a closed one via ui_reopen(id).",
            {},
        )
        async def ui_current(args: dict[str, Any]) -> dict[str, Any]:
            def _ago(ts) -> str:
                try:
                    d = int(time.time() - float(ts))
                except (TypeError, ValueError):
                    return "?"
                if d < 60:
                    return f"{max(d, 0)}s ago"
                if d < 3600:
                    return f"{d // 60}min ago"
                return f"{d // 3600}h ago"

            snap = session._view_snapshot()
            cur = snap.get("current")
            lines: list[str] = []
            if isinstance(cur, dict):
                # rev — «версия пуша»: сколько раз окно пушилось (ui_open/update/
                # reopen). Растёт при каждом пуше сервера в это окно.
                dr = cur.get("drawing")
                mark = (f", drawing: {len(dr.get('figures') or [])} figures "
                        "(ui_drawing)") if isinstance(dr, dict) else ""
                lines.append(
                    f"Running now: «{cur.get('title', '')}» "
                    f"(id={cur.get('id', '')}, rev {cur.get('rev', 1)}, "
                    f"updated {_ago(cur.get('updated_at'))}{mark}).")
            else:
                lines.append("No window is open right now.")
            hist = snap.get("history") or []
            if hist:
                lines.append("Closed (can ui_reopen):")
                for h in hist:
                    if isinstance(h, dict):
                        lines.append(f"  • id={h.get('id', '')} — "
                                     f"«{h.get('title', '')}»")
            else:
                lines.append("Closed history is empty.")
            # §handlers: заодно показываем зарегистрированные ручки чата.
            recs = session._handler_list()
            if recs:
                lines.append("Handlers (hedgehog.call):")
                for r in recs:
                    lines.append(f"  • {r['name']} → {r.get('script', '')}"
                                 + (f" (window {r['view_id']})"
                                    if r.get("view_id") else ""))
            return {"content": [{"type": "text", "text": "\n".join(lines)}]}

        @tool(
            "ui_reopen",
            "Reopen a previously closed (or current) window by id from ui_current "
            "— the server shows the saved HTML again WITHOUT rebuilding it. "
            "id — the identifier of the view record.",
            {"id": str},
        )
        async def ui_reopen(args: dict[str, Any]) -> dict[str, Any]:
            rec = session._view_reopen(str(args.get("id", "")))
            if not rec:
                return {"content": [{"type": "text", "text":
                    "No view with that id (see ui_current)."}]}
            await session._publish("ui_request", {
                "html": rec.get("html", ""),
                "title": rec.get("title", "Interactive"),
                "persistent": True,
                "allow_external": bool(rec.get("allow_external", False)),
                "view_id": rec.get("id", ""),
                "kind": rec.get("kind", "app"),
            })
            return {"content": [{"type": "text", "text":
                f"Window «{rec.get('title', '')}» is open again."}]}

        @tool(
            "ui_drawing",
            "Read the user's DRAWING on a window (§draw): a webview screenshot with "
            "their drawing (be sure to view it with Read — it shows what is "
            "underlined/circled over the real state), the figure coordinates "
            "(CSS-px) and the view size. view_id is optional — defaults to the current "
            "window. This lets you understand the edits even with animation/DB data.",
            {"view_id": str},
        )
        async def ui_drawing(a: dict[str, Any]) -> dict[str, Any]:
            vid = str(a.get("view_id", "")).strip()
            if not vid:
                cur = session._view_snapshot().get("current")
                vid = (cur or {}).get("id", "") if isinstance(cur, dict) else ""
            view = session._view_get(vid) if vid else None
            dr = (view or {}).get("drawing")
            if not isinstance(dr, dict):
                return {"content": [{"type": "text", "text":
                    "This window has no drawing."}]}
            figs = dr.get("figures") or []
            parts = [f"Drawing on «{view.get('title', '')}» (view_id={vid}): "
                     f"{len(figs)} figures, view size {dr.get('size', {})}."]
            img = session._chat_file_path(dr.get("image", ""))
            if img:
                parts.append(f"Screenshot with the drawing (view it with Read): {img}")
            parts.append("Figure coordinates (CSS-px, drawing order): "
                         + json.dumps(figs, ensure_ascii=False)[:2000])
            if view.get("kind") != "blank":
                parts.append("This is an app window — edit its HTML to match the "
                             "drawing (you have the HTML from ui_open/ui_current).")
            return {"content": [{"type": "text", "text": "\n".join(parts)}]}

        # §handlers Ф-2: серверные «ручки» для окон — детерминированный доступ
        # к данным (БД) БЕЗ хода агента. Окно зовёт hedgehog.call(name, args),
        # сервер запускает скрипт (stdin=JSON → stdout=JSON). Реестр — per-chat.
        @tool(
            "handler_register",
            "Register a server HANDLER for a window: a script in the chat cwd "
            "that reads JSON args from STDIN and prints a JSON result to STDOUT. "
            "The window calls it INSTANTLY via `const r = await "
            "hedgehog.call(name, args)` — no agent turn, deterministic, zero "
            "tokens — where r is {ok:true, data:<your parsed JSON>} or "
            "{ok:false, error:'...'} (it never rejects). Ideal for scrollable DB "
            "dashboards. view_id (optional, from ui_current) binds the handler to "
            "a window so it is erased when that window is deleted. The script must "
            "live INSIDE the chat cwd.",
            {"name": str, "script": str, "view_id": str},
        )
        async def handler_register(args: dict[str, Any]) -> dict[str, Any]:
            name = str(args.get("name", "")).strip()
            script = str(args.get("script", "")).strip()
            view_id = str(args.get("view_id", "")).strip() or None
            if not name or not script:
                return {"content": [{"type": "text", "text":
                    "name and script are required."}]}
            # Авто-привязка к ТЕКУЩЕМУ окну, если view_id не задан — окно
            # удалят → ручка сотрётся вместе с ним.
            if view_id is None:
                cur = session._view_snapshot().get("current")
                if isinstance(cur, dict):
                    view_id = cur.get("id")
            # Проверим, что скрипт реально существует внутри cwd (быстрый фидбэк).
            probe = handler_runner._resolve_script(Path(session.meta.cwd), script)
            if probe is None:
                return {"content": [{"type": "text", "text":
                    f"Script not found or outside the chat cwd: {script}"}]}
            session._handler_register(name, script, view_id)
            attach = f", bound to window {view_id}" if view_id else ""
            return {"content": [{"type": "text", "text":
                f"Handler «{name}» → {script}{attach}. In the window: "
                f"await hedgehog.call(\"{name}\", args)."}]}

        @tool(
            "handler_list",
            "List the server handlers registered in THIS chat "
            "(name → script, window binding).",
            {},
        )
        async def handler_list(args: dict[str, Any]) -> dict[str, Any]:
            recs = session._handler_list()
            if not recs:
                return {"content": [{"type": "text", "text":
                    "There are no handlers in this chat."}]}
            lines = [f"  • {r['name']} → {r.get('script', '')}"
                     + (f" (window {r['view_id']})" if r.get("view_id") else "")
                     for r in recs]
            return {"content": [{"type": "text", "text":
                "Chat handlers:\n" + "\n".join(lines)}]}

        @tool(
            "handler_unregister",
            "Delete a server handler by name.",
            {"name": str},
        )
        async def handler_unregister(args: dict[str, Any]) -> dict[str, Any]:
            ok = session._handler_unregister(str(args.get("name", "")).strip())
            return {"content": [{"type": "text", "text":
                "Deleted." if ok else "No such handler (see handler_list)."}]}

        @tool(
            "handler_call",
            "Test a handler yourself: run it with arguments and see the "
            "JSON result (the way the window does via hedgehog.call). "
            "args — a JSON object as a string (e.g. '{\"date\":\"2026-08-09\"}').",
            {"name": str, "args": str},
        )
        async def handler_call(a: dict[str, Any]) -> dict[str, Any]:
            name = str(a.get("name", "")).strip()
            raw = str(a.get("args", "") or "{}")
            try:
                parsed = json.loads(raw)
            except ValueError:
                return {"content": [{"type": "text", "text":
                    "args must be a JSON object as a string."}]}
            rec = session._handler_get(name)
            if not rec:
                return {"content": [{"type": "text", "text":
                    f"No handler «{name}» (see handler_list)."}]}
            res = await handler_runner.run(
                session.meta.cwd, rec["script"], parsed)
            return {"content": [{"type": "text", "text":
                json.dumps(res, ensure_ascii=False)[:2000]}]}

        @tool(
            "kv_set",
            "Save a value under a key in the server's SHARED store (visible from ALL "
            "chats and windows). For counters/state shared across windows and chats.",
            {"key": str, "value": str},
        )
        async def kv_set(args: dict[str, Any]) -> dict[str, Any]:
            session._kv_set(str(args.get("key", "")), str(args.get("value", "")))
            return {"content": [{"type": "text", "text": "ok"}]}

        @tool(
            "kv_get",
            "Read a value by key from the server's shared store (empty if "
            "not set).",
            {"key": str},
        )
        async def kv_get(args: dict[str, Any]) -> dict[str, Any]:
            return {"content": [{"type": "text",
                                 "text": session._kv_get(str(args.get("key", "")))}]}

        return create_sdk_mcp_server(
            name="hedgehog",
            tools=[attach_file, ask_ui, ui_open, ui_update, ui_close,
                   ui_current, ui_reopen, ui_drawing,
                   handler_register, handler_list, handler_unregister,
                   handler_call, kv_set, kv_get])

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
        Тем же round-trip, что picker/permission (_pending future)."""
        frame = await self._publish("ui_request", {"html": html, "title": title})
        data = await self._wait_answer(frame["id"], {})
        log.info("ui.answered", chat=self.meta.chatId,
                 related=frame["id"][-6:], size=len(data or ""))
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

    async def _ensure_client(self) -> ClaudeSDKClient:
        if self._client is None:
            opts: dict = {
                "cwd": self.meta.cwd,
                "can_use_tool": self._can_use_tool,
                "stderr": self._stderr_tail.append,
            }
            self._stderr_tail.clear()
            # permission_mode обрабатываем САМИ в _can_use_tool, а не через
            # опцию SDK: её значение bypassPermissions превращается в CLI-флаг
            # --dangerously-skip-permissions, который запрещён под root (наш
            # контейнер — root). Свой callback работает при любом uid и даёт
            # полный контроль (см. _can_use_tool).
            # MCP: пользовательские серверы (§12) + встроенный hedgehog
            # (инструмент attach_file — агент шлёт файлы в чат).
            mcp = dict(self._mcp_servers)
            mcp["hedgehog"] = self._make_hedgehog_mcp()
            opts["mcp_servers"] = mcp
            # Гейт скиллов (§skills): непустой allowlist → включаем эти
            # скиллы и открываем CLI источники user/project, иначе он не
            # найдёт папки .claude/skills. Пусто/None → ничего не трогаем
            # (blast radius = 0, поведение как было — скиллы выключены).
            if self.meta.skills:
                opts["skills"] = list(self.meta.skills)
                opts["setting_sources"] = ["user", "project"]
            # Авторизация Claude (§13 + §altauth): режим из data/auth.json.
            #   oauth      — подписка через setup-token (env CLAUDE_CODE_OAUTH_TOKEN);
            #   apikey     — прямой API-ключ (x-api-key) [+ кастомный base_url];
            #   omniroute  — шлюз: ключ + base_url + модели шлюза на 3 тира,
            #                дефолтный тир алиасом в opts["model"].
            # env кладём ТОЛЬКО для выбранного режима (SDK мержит его поверх
            # окружения процесса) — так активный способ заменяет прошлый.
            auth = self._config.load_auth_config()
            mode = auth.get("mode", "oauth")
            env: dict[str, str] = {}
            if mode == "apikey":
                env["ANTHROPIC_API_KEY"] = auth.get("api_key", "")
                if auth.get("base_url"):
                    env["ANTHROPIC_BASE_URL"] = auth["base_url"]
            elif mode == "omniroute":
                env["ANTHROPIC_API_KEY"] = auth.get("api_key", "")
                env["ANTHROPIC_BASE_URL"] = auth.get("base_url", "")
                env["ANTHROPIC_DEFAULT_OPUS_MODEL"] = auth.get("opus_model", "")
                env["ANTHROPIC_DEFAULT_SONNET_MODEL"] = auth.get("sonnet_model", "")
                env["ANTHROPIC_DEFAULT_HAIKU_MODEL"] = auth.get("haiku_model", "")
                opts["model"] = auth.get("default_tier") or "haiku"
            else:  # oauth (по умолчанию) — setup-token не пишет creds-файл,
                # поэтому подкладываем его CLI через env; нет файла → базовые креды.
                oauth = self._config.load_oauth_token()
                if oauth:
                    env["CLAUDE_CODE_OAUTH_TOKEN"] = oauth
            if env:
                opts["env"] = env
            # Resume контекста: CLI хранит сессии на диске, meta.json помнит
            # id последней — рестарт Ёжика/set_mode больше не амнезия.
            self._resumed_from = self.meta.claude_session_id
            if self._resumed_from:
                opts["resume"] = self._resumed_from
            self._client = ClaudeSDKClient(ClaudeAgentOptions(**opts))
            await self._client.connect()
            log.info("sdk.connected", chat=self.meta.chatId, cwd=self.meta.cwd,
                     resume=self._resumed_from,
                     mcp=list(self._mcp_servers),
                     permission_mode=self.meta.permission_mode,
                     skills=list(self.meta.skills or []))
        return self._client

    async def _one_turn(self, prompt: str):
        try:
            await self._turn(prompt)
        except Exception as e:
            # Битый resume (файл сессии CLI удалён/переехал cwd) — не
            # смертельно: забываем session_id, повторяем ход в свежей сессии.
            # Причину ищем в stderr CLI: исключение SDK — generic exit code.
            err_text = repr(e) + " " + " ".join(self._stderr_tail)
            if self._resumed_from and is_resume_error(err_text):
                log.warning("sdk.resume_failed", chat=self.meta.chatId,
                            session=self._resumed_from, err=err_text[-300:])
                self._set_session_id(None)
                await self._disconnect()
                # Свежий клиент: досланные в упавший ход /btw ушли вместе со
                # старым коннектом — ретраим только первичный prompt.
                await self._turn(prompt)
            else:
                raise

    def _set_session_id(self, sid: str | None):
        if sid == self.meta.claude_session_id:
            return
        self.meta.claude_session_id = sid
        if self._on_session_id is not None:
            self._on_session_id(sid)
        log.info("sdk.session_id", chat=self.meta.chatId, session=sid)

    async def _turn(self, prompt: str):
        client = await self._ensure_client()
        await client.query(prompt)
        agent_msg_id = new_ulid()  # группирует text_delta одного ответа (§4.2)
        # Неавторизованный CLI не кидает исключение, а отвечает обычным
        # результатом «Not logged in · Please run /login» (e2e 2026-07-12).
        auth_needed = False

        # §fix: receive_response() отдаёт сообщения ДО ResultMessage включительно
        # и завершается — ход читается ПОЛНОСТЬЮ, без гонки idle-grace. Каждое
        # сообщение = свой ход (очередь, см. handle_user_msg), поэтому ответ
        # больше не теряется и не «сползает» под следующее сообщение.
        last_result: ResultMessage | None = None
        async for msg in client.receive_response():
            if isinstance(msg, SystemMessage):
                if msg.subtype == "init":
                    sid = (msg.data or {}).get("session_id")
                    if sid:
                        self._set_session_id(sid)
            elif isinstance(msg, AssistantMessage):
                for block in msg.content:
                    if isinstance(block, TextBlock):
                        await self._publish("text_delta", {
                            "delta": block.text,
                            "agent_msg_id": agent_msg_id,
                        })
                    elif isinstance(block, ToolUseBlock):
                        await self._publish("tool_use", {
                            "tool_use_id": block.id,
                            "tool": block.name,
                            "input": block.input,
                        })
                        # §grep-audit: Grep-инструмент запускает ugrep, который
                        # изредка падает (2.2 ГБ core). Логируем его аргументы в
                        # hedgehog.log (не ротируется) — при краше/подвисании
                        # последняя запись покажет виновный запрос.
                        if block.name == "Grep":
                            inp = block.input or {}
                            log.info("agent.grep", chat=self.meta.chatId,
                                     pattern=inp.get("pattern"),
                                     path=inp.get("path"),
                                     glob=inp.get("glob"),
                                     type=inp.get("type"),
                                     output_mode=inp.get("output_mode"))
            elif isinstance(msg, UserMessage):
                content = msg.content if isinstance(msg.content, list) else []
                for block in content:
                    if isinstance(block, ToolResultBlock):
                        await self._publish("tool_result", {
                            "tool_use_id": block.tool_use_id,
                            "output": _result_text(block.content),
                            "is_error": bool(block.is_error),
                        })
            elif isinstance(msg, ResultMessage):
                if is_auth_error(msg.result or ""):
                    auth_needed = True
                if msg.session_id:
                    self._set_session_id(msg.session_id)
                last_result = msg

        # Один agent_done с итоговым результатом хода.
        if last_result is not None:
            usage = last_result.usage or {}
            await self._publish("agent_done", {
                "result": last_result.result or "",
                "usage": {
                    "input_tokens": usage.get("input_tokens", 0),
                    "output_tokens": usage.get("output_tokens", 0),
                },
            })

        if auth_needed:
            log.warning("agent.auth_required_result", chat=self.meta.chatId)
            await self._send_chat_error(
                Err.AUTH_REQUIRED,
                "Claude на сервере не авторизован — открой ссылку "
                "авторизации и пришли код (auth_code)")
            if self._on_auth_required is not None:
                await self._on_auth_required()
            # Клиент бесполезен без логина; свежий — на следующий user_msg.
            await self._disconnect()

    # ---------- permission / picker (SDK callback) ----------

    # Инструменты правки файлов — авто-разрешаются в режиме acceptEdits.
    _EDIT_TOOLS = {"Write", "Edit", "MultiEdit", "NotebookEdit"}

    async def _can_use_tool(self, tool_name: str, tool_input: dict[str, Any],
                            context: ToolPermissionContext):
        # Пресеты прав (§3.7) — обрабатываем здесь, а не флагом SDK
        # (bypass-флаг запрещён под root).
        mode = self.meta.permission_mode
        try:
            # AskUserQuestion — это ВОПРОС ПОЛЬЗОВАТЕЛЮ, а не гейт прав на
            # инструмент. Показываем пикер ВСЕГДА, до проверок режима прав:
            # иначе в bypassPermissions (и в любом авто-allow) SDK молча
            # исполнит инструмент с пустыми answers — вопрос теряется, клиент
            # не видит вариантов (баг «пропадают варианты ответа»).
            if tool_name == "AskUserQuestion":
                return await self._ask_via_picker(tool_input)
            # Наш встроенный инструмент отправки файла в чат — безопасен
            # (копирует файл в files-папку чата), разрешаем без спроса.
            if tool_name == "mcp__hedgehog__attach_file":
                return PermissionResultAllow()
            if mode == "bypassPermissions":
                return PermissionResultAllow()      # автономный чат: всё без спроса
            if mode == "acceptEdits" and tool_name in self._EDIT_TOOLS:
                return PermissionResultAllow()      # правки без спроса, прочее спросим
            return await self._ask_permission(tool_name, tool_input)
        except asyncio.TimeoutError:
            await self._send_chat_error(
                Err.PERMISSION_TIMEOUT,
                f"No user response for {tool_name} within "
                f"{int(self._config.permission_timeout)}s")
            return PermissionResultDeny(
                message="user did not respond in time", interrupt=True)

    async def _ask_permission(self, tool_name: str, tool_input: dict[str, Any]):
        if tool_name in self._always_allowed:
            return PermissionResultAllow()

        frame = await self._publish("permission_request", {
            "tool": tool_name,
            "input": tool_input,
        })
        decision = await self._wait_answer(frame["id"], {})
        log.info("permission.decision", chat=self.meta.chatId,
                 tool=tool_name, decision=decision)
        if decision == "allow_always":
            self._always_allowed.add(tool_name)
        if decision in ("allow", "allow_always"):
            return PermissionResultAllow()
        return PermissionResultDeny(message="user denied")

    async def _ask_via_picker(self, tool_input: dict[str, Any]):
        """AskUserQuestion → последовательный picker_request на каждый вопрос.

        Формат ответа CLI: updated_input.answers — словарь
        {"<текст вопроса>": "<выбранный label>"} (совпадает со схемой самого
        инструмента AskUserQuestion: поле `answers`, «User answers collected
        by the permission component»). Подтверждено e2e 2026-07-05.
        """
        questions = tool_input.get("questions") or []
        answers: dict[str, str] = {}
        for q in questions:
            options = [
                {"id": str(i), "label": opt.get("label", str(opt))}
                for i, opt in enumerate(q.get("options") or [])
            ]
            frame = await self._publish("picker_request", {
                "question": q.get("question", ""),
                "options": options,
                "multi": bool(q.get("multiSelect")),
            })
            option_id = await self._wait_answer(frame["id"], {})
            try:
                label = options[int(option_id)]["label"]
            except (ValueError, IndexError):
                label = option_id  # клиент прислал произвольный текст
            answers[q.get("question", "")] = label
            log.info("picker.answered", chat=self.meta.chatId, answer=label)
        return PermissionResultAllow(
            updated_input={**tool_input, "answers": answers})

    async def _wait_answer(self, related: str, ctx: dict) -> str:
        early = self._early_answers.pop(related, None)
        if early is not None:
            return early
        fut: asyncio.Future = asyncio.get_running_loop().create_future()
        self._pending[related] = (fut, ctx)
        try:
            return await asyncio.wait_for(fut, timeout=self._config.permission_timeout)
        finally:
            self._pending.pop(related, None)


def _result_text(content: Any) -> str:
    """tool_result.content SDK: str | list[dict] | None → плоский текст."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    parts = []
    for item in content:
        if isinstance(item, dict) and item.get("type") == "text":
            parts.append(item.get("text", ""))
    return "\n".join(parts)
