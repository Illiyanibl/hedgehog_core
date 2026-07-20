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
from collections import deque
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
)

from ..config import Config
from ..ids import new_ulid
from ..protocol import Err, make_error
from ..store.chats import ChatMeta
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
        # Число незакрытых запросов текущего хода: первичный prompt + каждый
        # досланный /btw. Ход завершается (agent_done), только когда счётчик
        # обнуляется — все запросы получили свой ResultMessage. См. _turn.
        self._outstanding = 0
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
        """Обработать входящее сообщение. Возврат: True — сообщение влито в
        текущий ход (/btw-досыл), False — поставлено обычным ходом.

        Правило (очередь пуста → напрямую, не пуста → /btw): если агент занят
        и клиент подключён — вливаем реплику в идущий ход через client.query()
        (stdin CLI), агент подхватывает её по ходу. Иначе — обычная очередь.
        """
        await self.start()
        if self._busy and self._client is not None:
            await self._inject(content)
            await self._emit_status()
            return True
        await self._queue.put(content)
        await self._emit_status()  # idle→busy при первом сообщении
        return False

    async def _inject(self, content: str):
        """Досыл реплики в идущий ход (/btw): +1 к счётчику незакрытых
        запросов и запись в stdin CLI. Ход не завершится, пока не придёт
        ResultMessage на каждый query (см. _turn)."""
        self._outstanding += 1
        log.info("agent.btw_inject", chat=self.meta.chatId,
                 outstanding=self._outstanding)
        await self._client.query(content)

    def resolve_permission(self, related: str, decision: str) -> bool:
        return self._resolve(related, decision)

    def resolve_picker(self, related: str, option_id: str) -> bool:
        return self._resolve(related, option_id)

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
            self._outstanding = 1          # первичный запрос хода
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
                self._outstanding = 0
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
            if self._mcp_servers:
                opts["mcp_servers"] = self._mcp_servers
            # Гейт скиллов (§skills): непустой allowlist → включаем эти
            # скиллы и открываем CLI источники user/project, иначе он не
            # найдёт папки .claude/skills. Пусто/None → ничего не трогаем
            # (blast radius = 0, поведение как было — скиллы выключены).
            if self.meta.skills:
                opts["skills"] = list(self.meta.skills)
                opts["setting_sources"] = ["user", "project"]
            # Токен из чатной авторизации (§13): setup-token не пишет
            # ~/.claude/.credentials.json, поэтому подкладываем его CLI
            # через env. Если файла нет — работаем на базовых кредах.
            oauth = self._config.load_oauth_token()
            if oauth:
                opts["env"] = {"CLAUDE_CODE_OAUTH_TOKEN": oauth}
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
                # старым коннектом — считаем один незакрытый запрос (ретрай).
                self._outstanding = 1
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

        # receive_messages() — непрерывный поток (не останавливается на
        # ResultMessage). Останавливаемся сами, когда закрыты ВСЕ запросы хода
        # (_outstanding == 0): первичный prompt + все досланные /btw. Досыл
        # (_inject) увеличивает счётчик и пишет ещё один query в тот же stdin,
        # его ответ идёт в этот же ход — agent_done эмитим один раз, в конце.
        async for msg in client.receive_messages():
            if isinstance(msg, SystemMessage):
                # init-сообщение несёт session_id — сохраняем сразу, чтобы
                # даже оборванный ход можно было резюмить.
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
                self._outstanding -= 1
                if self._outstanding <= 0:
                    usage = msg.usage or {}
                    await self._publish("agent_done", {
                        "result": msg.result or "",
                        "usage": {
                            "input_tokens": usage.get("input_tokens", 0),
                            "output_tokens": usage.get("output_tokens", 0),
                        },
                    })
                    # Перепроверка после await: если во время публикации влетел
                    # досыл (_inject увеличил счётчик) — не выходим, дочитываем
                    # его ответ в этот же ход.
                    if self._outstanding <= 0:
                        break

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
