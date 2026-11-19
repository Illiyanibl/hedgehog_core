"""§multi-cli (§20): сессия чата поверх OpenAI Codex (`codex app-server`,
JSON-RPC по stdio). Тот же контракт, что у ClaudeSession/AntigravitySession:
очередь user_msg, один ход за раз, те же фреймы наружу (text_delta, tool_use,
tool_result, agent_done, permission_request, error), прерывание, resume.

Особенности Codex 0.167 (проверено живьём):
- текст идёт токен-стримом (`item/agentMessage/delta`);
- песочница bwrap в контейнерах недоступна → права держим сами:
  `approvalPolicy=untrusted` (запрос на всё, кроме заведомо безопасного) и
  `sandbox=danger-full-access`; `bypassPermissions` → `never`;
- запросы разрешений приходят серверными запросами (commandExecution /
  fileChange / permissions / mcpServer/elicitation) — решает политика Ёжика;
- прерывание — `turn/interrupt` (ход закрывается `turn/completed` со статусом
  `interrupted`); `turn/steer` намеренно не используется (решение §20).
"""

from __future__ import annotations

import asyncio
import os
import sys
from typing import Any

import structlog

from ..i18n import Msg
from ..ids import new_ulid
from ..protocol import Err
from .acp_client import AcpClient, AcpClosed, AcpRpcError
from . import codex_auth
from .acp_common import clip_text, has_http_code
from .agent_session_base import MCP_BRIDGE, AgentSessionBase
from .claude_session import HEDGEHOG_FORMULA_APPEND, HEDGEHOG_SYSTEM_APPEND
from .hedgehog_mcp import BUILTIN_MCP_NAME
from .permissions import ToolRequest

log = structlog.get_logger("codex")

CLI_TYPE = "codex"
# Системные инструкции Ёжика: Codex принимает их отдельным каналом (thread
# developerInstructions) — без префикса в первом сообщении.
CODEX_DEV_INSTRUCTIONS = HEDGEHOG_SYSTEM_APPEND + HEDGEHOG_FORMULA_APPEND
_OUT_CAP = 20000


def codex_mode(permission_mode: str) -> tuple[str, str]:
    """permission_mode Ёжика → (approvalPolicy, sandbox) Codex (§20).

    default/acceptEdits: `untrusted` (спрашивает про всё, кроме безопасного) —
    решения принимает политика Ёжика; песочница по умолчанию выключена
    (`danger-full-access`: bwrap в контейнерах не работает), переопределяется
    env HEDGEHOG_CODEX_SANDBOX (read-only | workspace-write | danger-full-access).
    bypassPermissions: без запросов и без ограничений."""
    if permission_mode == "bypassPermissions":
        return "never", "danger-full-access"
    sandbox = os.environ.get("HEDGEHOG_CODEX_SANDBOX", "danger-full-access")
    if sandbox not in ("read-only", "workspace-write", "danger-full-access"):
        sandbox = "danger-full-access"
    return "untrusted", sandbox


def classify_error(text: str) -> tuple[str, Any]:
    """Текст ошибки Codex → (код §8, сообщение пользователю)."""
    low = text.lower()
    # Голые «login»/«log in»/«authentication» исключены: встречаются в чужих
    # ошибках (имена файлов в stderr). Остальное защищено тем, что
    # CodexAuthManager.start() не затирает живой токен.
    if has_http_code(low, 401) or any(m in low for m in ("unauthorized", "not logged in",
                              "please log in", "please sign in",
                              "token expired", "refresh token",
                              "authentication failed")):
        return Err.AUTH_REQUIRED, Msg("codex.auth_required")
    if any(m in low for m in ("usage limit", "rate limit", "rate_limit",
                              "quota", "limit reached")) or has_http_code(low, 429):
        return Err.RATE_LIMITED, Msg("codex.rate_limited")
    return Err.AGENT_CRASH, f"Codex failed: {text[:300]}"


def codex_mcp_config(servers: dict[str, dict] | None) -> dict[str, dict]:
    """Реестр MCP Ёжика (формат Claude SDK) → `config.mcp_servers` Codex."""
    out: dict[str, dict] = {}
    for name, cfg in (servers or {}).items():
        if not isinstance(cfg, dict):
            continue
        if cfg.get("url") and cfg.get("type") in (None, "http", "sse"):
            entry: dict[str, Any] = {"url": cfg["url"]}
            if cfg.get("headers"):
                entry["http_headers"] = {k: str(v)
                                         for k, v in cfg["headers"].items()}
            out[name] = entry
        elif cfg.get("command"):
            entry = {"command": cfg["command"],
                     "args": list(cfg.get("args") or [])}
            if cfg.get("env"):
                entry["env"] = {k: str(v) for k, v in cfg["env"].items()}
            out[name] = entry
    return out


def _clip(text: Any) -> str:
    return clip_text(text, _OUT_CAP)


def _mcp_result_text(item: dict) -> str:
    err = item.get("error")
    if err:
        return _clip(err.get("message") if isinstance(err, dict) else err)
    res = item.get("result")
    if isinstance(res, dict):
        parts = [c.get("text", "") for c in res.get("content") or []
                 if isinstance(c, dict) and c.get("type") == "text"]
        if parts:
            return _clip("\n".join(parts))
    return _clip(res)


class CodexSession(AgentSessionBase):
    CLI_TYPE = CLI_TYPE
    SERVER_ARGS = ("app-server",)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._suppress = False
        self._thread_id: str | None = None
        self._turn_id: str | None = None
        self._turn_done = asyncio.Event()
        self._turn_status: str | None = None
        self._turn_error: str | None = None
        self._items: dict[str, dict] = {}        # id → item (fileChange: пути)
        self._delta_items: set[str] = set()      # у каких agentMessage были дельты
        self._turn_usage = [0, 0]                # input, output за ход

    def _spawn_extra_env(self) -> dict[str, str]:
        return codex_auth.codex_extra_env()

    def _classify_error(self, text: str):
        return classify_error(text)

    # ---------- процесс и тред ----------

    def _mcp_config(self) -> dict[str, dict]:
        cfg = codex_mcp_config(self._mcp_servers)
        cfg[BUILTIN_MCP_NAME] = {"command": sys.executable,
                                 "args": [MCP_BRIDGE],
                                 "env": self._bridge_env()}
        return cfg

    def _thread_params(self) -> dict[str, Any]:
        approval, sandbox = codex_mode(self.meta.permission_mode)
        params: dict[str, Any] = {
            "cwd": self.meta.cwd, "approvalPolicy": approval,
            "sandbox": sandbox,
            "config": {"mcp_servers": self._mcp_config()},
            "developerInstructions": CODEX_DEV_INSTRUCTIONS}
        model = self._state().get("model") or self.meta.model
        rec = codex_auth.alt_record()
        if rec.get("method") == "gateway":
            ids = {m.get("id") for m in rec.get("models") or []}
            if model not in ids:                     # модель прежнего способа не годится
                model = rec.get("active_id")
        if model:
            params["model"] = model
        return params

    async def _open_session(self, client: AcpClient) -> None:
        await client.request("initialize", {
            "clientInfo": {"name": "hedgehog", "title": "Hedgehog",
                           "version": "1"},
            "capabilities": {}}, timeout=30)
        await client.notify("initialized")
        params = self._thread_params()
        tid = self._saved_session_id()
        opened = False
        if tid:
            self._suppress = True
            try:
                await client.request("thread/resume", {
                    "threadId": tid, **params}, timeout=60)
                opened = True
            except AcpRpcError as e:
                log.info("codex.resume_failed", chat=self.meta.chatId,
                         err=str(e))
            finally:
                self._suppress = False
        if not opened:
            res = await client.request("thread/start", params, timeout=60)
            tid = ((res or {}).get("thread") or {}).get("id")
            if not tid:
                raise RuntimeError("codex thread/start returned no thread id")
            if self._on_session_id is not None:
                self._on_session_id(tid)
        self._thread_id = tid
        self._session_id = tid
        log.info("codex.connected", chat=self.meta.chatId, thread=self._thread_id)

    # ---------- уведомления ----------

    async def _on_notification(self, method: str, params: dict) -> None:
        if self._suppress:
            return
        if params.get("threadId") not in (None, self._thread_id):
            return
        if method == "item/agentMessage/delta":
            delta = params.get("delta") or ""
            iid = params.get("itemId") or ""
            if delta:
                self._delta_items.add(iid)
                self._turn_text.append(delta)
                await self._emit_delta(delta, iid or self._agent_msg_id)
        elif method == "item/started":
            await self._on_item_started(params.get("item") or {})
        elif method == "item/completed":
            await self._on_item_completed(params.get("item") or {})
        elif method == "thread/tokenUsage/updated":
            last = ((params.get("tokenUsage") or {}).get("last") or {})
            self._turn_usage[0] += int(last.get("inputTokens") or 0)
            self._turn_usage[1] += int(last.get("outputTokens") or 0)
        elif method == "turn/completed":
            turn = params.get("turn") or {}
            self._turn_status = turn.get("status")
            err = turn.get("error")
            if err:                         # не затираем причину из `error`-уведомления
                self._turn_error = str(err.get("message") if isinstance(err, dict)
                                       else err)
            self._turn_done.set()
        elif method == "error":
            err = params.get("error")
            msg = err.get("message") if isinstance(err, dict) else err
            if msg and not params.get("willRetry"):
                self._turn_error = str(msg)

    def _tool_name_for(self, item: dict) -> str:
        t = item.get("type")
        if t == "commandExecution":
            return "Bash"
        if t == "fileChange":
            kinds = {((c.get("kind") or {}).get("type"))
                     for c in item.get("changes") or [] if isinstance(c, dict)}
            return "Write" if kinds == {"add"} else "Edit"
        if t == "mcpToolCall":
            return f"mcp__{item.get('server')}__{item.get('tool')}"
        if t == "webSearch":
            return "WebSearch"
        return str(t)

    def _tool_input(self, item: dict) -> dict:
        t = item.get("type")
        if t == "commandExecution":
            return {"command": item.get("command"), "cwd": item.get("cwd")}
        if t == "fileChange":
            return {"changes": [{"path": c.get("path"),
                                 "kind": (c.get("kind") or {}).get("type"),
                                 "diff": _clip(c.get("diff"))[:2000]}
                                for c in item.get("changes") or []
                                if isinstance(c, dict)]}
        if t == "mcpToolCall":
            return item.get("arguments") if isinstance(
                item.get("arguments"), dict) else {}
        if t == "webSearch":
            return {"query": item.get("query")}
        return {}

    _TOOL_ITEMS = ("commandExecution", "fileChange", "mcpToolCall", "webSearch")

    async def _on_item_started(self, item: dict) -> None:
        iid, t = item.get("id"), item.get("type")
        if not iid:
            return
        self._items[iid] = item
        if t in self._TOOL_ITEMS and iid not in self._seen_tools:
            self._seen_tools.add(iid)
            await self._flush_delta()       # хвост текста — до карточки тула
            await self._publish("tool_use", {
                "tool_use_id": iid, "tool": self._tool_name_for(item),
                "rawName": t, "input": self._tool_input(item)})

    async def _on_item_completed(self, item: dict) -> None:
        iid, t = item.get("id"), item.get("type")
        if not iid:
            return
        self._items[iid] = item
        if t == "agentMessage":
            if iid not in self._delta_items and item.get("text"):
                # нет дельт (короткий ответ целиком) — публикуем текст как есть
                self._turn_text.append(item["text"])
                await self._flush_delta()
                await self._publish("text_delta", {
                    "delta": item["text"], "agent_msg_id": iid})
            return
        if t not in self._TOOL_ITEMS or iid in self._done_tools:
            return
        if iid not in self._seen_tools:          # started пропущен — досылаем
            self._seen_tools.add(iid)
            await self._publish("tool_use", {
                "tool_use_id": iid, "tool": self._tool_name_for(item),
                "rawName": t, "input": self._tool_input(item)})
        self._done_tools.add(iid)
        status = item.get("status")
        if t == "commandExecution":
            code = item.get("exitCode")
            out, bad = (_clip(item.get("aggregatedOutput")),
                        status == "failed" or code not in (0, None))
        elif t == "fileChange":
            out = "\n".join(f"{(c.get('kind') or {}).get('type')} {c.get('path')}"
                            for c in item.get("changes") or []
                            if isinstance(c, dict))
            bad = status == "failed"
        elif t == "mcpToolCall":
            out, bad = _mcp_result_text(item), status == "failed"
        else:
            out, bad = "", status == "failed"
        await self._publish("tool_result", {
            "tool_use_id": iid, "output": out, "is_error": bad})

    # ---------- запросы от Codex (разрешения, ввод) ----------

    async def _on_request(self, method: str, params: dict) -> Any:
        if method == "item/commandExecution/requestApproval":
            return await self._approve_command(params)
        if method == "item/fileChange/requestApproval":
            return await self._approve_file_change(params)
        if method == "item/permissions/requestApproval":
            return await self._approve_permissions(params)
        if method == "mcpServer/elicitation/request":
            return await self._approve_mcp(params)
        if method == "item/tool/requestUserInput":
            return await self._ask_user_input(params)
        raise AcpRpcError(-32601, f"method not found: {method}")

    async def _approve_command(self, params: dict) -> dict:
        ans = await self._decide(ToolRequest(
            name="Bash", kind="execute",
            input={"command": params.get("command"), "cwd": params.get("cwd")}))
        return {"decision": {"allow": "accept", "allow_always": "accept",
                             "deny": "decline", "cancel": "cancel"}[ans]}

    async def _approve_file_change(self, params: dict) -> dict:
        item = self._items.get(params.get("itemId") or "") or {}
        changes = [c for c in item.get("changes") or [] if isinstance(c, dict)]
        paths = [c["path"] for c in changes if c.get("path")]
        ans = await self._decide(ToolRequest(
            name=self._tool_name_for(item) if item else "Edit", kind="edit",
            input=self._tool_input(item) if item else {"reason": params.get("reason")},
            paths=paths))
        return {"decision": {"allow": "accept", "allow_always": "accept",
                             "deny": "decline", "cancel": "cancel"}[ans]}

    async def _approve_permissions(self, params: dict) -> dict:
        ans = await self._decide(ToolRequest(
            name="Permissions", kind="other",
            input={"permissions": params.get("permissions"),
                   "reason": params.get("reason")}))
        if ans in ("allow", "allow_always"):
            return {"permissions": params.get("permissions") or {},
                    "scope": "turn"}
        return {"permissions": {}}

    async def _approve_mcp(self, params: dict) -> dict:
        meta = params.get("_meta") or {}
        if meta.get("codex_approval_kind") != "mcp_tool_call":
            # настоящий elicitation MCP-сервера (вопрос пользователю), а не
            # подтверждение вызова — пока не поддерживаем
            return {"action": "decline", "content": None}
        tool = meta.get("tool_name") or ""
        server = params.get("serverName") or ""
        inp = meta.get("tool_params") or meta.get("arguments") or {}
        ans = await self._decide(ToolRequest(
            name=f"mcp__{server}__{tool}", kind="other",
            input=inp if isinstance(inp, dict) else {}))
        return {"action": {"allow": "accept", "allow_always": "accept",
                           "deny": "decline", "cancel": "cancel"}[ans],
                "content": None}

    async def _ask_user_input(self, params: dict) -> dict:
        """item/tool/requestUserInput → picker_request на каждый вопрос."""
        answers: dict[str, dict] = {}
        for q in params.get("questions") or []:
            options = [{"id": str(i), "label": o.get("label", str(o))}
                       for i, o in enumerate(q.get("options") or [])]
            try:
                option_id = await self.request("picker_request", {
                    "question": q.get("question", ""), "options": options,
                    "multi": False})
            except asyncio.TimeoutError:
                option_id = ""
            try:
                label = options[int(option_id)]["label"]
            except (ValueError, IndexError):
                label = option_id          # произвольный текст клиента
            answers[q.get("id", "")] = {"answers": [label] if label else []}
        return {"answers": answers}

    # ---------- ход ----------

    async def _turn(self, prompt: str) -> tuple[str, bool]:
        self._interrupt_evt.clear()      # ДО старта процесса (прерывание не теряем)
        client = await self._ensure_client()
        self._turn_text.clear()
        self._stream_red.reset()
        self._seen_tools.clear()
        self._done_tools.clear()
        self._delta_items.clear()
        self._items.clear()
        self._turn_usage = [0, 0]
        self._turn_status = self._turn_error = None
        self._turn_id = None
        self._turn_done.clear()
        params: dict[str, Any] = {
            "threadId": self._thread_id,
            "input": [{"type": "text", "text": prompt}]}
        effort = self._state().get("effort")
        if effort:
            params["effort"] = effort
        res = await client.request("turn/start", params, timeout=60)
        self._turn_id = ((res or {}).get("turn") or {}).get("id")
        wait_done = asyncio.create_task(self._turn_done.wait())
        wait_int = asyncio.create_task(self._interrupt_evt.wait())
        wait_dead = asyncio.create_task(client.wait_closed())
        try:
            await asyncio.wait({wait_done, wait_int, wait_dead},
                               return_when=asyncio.FIRST_COMPLETED)
            if not self._turn_done.is_set() and not client.alive:
                # процесс Codex умер посреди хода — иначе ждали бы вечно
                raise AcpClosed("codex process exited during the turn")
            if not self._turn_done.is_set():      # новое сообщение прерывает ход
                try:
                    await client.request("turn/interrupt", {
                        "threadId": self._thread_id,
                        "turnId": self._turn_id},
                        timeout=self.INTERRUPT_TIMEOUT)
                except AcpRpcError as e:          # ход уже закончился — не ошибка
                    log.info("codex.interrupt_noop", chat=self.meta.chatId,
                             err=str(e))
                try:
                    await asyncio.wait_for(self._turn_done.wait(),
                                           self.INTERRUPT_TIMEOUT)
                except asyncio.TimeoutError:
                    log.warning("codex.interrupt_timeout", chat=self.meta.chatId)
                    await self._drop_client()     # следующий ход — thread/resume
        finally:
            wait_done.cancel()
            wait_int.cancel()
            wait_dead.cancel()
        if self._turn_status == "failed" or (
                self._turn_status is None and self._turn_error):
            raise RuntimeError(self._turn_error or "codex turn failed")
        text = "".join(self._turn_text)
        await self._flush_delta()
        await self._publish("agent_done", {
            "result": text,
            "usage": {"input_tokens": self._turn_usage[0],
                      "output_tokens": self._turn_usage[1]}})
        self._agent_msg_id = new_ulid()
        return text, self._turn_status == "completed"
