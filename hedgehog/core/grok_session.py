"""§multi-cli (§21): сессия чата поверх Grok Build CLI (`grok agent stdio`, ACP).

Тот же контракт, что у AntigravitySession (очередь user_msg, один ход за раз,
фреймы наружу: text_delta/tool_use/tool_result/agent_done/permission_request/
error, прерывание, resume). Особенности grok 1.0.77 (проверено живьём):
- `session/request_permission` приходит на НЕ read-only shell и на ПРАВКИ файлов
  (в т.ч. вне cwd, с diff) → у Grok есть edit_gate; read-only shell он
  разрешает сам. Решает общая политика Ёжика; sandbox по умолчанию выключен;
- MCP-инструменты grok НЕ спрашивает → CTL_GATE (гейт в ctl_server), а вызывает
  их через мета-инструменты `search_tool`/`use_tool` (tool_name `server__tool`);
- имя инструмента — в `_meta["x.ai/tool"].name`; результат (вывод) приходит в
  tool_call_update.content; токены — в `_x.ai/session_notification:turn_completed`;
- модель/эффорт: `session/set_config_option` (значение — строка);
- лимитов через ACP нет (`grok usage` — только TUI).
"""

from __future__ import annotations

import asyncio
import contextlib
from typing import Any

import structlog

from ..i18n import Msg
from ..protocol import Err
from .acp_client import AcpClient, AcpRpcError
from .acp_common import clip_input, has_http_code
from .acp_session import AcpSessionBase
from . import grok_auth, grok_rpc
from .claude_session import HEDGEHOG_FORMULA_APPEND, HEDGEHOG_SYSTEM_APPEND
from .tool_names import normalize_tool_name

log = structlog.get_logger("grok")

CLI_TYPE = "grok"


def _grok_names(text: str) -> str:
    """Инструменты Ёжика в нотации Grok: `hedgehog__<tool>` через use_tool."""
    return (text.replace("mcp__hedgehog__", "hedgehog__")
                .replace("mcp__neko_browser__", "neko_browser__"))


# Системные правила (session/new _meta.rules): те же инструкции, что у Claude,
# + как вызывать MCP-инструменты в Grok.
GROK_RULES = (
    "MCP tools of the `hedgehog` server are called with the `use_tool` tool "
    "(find them first with `search_tool`); `tool_name` has the form "
    "`hedgehog__<tool>`.\n\n"
    + _grok_names(HEDGEHOG_SYSTEM_APPEND + HEDGEHOG_FORMULA_APPEND))


def classify_error(text: str) -> tuple[str, str]:
    """Текст ошибки grok/ACP → (код §8, сообщение пользователю)."""
    low = text.lower()
    if any(m in low for m in ("not logged in", "please log in", "please login",
                              "unauthenticated", "unauthorized",
                              "sign in to", "authentication required",
                              "re-authenticate", "login required")) \
            or has_http_code(low, 401):
        return Err.AUTH_REQUIRED, Msg("grok.auth_required")
    if has_http_code(low, 429) or any(m in low for m in (
            "rate limit", "usage limit", "quota", "too many requests",
            "limit reached")):
        return Err.RATE_LIMITED, Msg("grok.rate_limited")
    return Err.AGENT_CRASH, f"Grok failed: {text[:300]}"


def grok_tool_name(upd: dict, servers=()) -> str:
    """Каноническое имя инструмента из tool_call/запроса прав Grok."""
    meta = ((upd.get("_meta") or {}).get("x.ai/tool")) or {}
    raw = str(meta.get("name") or upd.get("title") or upd.get("name") or "")
    inp = upd.get("rawInput") or {}
    if raw == "use_tool" and isinstance(inp, dict):
        srv, sep, tool = str(inp.get("tool_name") or "").partition("__")
        if sep and srv and tool:
            return f"mcp__{srv}__{tool}"
    return normalize_tool_name(raw, servers)


def _tool_input(upd: dict) -> Any:
    inp = upd.get("rawInput") or upd.get("args") or {}
    if isinstance(inp, dict) and "tool_input" in inp and "tool_name" in inp:
        return clip_input(inp.get("tool_input") or {})   # use_tool: аргументы MCP
    return clip_input(inp)


class GrokSession(AcpSessionBase):
    CLI_TYPE = CLI_TYPE
    LOG_TAG = "grok"
    SERVER_ARGS = ("agent", "stdio")
    USAGE_WAIT = 1.5      # сколько ждать turn_completed после ответа на prompt

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._turn_usage = [0, 0]
        self._usage_evt = asyncio.Event()     # turn_completed (токены) получен

    def _classify_error(self, text: str) -> tuple[str, str]:
        return classify_error(text)

    def _spawn_extra_env(self) -> dict[str, str]:
        return grok_rpc.grok_extra_env()

    def _tool_identity(self, upd: dict) -> tuple[str, str]:
        raw = str(((upd.get("_meta") or {}).get("x.ai/tool") or {})
                  .get("name") or upd.get("title") or "")
        return grok_tool_name(upd, self._servers()), raw

    def _tool_input(self, upd: dict) -> Any:
        return _tool_input(upd)

    def _new_session_params(self, mcp: list[dict]) -> dict:
        return {**super()._new_session_params(mcp),
                "_meta": {"rules": GROK_RULES}}

    def _on_new_session(self, res: dict) -> None:
        grok_rpc.remember_models(res)    # кэш для models_list без лишних session/new

    async def _apply_settings(self, client: AcpClient, sid: str) -> None:
        state = self._state()
        model = state.get("model") or self.meta.model
        rec = grok_auth.alt_record()
        if rec.get("method") == "gateway":
            ids = {m.get("id") for m in rec.get("models") or []}
            if model not in ids:                     # модель прежнего способа не годится
                model = rec.get("active_id")
            if model:
                model = grok_rpc.gateway_key(model)  # запись [model.<key>] из config.toml
        for cfg, value in (("model", model),
                           ("reasoning_effort", state.get("effort"))):
            if not value:
                continue
            try:
                await client.request("session/set_config_option", {
                    "sessionId": sid, "configId": cfg, "value": str(value)},
                    timeout=30)
            except (AcpRpcError, asyncio.TimeoutError) as e:
                log.warning("grok.set_config_failed", chat=self.meta.chatId,
                            option=cfg, value=value, err=str(e))

    async def _on_ext_notification(self, method: str, params: dict,
                                   upd: dict) -> None:
        if method == "_x.ai/session_notification" \
                and upd.get("sessionUpdate") == "turn_completed":
            u = upd.get("usage") or {}
            self._turn_usage = [int(u.get("inputTokens") or 0),
                                int(u.get("outputTokens") or 0)]
            self._usage_evt.set()

    def _turn_reset(self) -> None:
        self._turn_usage = [0, 0]
        self._usage_evt.clear()

    async def _usage(self, result: dict, finished: bool) -> dict:
        if finished and not self._usage_evt.is_set():
            # turn_completed может прийти позже ответа на session/prompt
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(self._usage_evt.wait(), self.USAGE_WAIT)
        return {"input_tokens": self._turn_usage[0],
                "output_tokens": self._turn_usage[1]}
