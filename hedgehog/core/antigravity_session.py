"""§multi-cli: сессия чата поверх Antigravity CLI (`agy acp`, Agent Client
Protocol). Реализует тот же контракт, что ClaudeSession (core/session_base.py):
очередь user_msg, один ход за раз, те же фреймы наружу (text_delta, tool_use,
tool_result, agent_done, permission_request, error), прерывание, resume.

Известные особенности agy 1.5.0 (проверено живьём, protocol/messages.md §18.8):
- tool_call_update не несёт вывода инструмента (только status) → tool_result
  с пустым output, is_error по status=failed;
- ПРАВКИ файлов идут без session/request_permission (даже вне рабочего каталога);
  запрос приходит на shell-команды (kind=execute) — политика Ёжика решает их.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any

import structlog

from ..i18n import Msg
from ..protocol import Err
from .acp_client import AcpClient, AcpRpcError
from .acp_common import (_pick_option, _tool_output, acp_mcp_servers,  # noqa: F401
                         clip_input, has_http_code)
from . import agy_auth
from .acp_session import AcpSessionBase
from .claude_session import HEDGEHOG_FORMULA_APPEND, HEDGEHOG_SYSTEM_APPEND
from .tool_names import normalize_tool_name

log = structlog.get_logger("agy")

CLI_TYPE = "antigravity"


def _agy_names(text: str) -> str:
    """agy показывает MCP-инструменты как mcp_<server>_<tool> (одинарные _)."""
    return (text.replace("mcp__hedgehog__", "mcp_hedgehog_")
                .replace("mcp__neko_browser__", "mcp_neko_browser_"))


# Системные инструкции для agy (ACP не даёт system prompt): те же, что у Claude,
# с именами инструментов в нотации agy; уходят префиксом ПЕРВОГО хода новой сессии.
AGY_SYSTEM_PREFIX = _agy_names(HEDGEHOG_SYSTEM_APPEND + HEDGEHOG_FORMULA_APPEND)


def classify_error(text: str) -> tuple[str, str]:
    """Текст ошибки agy/ACP → (код §8, сообщение пользователю)."""
    low = text.lower()
    if any(m in low for m in ("not eligible", "permission_denied", "sign in",
                              "log in", "unauthenticated", "not signed in",
                              "login required")):
        return Err.AUTH_REQUIRED, Msg("agy.auth_required")
    if has_http_code(low, 429) or any(m in low for m in (
            "resource_exhausted", "quota", "rate limit", "rate-limit")):
        return Err.RATE_LIMITED, Msg("agy.rate_limited")
    return Err.AGENT_CRASH, f"Antigravity failed: {text[:300]}"


class AntigravitySession(AcpSessionBase):
    CLI_TYPE = CLI_TYPE
    LOG_TAG = "agy"
    PROXY_USER_MCP = True
    SERVER_ARGS = ("acp",)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._first_turn_prefix: str | None = None   # системные инструкции
        self._prefix_used = False

    def _classify_error(self, text: str) -> tuple[str, str]:
        return classify_error(text)

    def _server_args(self) -> tuple[str, ...]:
        return (*self.SERVER_ARGS, *agy_auth.agy_server_args())

    def _spawn_extra_env(self) -> dict[str, str]:
        return agy_auth.agy_extra_env()

    def _tool_identity(self, upd: dict) -> tuple[str, str]:
        raw = str(upd.get("name") or "")
        return normalize_tool_name(raw, self._servers()), raw

    def _tool_input(self, upd: dict) -> Any:
        return clip_input(upd.get("rawInput") or upd.get("args") or {})

    def _on_new_session(self, res: dict) -> None:
        self._first_turn_prefix = AGY_SYSTEM_PREFIX

    async def _apply_settings(self, client: AcpClient, sid: str) -> None:
        model = self._state().get("model") or self.meta.model
        if not model:
            return
        try:
            await client.request("session/set_model", {
                "sessionId": sid, "modelId": model}, timeout=30)
        except (AcpRpcError, asyncio.TimeoutError) as e:
            log.warning("agy.set_model_failed", chat=self.meta.chatId,
                        model=model, err=str(e))

    def _prepare_prompt(self, prompt: str) -> str:
        self._prefix_used = False
        if self._first_turn_prefix:
            self._prefix_used = True
            return (f"[Host instructions — follow them, do not quote them]\n"
                    f"{self._first_turn_prefix}\n\n[User message]\n{prompt}")
        return prompt

    async def _inspect_turn_text(self, text: str) -> None:
        # agy отдаёт ошибку API (в т.ч. 429 квоты ключа) обычным сообщением
        # «⚠ agent executor error: …» — превращаем в ошибку чата
        if not re.match(r"\s*\W{0,3}\s*agent executor error", text):
            return
        code, message = classify_error(text)
        await self._send_chat_error(code, message)
        if code == Err.AUTH_REQUIRED:
            self._fire_auth_required()

    def _turn_finished(self, finished: bool) -> None:
        if self._prefix_used:        # префикс «потрачен», когда ход отработал
            self._first_turn_prefix = None
