"""Базовый контракт per-chat сессии агента (ClaudeSession и будущие CLI).

§multi-cli: сессия агента — то, что wss-слой создаёт по `meta.cliType` и
дальше зовёт ТОЛЬКО через этот контракт (диспетчеризация команд клиента на
активный CLI, protocol/messages.md §18.6). PtySession (broker_shell) сюда не
относится — у неё свой ввод (`write`/`resize`).
"""

from __future__ import annotations

from typing import Any, Awaitable, Callable, Protocol, runtime_checkable

# publish(ftype, payload) → frame; шину пробрасывает wss-слой,
# chatId сессия не указывает — он зашит в замыкании.
PublishFn = Callable[[str, dict[str, Any]], Awaitable[dict]]


class SessionClosed(RuntimeError):
    """Сессия закрыта для новых сообщений (set_cli/stop) — вызывающий обязан
    повторить доставку через актуальную сессию чата (иначе сообщение ушло бы в
    «осиротевшую» сессию вне реестра и подняло бы лишний процесс CLI)."""


@runtime_checkable
class AgentSession(Protocol):
    """Минимальный набор, которым пользуется wss-слой."""

    async def start(self) -> None: ...

    async def stop(self) -> None: ...

    async def handle_user_msg(self, content: str, interrupt: bool = True,
                              on_result: Any = None) -> bool: ...

    def resolve(self, related: str, value: str) -> bool: ...

    async def handle_ui_event(self, data: str) -> None: ...

    def set_client_caps(self, caps: Any) -> None: ...

    def close_intake(self) -> None: ...

    def take_queued(self) -> list[tuple[str, Any]]: ...

    def pending_request_ids(self) -> list[str]: ...
