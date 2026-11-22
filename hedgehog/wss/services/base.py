"""Контракты хоста для сервисов wss (структурная типизация, без импорта сервера)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from ...bus.hub import Hub
    from ...config import Config
    from ...store.chats import ChatMeta, ChatStore
    from .cli_auth import CliAuthService
    from .cli_installer import CliInstallService


class AuthHost(Protocol):
    """Что CliAuthService берёт у сервера (вызывается в момент обращения,
    bound-методы не захватываются — подмены на экземпляре продолжают работать)."""

    config: Config
    hub: Hub
    store: ChatStore

    def _configure_grok_home(self) -> None: ...

    async def _quiesce_cli(self, cli: str, *, notify_busy: bool) -> list: ...

    async def _resume_queued(self, pending: list) -> None: ...

    async def _restart_cli_sessions(self, cli: str) -> None: ...

    async def _reset_all_chat_models(self) -> None: ...

    def _invalidate_models_cache(self) -> None: ...

    async def _broadcast_cli_status(self, cli: str, *,
                                    install: bool = False) -> None: ...

    async def _broadcast_meta(self, ftype: str, meta: ChatMeta) -> None: ...

    def _spawn_tracked(self, conn_id: int, op_id: str, kind: str, coro: Any,
                       *, broadcast: bool = False) -> None: ...

    def _mark_committing(self, op_id: str | None) -> None: ...

    async def _emit_op_slow(self, op_id: str, kind: str, conn_id: int,
                            broadcast: bool) -> None: ...


class CliInstallHost(Protocol):
    """Что CliInstallService берёт у сервера (в момент вызова)."""

    config: Config
    hub: Hub
    store: ChatStore
    cli_auth: CliAuthService          # MED-1: token_rejected()

    def _invalidate_models_cache(self) -> None: ...

    async def _push_models_list(self, cli: str) -> None: ...

    async def _broadcast_cli_status(self, cli: str, *,
                                    install: bool = False) -> None: ...


class ModelsHost(Protocol):
    """Что ModelsRefresher берёт у сервера (в момент вызова)."""

    config: Config
    hub: Hub
    store: ChatStore
    sessions: dict                    # §models M1: занят ли агент Claude
    cli_auth: CliAuthService          # MED-1: clear_token_rejected()
    cli_installer: CliInstallService  # list_models: CLI не установлен → NO_CLI

    async def _broadcast_cli_status(self, cli: str, *,
                                    install: bool = False) -> None: ...


class NekoHost(Protocol):
    """Что NekoController берёт у сервера (в момент вызова)."""

    config: Config
    hub: Hub

    async def _reply_or_broadcast(self, conn_id: int, frame: dict) -> None: ...


class UpdateHost(Protocol):
    """Что UpdateController берёт у сервера (в момент вызова)."""

    hub: Hub

    async def _reply_or_broadcast(self, conn_id: int, frame: dict) -> None: ...
