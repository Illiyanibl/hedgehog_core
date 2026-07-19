"""Базовый контракт per-chat сессии (ClaudeSession / PtySession)."""

from __future__ import annotations

from typing import Any, Awaitable, Callable, Protocol

from ..store.chats import ChatMeta

# publish(ftype, payload) → frame; шину пробрасывает wss-слой,
# chatId сессия не указывает — он зашит в замыкании.
PublishFn = Callable[[str, dict[str, Any]], Awaitable[dict]]


class Session(Protocol):
    meta: ChatMeta

    async def start(self) -> None: ...
    async def stop(self) -> None: ...
