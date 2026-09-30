"""Базовый контракт per-chat сессии (ClaudeSession / PtySession)."""

from __future__ import annotations

from typing import Any, Awaitable, Callable

# publish(ftype, payload) → frame; шину пробрасывает wss-слой,
# chatId сессия не указывает — он зашит в замыкании.
PublishFn = Callable[[str, dict[str, Any]], Awaitable[dict]]

# Прим.: раньше здесь был Protocol `Session` (meta/start/stop) — удалён как
# неиспользуемый (ClaudeSession/PtySession не аннотируются им нигде).
