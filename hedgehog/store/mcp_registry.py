"""Реестр MCP-серверов — /data/mcp.json (protocol/messages.md §12).

Словарь имя→конфиг в схеме Claude Agent SDK. Файл хранит секреты (заголовки,
токены), поэтому лежит только на сервере пользователя и в протокол не попадает.
Чат подключает серверы по имени через create_chat.mcp.

Реестр читается при каждом старте сессии (не кэшируется) — правка mcp.json
подхватывается новой сессией без рестарта Ёжика.
"""

from __future__ import annotations

import json
from pathlib import Path

import structlog

log = structlog.get_logger("mcp")

_ALLOWED_TYPES = {"http", "sse", "stdio"}


class McpRegistry:
    def __init__(self, path: Path):
        self.path = path

    def _load(self) -> dict[str, dict]:
        if not self.path.exists():
            return {}
        try:
            data = json.loads(self.path.read_text())
        except (ValueError, OSError) as e:
            log.warning("mcp.registry_unreadable", path=str(self.path), err=str(e))
            return {}
        if not isinstance(data, dict):
            log.warning("mcp.registry_not_object", path=str(self.path))
            return {}
        return data

    def resolve(self, names: list[str]) -> dict[str, dict]:
        """имена → {имя: конфиг} для ClaudeAgentOptions.mcp_servers.

        Неизвестные/битые имена пропускаются с WARNING — чат всё равно
        создаётся (§3.7), просто без этого MCP.
        """
        if not names:
            return {}
        registry = self._load()
        out: dict[str, dict] = {}
        for name in names:
            cfg = registry.get(name)
            if cfg is None:
                log.warning("mcp.unknown_server", name=name)
                continue
            if not isinstance(cfg, dict) or cfg.get("type") not in _ALLOWED_TYPES:
                log.warning("mcp.bad_config", name=name, type=(
                    cfg.get("type") if isinstance(cfg, dict) else type(cfg).__name__))
                continue
            out[name] = cfg
        return out

    def known_names(self) -> list[str]:
        return sorted(self._load().keys())
