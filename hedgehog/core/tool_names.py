"""§multi-cli (§18.6): нормализация имён инструментов к каноническому виду, как
их знает клиент и политика прав Ёжика (имена Claude Code; MCP —
`mcp__<server>__<tool>`).

Antigravity присылает MCP-инструменты как `mcp_<server>_<tool>` (одинарные
подчёркивания), поэтому разбор неоднозначен при `_` в именах серверов — префикс
сверяется с ИЗВЕСТНЫМИ серверами (реестр mcp.json + встроенные).
"""

from __future__ import annotations

from typing import Iterable

# Встроенные инструменты agy → имена Claude Code. Наблюдались в ACP:
# read_file, write_file, run_command; остальное — предположение по именам agy,
# пополнять по логам (неизвестные проходят как есть, §18.6).
BUILTIN_MAP = {
    "read_file": "Read",
    "view_file": "Read",
    "write_file": "Write",
    "edit_file": "Edit",
    "replace_file_content": "Edit",
    "multi_replace_file_content": "MultiEdit",
    "run_command": "Bash",
    "grep_search": "Grep",
    "find_by_name": "Glob",
    "list_dir": "LS",
    # Grok Build (grok agent stdio): имя в _meta["x.ai/tool"].name
    "run_terminal_command": "Bash",
    "search_replace": "Edit",
    "write": "Write",
    "grep": "Grep",
    "todo_write": "TodoWrite",
    "web_fetch": "WebFetch",
}


def normalize_tool_name(raw: str, known_servers: Iterable[str] = ()) -> str:
    """raw → канон. `mcp__x__y` остаётся; `mcp_x_y` → `mcp__x__y` по известным
    серверам (самый длинный префикс); встроенные — по BUILTIN_MAP."""
    if raw.startswith("mcp__"):
        return raw
    if raw.startswith("mcp_"):
        rest = raw[len("mcp_"):]
        for srv in sorted(known_servers, key=len, reverse=True):
            if rest.startswith(srv + "_") and len(rest) > len(srv) + 1:
                return f"mcp__{srv}__{rest[len(srv) + 1:]}"
        return raw          # сервер неизвестен — не гадаем
    return BUILTIN_MAP.get(raw, raw)
