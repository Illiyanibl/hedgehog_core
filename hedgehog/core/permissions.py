"""§multi-cli (§18.8): единая политика прав Ёжика для CLI, у которых решение
«разрешить/спросить» принимает сам Ёжик (Antigravity по ACP). ClaudeSession
пока держит свою логику в `_can_use_tool` (поведение рабочих чатов не меняем);
политика повторяет её семантику: bypass → всё, acceptEdits → правки внутри
рабочего каталога, иначе спрашиваем.
"""

from __future__ import annotations

import enum
import os
from dataclasses import dataclass, field
from typing import Callable, Mapping

# Имена инструментов правки файлов (после нормализации, см. tool_names.py).
EDIT_TOOL_NAMES = frozenset({"write", "edit", "multiedit", "notebookedit",
                             "write_file", "edit_file", "create_file",
                             "replace_file_content",
                             "multi_replace_file_content", "apply_patch"})
# Безопасные встроенные инструменты Ёжика — без спроса (для ВСЕХ CLI): чтение
# состояния или безобидное действие для самого пользователя. Всё, что запускает
# скрипты (handler_*), пишет в другие чаты (send_to_chat, list_chats), создаёт
# отложенные задания (schedule_add, remind), пишет данные (kv_set, artifact_put),
# тратит деньги (generate_image) или рисует окна (ask_ui, ui_open…), остаётся с
# запросом.
HEDGEHOG_SAFE_TOOLS = (
    "attach_file", "formula_mode", "notify", "kv_get", "ui_current",
    "ui_drawing", "schedule_list", "artifact_list", "artifact_get",
    "handler_list")
AUTO_ALLOW = frozenset(f"mcp__hedgehog__{t}" for t in HEDGEHOG_SAFE_TOOLS)


class Decision(enum.Enum):
    ALLOW = "allow"
    DENY = "deny"
    ASK = "ask"


@dataclass
class ToolRequest:
    name: str                      # каноническое имя (tool_names.normalize)
    kind: str | None = None        # ACP kind: read/edit/execute/…
    input: Mapping | None = None
    paths: list[str] = field(default_factory=list)   # затрагиваемые пути


def _inside(path: str, root: str) -> bool:
    """path внутри root? Относительные пути считаем от root (а не от cwd процесса
    Ёжика), симлинки разворачиваем; любая ошибка → False (fail-closed)."""
    try:
        r = os.path.realpath(os.path.abspath(root))
        joined = path if os.path.isabs(path) else os.path.join(r, path)
        p = os.path.realpath(os.path.abspath(joined))
        return os.path.commonpath([p, r]) == r
    except (ValueError, OSError, TypeError):
        return False


class PermissionPolicy:
    def __init__(self, mode_getter: Callable[[], str], cwd: str,
                 always_allowed: set[str] | None = None):
        self._mode = mode_getter           # читаем на КАЖДЫЙ запрос (§18.8)
        self._cwd = cwd
        self.always_allowed = always_allowed if always_allowed is not None else set()

    def is_edit(self, req: ToolRequest) -> bool:
        """Правка файла внутри рабочего каталога? Без пути — не считаем
        правкой (консервативно: спросим)."""
        if req.kind != "edit" and req.name.lower() not in EDIT_TOOL_NAMES:
            return False
        if not req.paths:
            return False
        return all(_inside(p, self._cwd) for p in req.paths)

    def decide(self, req: ToolRequest) -> Decision:
        if req.name in AUTO_ALLOW:
            return Decision.ALLOW
        mode = self._mode()
        if mode == "bypassPermissions":
            return Decision.ALLOW
        if req.name in self.always_allowed:
            return Decision.ALLOW
        if mode == "acceptEdits" and self.is_edit(req):
            return Decision.ALLOW
        return Decision.ASK


def extract_paths(update: Mapping) -> list[str]:
    """Пути из ACP tool_call: locations[].path, затем args/rawInput (Path,
    path, file_path, TargetFile…)."""
    out: list[str] = []
    for loc in update.get("locations") or []:
        p = loc.get("path") if isinstance(loc, Mapping) else None
        if p:
            out.append(str(p))
    if not out:
        raw = update.get("rawInput") or update.get("args") or {}
        if isinstance(raw, Mapping):
            for k in ("Path", "path", "file_path", "FilePath", "TargetFile",
                      "AbsolutePath"):
                if raw.get(k):
                    out.append(str(raw[k]))
                    break
    return out
