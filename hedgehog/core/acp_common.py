"""Общие помощники ACP-сессий (Antigravity, Grok): реестр MCP → mcpServers,
выбор варианта ответа на session/request_permission, текст результата инструмента."""

from __future__ import annotations

import re
from typing import Any

OUT_CAP = 20_000      # предел текста вывода инструмента в ленте/истории
INPUT_CAP = 4_000     # предел строкового значения во входе инструмента


def acp_mcp_servers(servers: dict[str, dict] | None) -> list[dict]:
    """Реестр MCP Ёжика (формат Claude SDK) → mcpServers ACP."""
    out: list[dict] = []
    for name, cfg in (servers or {}).items():
        if not isinstance(cfg, dict):
            continue
        kind = cfg.get("type")
        if kind in ("http", "sse") and cfg.get("url"):
            out.append({"type": kind, "name": name, "url": cfg["url"],
                        "headers": [{"name": k, "value": str(v)} for k, v in
                                    (cfg.get("headers") or {}).items()]})
        elif cfg.get("command"):
            out.append({"name": name, "command": cfg["command"],
                        "args": list(cfg.get("args") or []),
                        "env": [{"name": k, "value": str(v)} for k, v in
                                (cfg.get("env") or {}).items()]})
    return out


def pick_option(options: list[dict], allow: bool, always: bool = False) -> str | None:
    kinds = (("allow_always", "allow_once") if always else
             ("allow_once", "allow_always")) if allow else (
             "reject_once", "reject_always")
    for k in kinds:
        for o in options:
            if o.get("kind") == k and o.get("optionId"):
                return o["optionId"]
    return None


def clip_text(text: Any, cap: int = OUT_CAP) -> str:
    """Строка не длиннее cap (+ маркер усечения); None → ''."""
    s = text if isinstance(text, str) else ("" if text is None else str(text))
    return s if len(s) <= cap else s[:cap] + "\n…[truncated]"


def clip_input(inp: Any, cap: int = INPUT_CAP) -> Any:
    """Вход инструмента для ленты: длинные строковые значения (содержимое файла,
    HTML окна) усекаются; структура сохраняется."""
    if isinstance(inp, dict):
        return {k: clip_input(v, cap) for k, v in inp.items()}
    if isinstance(inp, list):
        return [clip_input(v, cap) for v in inp[:200]]
    return clip_text(inp, cap) if isinstance(inp, str) else inp


def has_http_code(text: str, code: int) -> bool:
    """В тексте есть HTTP-код как отдельное число (не часть «14012 bytes»)."""
    return re.search(rf"(?<!\d){code}(?!\d)", text) is not None


def tool_output(update: dict) -> str:
    """Текст результата из content ACP (diff/text); agy обычно не присылает."""
    parts: list[str] = []
    for item in update.get("content") or []:
        if not isinstance(item, dict):
            continue
        if item.get("type") == "diff":
            parts.append(f"diff {item.get('path', '')}")
        else:
            inner = item.get("content")
            if isinstance(inner, dict) and inner.get("text"):
                parts.append(str(inner["text"]))
    from .secrets_redact import redact
    return redact(clip_text("\n".join(parts)))


_tool_output = tool_output          # прежнее имя (тесты/реэкспорты)


_pick_option = pick_option          # прежнее имя
