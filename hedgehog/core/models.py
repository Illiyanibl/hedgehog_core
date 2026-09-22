"""§models: список доступных моделей Claude CLI — проба + дисковый кэш.

Источник правды — сам CLI: пустой `/model` печатает строку вида
    Usage: /model <name>. Available: sonnet, opus, haiku, …, or a full model ID.
    Current model: <name> …
Парсим её и кэшируем на диск ПО ТИПУ CLI (data/models.<cliType>.json). Клиенту
список отдаётся из кэша МГНОВЕННО (фрейм list_models с cliType); кэш обновляет
ФОНОВЫЙ рефрешер раз в сутки (см. wss.server) — на клиентский запрос CLI не
дёргается. §cli-types: сейчас единственный тип — claude; задел под codex и др.

Проба изолированная: one-shot claude_agent_sdk.query() под тем же режимом
авторизации (build_auth_env). Токен только ЧИТАЕТСЯ (read-only) — `/model` не
логинит и не разлогинивает, второй процесс поднимается лишь в фоне и только
когда агент не занят.
"""
from __future__ import annotations

import asyncio
import json
import re
import shutil
import time
from pathlib import Path
from typing import Any

import structlog
from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    ResultMessage,
    TextBlock,
    query,
)

from .claude_session import build_auth_env, is_auth_error

log = structlog.get_logger("models")

_AVAILABLE_RE = re.compile(r"Available:\s*(.+)", re.IGNORECASE)
_CURRENT_RE = re.compile(r"Current model:\s*(.+)", re.IGNORECASE)
_PROBE_TIMEOUT = 60.0

# §cli-types: типы CLI-агентов, которые Ёžik умеет обслуживать. Сейчас только
# Claude; задел под Codex и др. — добавление сюда + ветка пробы в probe_models
# + (для реальной работы) своя session-реализация в wss-слое. Клиент шлёт
# cliType в list_models/create_chat; сервер отдаёт данные нужного типа.
DEFAULT_CLI_TYPE = "claude"
KNOWN_CLI_TYPES: tuple[str, ...] = ("claude",)


def parse_model_line(text: str) -> dict[str, Any]:
    """Из текста ответа `/model` достать список моделей и текущую.

    Возвращает {"models": [...], "current": str|None}. Толерантен к формату:
    режет хвост «or a full model ID», убирает пустые/дубликаты, хранит порядок.
    """
    models: list[str] = []
    current: str | None = None
    m = _AVAILABLE_RE.search(text or "")
    if m:
        raw = m.group(1).strip()
        # Обрезаем закрывающую фразу CLI (варианты пунктуации/регистра).
        raw = re.split(r",?\s*or a full model id", raw, flags=re.IGNORECASE)[0]
        raw = raw.rstrip(" .")
        seen: set[str] = set()
        for part in raw.split(","):
            name = part.strip()
            if name and name not in seen:
                seen.add(name)
                models.append(name)
    c = _CURRENT_RE.search(text or "")
    if c:
        # Строка вида «Opus 4.8 (effort: xhigh)» — оставляем как есть (инфо).
        current = c.group(1).strip() or None
    return {"models": models, "current": current}


def _unsupported(cli_type: str) -> dict[str, Any]:
    return {"cliType": cli_type, "models": [], "current": None, "raw": "",
            "auth_state": "UNSUPPORTED", "cli_present": False}


async def probe_models(config, cwd: str,
                       cli_type: str = DEFAULT_CLI_TYPE) -> dict[str, Any]:
    """One-shot проба списка моделей в изолированном процессе CLI типа cli_type.

    Возвращает {"cliType","models","current","raw","auth_state","cli_present"}.
    Ошибки/отсутствие CLI НЕ кидаем — возвращаем состояние (вызывающий решает,
    затирать ли кэш). auth_state: "OK"|"AUTH_REQUIRED"|"NO_CLI"|"ERROR"|"UNSUPPORTED".
    Сейчас реализован только claude (проба `/model`); прочие типы → UNSUPPORTED.
    """
    if cli_type not in KNOWN_CLI_TYPES:
        return _unsupported(cli_type)
    # §cli-types: пока единственная ветка — claude. Codex/др. добавляются здесь
    # своей командой/парсером.
    if shutil.which("claude") is None:
        return {"cliType": cli_type, "models": [], "current": None, "raw": "",
                "auth_state": "NO_CLI", "cli_present": False}

    env, model_override = build_auth_env(config)
    kwargs: dict[str, Any] = {"cwd": cwd}
    if env:
        kwargs["env"] = env
    if model_override is not None:
        kwargs["model"] = model_override

    texts: list[str] = []
    result_text = ""
    auth_state = "OK"
    try:
        async def _run() -> None:
            nonlocal result_text
            async for msg in query(prompt="/model",
                                   options=ClaudeAgentOptions(**kwargs)):
                if isinstance(msg, AssistantMessage):
                    for b in msg.content:
                        if isinstance(b, TextBlock):
                            texts.append(b.text)
                elif isinstance(msg, ResultMessage):
                    result_text = msg.result or ""
        await asyncio.wait_for(_run(), timeout=_PROBE_TIMEOUT)
    except Exception as e:  # noqa: BLE001 — проба не должна ронять рефрешер
        # На ошибочном результате труба SDK кидает исключение (§auth-falsepos).
        blob = repr(e) + " " + " ".join(texts) + " " + result_text
        if is_auth_error(blob):
            auth_state = "AUTH_REQUIRED"
        else:
            log.warning("models.probe_failed", err=repr(e))
            auth_state = "ERROR"

    raw = "\n".join([*texts, result_text]).strip()
    # Явный признак незалогиненности в тексте (без исключения).
    if auth_state == "OK" and is_auth_error(raw):
        auth_state = "AUTH_REQUIRED"

    if auth_state != "OK":
        return {"cliType": cli_type, "models": [], "current": None, "raw": raw,
                "auth_state": auth_state, "cli_present": True}

    parsed = parse_model_line(raw)
    return {"cliType": cli_type, "models": parsed["models"],
            "current": parsed["current"], "raw": raw,
            "auth_state": "OK", "cli_present": True}


# ---------- дисковый кэш (data/models.<cliType>.json) ----------

_SAFE_CLI_RE = re.compile(r"[^a-z0-9_-]+")


def cache_path(config, cli_type: str = DEFAULT_CLI_TYPE) -> Path:
    # Имя файла из cli_type санитизируем (тип приходит из протокола).
    safe = _SAFE_CLI_RE.sub("_", cli_type.lower()) or "unknown"
    return config.data_dir / f"models.{safe}.json"


def load_cache(config, cli_type: str = DEFAULT_CLI_TYPE) -> dict[str, Any] | None:
    try:
        data = json.loads(cache_path(config, cli_type).read_text())
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


def save_cache(config, data: dict[str, Any],
               cli_type: str = DEFAULT_CLI_TYPE) -> None:
    config.data_dir.mkdir(parents=True, exist_ok=True)
    p = cache_path(config, cli_type)
    tmp = p.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False))
    tmp.replace(p)
