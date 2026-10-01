"""§ctl: локальная «ручка» для встроенных MCP-тулов через unix-сокет.

Зачем: модель за шлюзом omniroute (провайдер `agy/antigravity`) не может звать
`mcp__hedgehog__*` нативно — шлюз коверкает имена функций при переводе формата
(`mcp__hedgehog__notify` → `mcp_hedgehog_notify_<hash>_ide`), и вызов не
доходит до SDK («No such tool available»). Но **Bash** у агента не коверкается.
Поэтому даём агенту CLI (`ctl_client.py`), который по unix-сокету дёргает РЕАЛЬНЫЙ
хендлер тула в процессе Ёжика и печатает результат в stdout — синхронно, тем же
ходом (возвращающие данные тулы и ask_ui работают без костыля «следующим ходом»).

Один источник правды: хендлеры — ровно те же, что у нативного MCP
(`build_hedgehog_mcp` кладёт `session._ctl_tools = {name: tool.handler}`).

Безопасность: сокет только локальный (в data_dir, 0600 + сам каталog 0700);
вызов идентифицируется per-session ТОКЕНОМ (выдан в env агента при старте
клиента), а НЕ chat_id — из Bash одного чата нельзя дёрнуть сессию другого.
Всё на главном event-loop, без нитей. Падение хендлера = ошибка одного
соединения; ридер/ход агента (SDK-труба) не затрагиваются по построению.
"""
from __future__ import annotations

import asyncio
import json
import os

import structlog

log = structlog.get_logger("ctl")

# token -> ClaudeSession. Модульный реестр: сессия регистрируется в
# _ensure_client (omniroute), снимается в stop(). Живёт на том же loop.
_sessions: dict[str, object] = {}

# Потолок одного запроса: ui_open/ask_ui несут десятки КБ HTML одной JSON-строкой.
_MAX_REQ = 16 * 1024 * 1024


def register(token: str, session) -> None:
    _sessions[token] = session


def unregister(token: str | None) -> None:
    if token:
        _sessions.pop(token, None)


def _first_line(s) -> str:
    """Первая непустая строка описания (для --list)."""
    for ln in str(s or "").splitlines():
        ln = ln.strip()
        if ln:
            return ln
    return ""


def _text_of(res) -> str:
    """Склеить текстовые блоки MCP-ответа {"content":[{"type":"text",...}]}."""
    if isinstance(res, dict):
        parts = [b.get("text", "") for b in (res.get("content") or [])
                 if isinstance(b, dict) and b.get("type") == "text"]
        if parts:
            return "\n".join(parts)
        return json.dumps(res, ensure_ascii=False)
    return str(res)


async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    # Внешний finally закрывает writer ВСЕГДА — в т.ч. на CancelledError
    # (shutdown отменяет _pending во время ctl-ask_ui): иначе клиент висел бы
    # до своего socket-таймаута. CancelledError после finally пробрасывается.
    resp: dict | None = None
    try:
        line = await reader.readline()
        if line:
            try:
                req = json.loads(line)
                token = req.get("token")
                tool = req.get("tool")
                args = req.get("args") if isinstance(req.get("args"), dict) else {}
                op = req.get("op") or "call"
                session = _sessions.get(token) if token else None
                if session is None:
                    resp = {"ok": False, "error": "unknown or expired session token"}
                elif op == "list":
                    # Самоописание: имена + первая строка описания каждого тула.
                    meta = getattr(session, "_ctl_meta", None) or {}
                    lines = [f"{n} — {_first_line(m.get('description'))}"
                             for n, m in meta.items()]
                    resp = {"ok": True, "text": "\n".join(lines)}
                elif op == "schema":
                    meta = (getattr(session, "_ctl_meta", None) or {}).get(tool)
                    if meta is None:
                        resp = {"ok": False, "error": f"unknown tool: {tool!r}"}
                    else:
                        resp = {"ok": True, "text": json.dumps(
                            {"name": tool, "description": meta.get("description"),
                             "input_schema": meta.get("input_schema")},
                            ensure_ascii=False, indent=2)}
                else:   # op == "call"
                    fn = (getattr(session, "_ctl_tools", None) or {}).get(tool)
                    if fn is None:
                        resp = {"ok": False, "error": f"unknown tool: {tool!r}"}
                    else:
                        try:
                            res = await fn(args)
                            resp = {"ok": True, "text": _text_of(res)}
                        except Exception as e:  # noqa: BLE001 — единый UX ошибки
                            log.warning("ctl.tool_failed", tool=tool, err=repr(e))
                            resp = {"ok": False, "error": repr(e)}
            except Exception as e:  # noqa: BLE001 — битый фрейм/JSON: не роняем сервер
                log.warning("ctl.bad_request", err=repr(e))
                resp = {"ok": False, "error": f"bad request: {e!r}"}
        if resp is not None:
            writer.write((json.dumps(resp, ensure_ascii=False) + "\n").encode())
            await writer.drain()
    except Exception as e:  # noqa: BLE001 — readline/drain: клиент отвалился
        log.warning("ctl.conn_error", err=repr(e))
    finally:
        try:
            writer.close()
        except Exception:  # noqa: BLE001
            pass


async def start(sock_path) -> asyncio.AbstractServer:
    """Поднять unix-сокет-сервер. Идемпотентно убираем старый сокет-файл."""
    p = str(sock_path)
    try:
        os.unlink(p)
    except FileNotFoundError:
        pass
    except OSError as e:
        log.warning("ctl.unlink_failed", sock=p, err=repr(e))
    server = await asyncio.start_unix_server(_handle, path=p, limit=_MAX_REQ)
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass
    log.info("ctl.listening", sock=p)
    return server
