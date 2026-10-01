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
import base64
import json
import os

import structlog

from ..ids import new_ulid

log = structlog.get_logger("ctl")

# §ctl-neko: тулы, которые нельзя давать агенту в shared-browser-context —
# они бьют по общему экрану/управлению, это зона Ёжика (get_neko/install_neko).
_NEKO_DENY = {"browser_install", "browser_close"}


def _neko_name(tool: str) -> str:
    """Нормализуем возможные префиксы к базовому имени neko-тула (browser_*)."""
    for pre in ("mcp__neko_browser__", "mcp_neko_browser_"):
        if tool.startswith(pre):
            return tool[len(pre):]
    return tool


def _save_image(block, cwd) -> str | None:
    """Сохранить image-блок (base64) в cwd чата; вернуть абсолютный путь."""
    data = getattr(block, "data", None)
    if not data:
        return None
    mime = getattr(block, "mimeType", "") or "image/png"
    ext = "png" if "png" in mime else ("jpg" if "jp" in mime else "img")
    try:
        raw = base64.b64decode(data)
        path = os.path.join(str(cwd), f"neko_screenshot_{new_ulid()}.{ext}")
        with open(path, "wb") as f:
            f.write(raw)
        return path
    except Exception as e:  # noqa: BLE001
        log.warning("neko.image_save_failed", err=repr(e))
        return None


def _neko_text(res, cwd) -> str:
    """CallToolResult → текст для stdout; image-блоки сохраняем в cwd и даём путь
    (base64 в stdout залил бы контекст модели)."""
    parts = []
    for b in (getattr(res, "content", None) or []):
        bt = getattr(b, "type", None)
        if bt == "text":
            parts.append(getattr(b, "text", "") or "")
        elif bt == "image":
            p = _save_image(b, cwd)
            parts.append(f"[screenshot saved: {p} — use Read or attach_file to view/send it]"
                         if p else "[image omitted]")
        else:
            parts.append(f"[{bt} block]")
    return "\n".join(p for p in parts if p)

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
                proxy = getattr(session, "_neko_proxy", None) if session else None
                if session is None:
                    resp = {"ok": False, "error": "unknown or expired session token"}
                elif op == "list":
                    # Самоописание: имена + первая строка описания каждого тула.
                    meta = getattr(session, "_ctl_meta", None) or {}
                    lines = [f"{n} — {_first_line(m.get('description'))}"
                             for n, m in meta.items()]
                    if proxy is not None:   # §neko: добавляем браузерные тулы
                        try:
                            cat = await proxy.list_tools()
                            lines += [f"{n} — {_first_line(m.get('description'))}"
                                      for n, m in cat.items()]
                        except Exception as e:  # noqa: BLE001 — neko лёг: не рушим список
                            lines.append(f"# browser tools (neko): unavailable ({e!r})")
                    resp = {"ok": True, "text": "\n".join(lines)}
                elif op == "schema":
                    meta = (getattr(session, "_ctl_meta", None) or {}).get(tool)
                    if meta is None and proxy is not None:
                        try:
                            meta = (await proxy.list_tools()).get(_neko_name(tool))
                        except Exception:  # noqa: BLE001
                            meta = None
                    if meta is None:
                        resp = {"ok": False, "error": f"unknown tool: {tool!r}"}
                    else:
                        resp = {"ok": True, "text": json.dumps(
                            {"name": tool, "description": meta.get("description"),
                             "input_schema": meta.get("input_schema")},
                            ensure_ascii=False, indent=2)}
                else:   # op == "call"
                    fn = (getattr(session, "_ctl_tools", None) or {}).get(tool)
                    nname = _neko_name(tool)
                    if fn is not None:
                        try:
                            res = await fn(args)
                            resp = {"ok": True, "text": _text_of(res)}
                        except Exception as e:  # noqa: BLE001 — единый UX ошибки
                            log.warning("ctl.tool_failed", tool=tool, err=repr(e))
                            resp = {"ok": False, "error": repr(e)}
                    elif proxy is not None and nname.startswith("browser_"):
                        if nname in _NEKO_DENY:
                            resp = {"ok": False,
                                    "error": f"{nname} is managed by hedgehog, not available"}
                        else:
                            try:
                                res = await proxy.call(nname, args)
                                text = _neko_text(res, session.meta.cwd)
                                if getattr(res, "isError", False):
                                    resp = {"ok": False, "error": text or "neko tool error"}
                                else:
                                    resp = {"ok": True, "text": text}
                            except Exception as e:  # noqa: BLE001
                                log.warning("neko.call_failed", tool=nname, err=repr(e))
                                resp = {"ok": False, "error": f"neko: {e!r}"}
                    else:
                        resp = {"ok": False, "error": f"unknown tool: {tool!r}"}
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
