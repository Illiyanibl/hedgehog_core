#!/usr/bin/env python3
"""§multi-cli: stdio-MCP-мост к встроенным тулам Ёжика (stdlib-only).

CLI без in-process MCP (Antigravity) запускает этот скрипт как обычный
stdio-MCP-сервер `hedgehog`; мост транслирует `tools/list` и `tools/call` в
unix-сокет ctl_server (тот же канал и те же хендлеры, что у нативного MCP и у
Bash-«ручки», §ctl). Сокет и per-session токен берутся из env
(HEDGEHOG_CTL_SOCK / HEDGEHOG_CTL_TOKEN), которые Ёжик кладёт в запись
mcpServers при старте сессии.

Транспорт MCP stdio: JSON-RPC 2.0, по одному сообщению на строку. Вызовы тулов
идут в потоках — ask_ui ждёт пользователя минутами и не должен блокировать
ping/cancel.
"""
import json
import os
import socket
import sys
import threading

PROTOCOL_DEFAULT = "2024-11-05"
# `mcp_bridge.py --server NAME` — мост к ДРУГОМУ серверу, обслуживаемому ctl_server
# (neko_browser): запросы получают поле server, имя в initialize — NAME.
SERVER = sys.argv[sys.argv.index("--server") + 1] if "--server" in sys.argv[1:-1] else None
_out_lock = threading.Lock()


def _send(obj: dict) -> None:
    data = json.dumps(obj, ensure_ascii=False) + "\n"
    with _out_lock:
        sys.stdout.write(data)
        sys.stdout.flush()


def _ctl(req: dict) -> dict:
    sock_path = os.environ.get("HEDGEHOG_CTL_SOCK")
    token = os.environ.get("HEDGEHOG_CTL_TOKEN")
    if not sock_path or not token:
        return {"ok": False, "error": "no HEDGEHOG_CTL_SOCK/TOKEN in env"}
    try:
        timeout = float(os.environ.get("HEDGEHOG_CTL_TIMEOUT") or 3660)
    except ValueError:
        timeout = 3660.0
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(sock_path)
        s.sendall((json.dumps(dict(req, token=token), ensure_ascii=False)
                   + "\n").encode("utf-8"))
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
        return json.loads(buf.decode("utf-8")) if buf else {
            "ok": False, "error": "empty reply from hedgehog"}
    except (OSError, ValueError) as e:
        return {"ok": False, "error": f"hedgehog ctl: {e!r}"}
    finally:
        s.close()


def _with_server(req: dict) -> dict:
    return dict(req, server=SERVER) if SERVER else req


def _call_tool(rid, params: dict) -> None:
    name = params.get("name")
    args = params.get("arguments") or {}
    res = _ctl(_with_server({"op": "call", "tool": name, "args": args}))
    if res.get("ok"):
        _send({"jsonrpc": "2.0", "id": rid, "result": {
            "content": [{"type": "text", "text": str(res.get("text", ""))}],
            "isError": False}})
    else:
        _send({"jsonrpc": "2.0", "id": rid, "result": {
            "content": [{"type": "text", "text": str(res.get("error", "error"))}],
            "isError": True}})


def handle(msg: dict) -> None:
    method, rid = msg.get("method"), msg.get("id")
    if method == "initialize":
        want = (msg.get("params") or {}).get("protocolVersion") or PROTOCOL_DEFAULT
        _send({"jsonrpc": "2.0", "id": rid, "result": {
            "protocolVersion": want, "capabilities": {"tools": {}},
            "serverInfo": {"name": SERVER or "hedgehog", "version": "1"}}})
    elif method == "tools/list":
        res = _ctl(_with_server({"op": "catalog"}))
        if not res.get("ok"):
            _send({"jsonrpc": "2.0", "id": rid, "error": {
                "code": -32000, "message": str(res.get("error", "ctl error"))}})
            return
        _send({"jsonrpc": "2.0", "id": rid, "result": {"tools": [
            {"name": t["name"], "description": t.get("description", ""),
             "inputSchema": t.get("input_schema") or {"type": "object"}}
            for t in res.get("tools", [])]}})
    elif method == "tools/call":
        threading.Thread(target=_call_tool, args=(rid, msg.get("params") or {}),
                         daemon=True).start()
    elif method == "ping":
        _send({"jsonrpc": "2.0", "id": rid, "result": {}})
    elif rid is not None:           # запрос, который мы не знаем
        _send({"jsonrpc": "2.0", "id": rid, "error": {
            "code": -32601, "message": f"method not found: {method}"}})
    # уведомления (notifications/initialized, cancelled …) — молча


def main() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        if isinstance(msg, dict):
            handle(msg)


if __name__ == "__main__":
    main()
