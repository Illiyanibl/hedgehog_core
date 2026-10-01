#!/usr/bin/env python3
"""§ctl: CLI-клиент «ручки» MCP-тулов Ёжика (stdlib-only — работает любым python3).

Агент вызывает из Bash:
    python3 "$HEDGEHOG_CALL" <tool> '<json-args>'
    python3 "$HEDGEHOG_CALL" <tool> -   < большой JSON на stdin (для HTML ui_open/ask_ui)

Сокет и токен берутся из env (HEDGEHOG_CTL_SOCK / HEDGEHOG_CTL_TOKEN), которые
Ёжик кладёт в окружение агента при старте под omniroute. Результат тула печатается
в stdout; при ошибке — текст в stderr и ненулевой код выхода.
"""
import json
import os
import socket
import sys


def _die(msg: str, code: int) -> None:
    print(msg, file=sys.stderr)
    sys.exit(code)


def main() -> None:
    sock = os.environ.get("HEDGEHOG_CTL_SOCK")
    token = os.environ.get("HEDGEHOG_CTL_TOKEN")
    if not sock or not token:
        _die("hedgehog-call: недоступно (нет HEDGEHOG_CTL_SOCK/TOKEN в env)", 2)
    if len(sys.argv) < 2:
        _die("usage:\n"
             "  hedgehog-call --list                  — список тулов + описания\n"
             "  hedgehog-call <tool> --schema         — JSON-схема аргументов тула\n"
             "  hedgehog-call <tool> ['<json>'|-]     — вызвать тул (- = JSON со stdin)", 2)

    # §ctl самоописание: --list и <tool> --schema не требуют аргументов.
    if sys.argv[1] == "--list":
        req = json.dumps({"token": token, "op": "list"})
    elif len(sys.argv) > 2 and sys.argv[2] == "--schema":
        req = json.dumps({"token": token, "op": "schema", "tool": sys.argv[1]})
    else:
        tool = sys.argv[1]
        arg = sys.argv[2] if len(sys.argv) > 2 else "{}"
        if arg == "-":
            arg = sys.stdin.read()
        arg = arg.strip() or "{}"
        try:
            args = json.loads(arg)
        except Exception as e:  # noqa: BLE001
            _die(f"hedgehog-call: битый JSON аргументов: {e}", 2)
        if not isinstance(args, dict):
            _die("hedgehog-call: аргументы должны быть JSON-объектом", 2)
        req = json.dumps({"token": token, "op": "call", "tool": tool, "args": args})
    try:
        timeout = float(os.environ.get("HEDGEHOG_CTL_TIMEOUT") or 3660)
    except ValueError:
        timeout = 3660.0
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(timeout)   # ask_ui ждёт пользователя (≈ ui_timeout + запас)
        s.connect(sock)
        s.sendall(req.encode("utf-8") + b"\n")
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
        s.close()
    except Exception as e:  # noqa: BLE001
        _die(f"hedgehog-call: соединение не удалось: {e}", 1)

    try:
        resp = json.loads(buf.decode("utf-8"))
    except Exception as e:  # noqa: BLE001
        _die(f"hedgehog-call: битый ответ сервера: {e}", 1)

    if resp.get("ok"):
        sys.stdout.write((resp.get("text") or "") + "\n")
        sys.exit(0)
    _die(f"hedgehog-call error: {resp.get('error')}", 1)


if __name__ == "__main__":
    main()
