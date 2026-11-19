#!/usr/bin/env python3
"""PreToolUse-хук Grok (stdlib-only; подключается в config.toml управляемого
GROK_HOME, см. core/grok_rpc.permission_config).

Grok читает файлы и выполняет read-only shell-команды без запроса даже вне
рабочего каталога. Хук возвращает {"decision": "ask"} для обращения к пути вне
cwd (кроме системных каталогов) — Grok превращает это в обычный
session/request_permission → политика Ёжика (default/acceptEdits спросят
пользователя, bypassPermissions разрешит). Любая ошибка → defer (fail-open: хук —
дополнительная страховка, а не единственная защита; секреты закрыты deny-правилами).
"""
import json
import os
import shlex
import sys

# обращения сюда не считаем «выходом за рабочий каталог»
SAFE_PREFIXES = ("/tmp", "/var/tmp", "/usr", "/bin", "/sbin", "/lib", "/lib64",
                 "/dev/null", "/dev/stdin", "/dev/stdout", "/dev/stderr",
                 "/dev/tty", "/dev/zero", "/dev/urandom")
PATH_KEYS = ("target_file", "file_path", "path", "target_directory", "directory",
             "dir", "AbsolutePath", "Path")
FILE_TOOLS = ("read_file", "list_dir", "grep", "Read", "Grep", "Glob", "LS")
SHELL_TOOLS = ("run_terminal_command", "Bash")


def _inside(path: str, root: str) -> bool:
    try:
        r = os.path.realpath(root)
        p = os.path.realpath(path if os.path.isabs(path) else os.path.join(r, path))
        return os.path.commonpath([p, r]) == r
    except (ValueError, OSError):
        return False


def _is_safe(path: str) -> bool:
    return any(path == s or path.startswith(s + "/") for s in SAFE_PREFIXES)


def _expand(tok: str, cwd: str) -> str | None:
    """Токен shell-команды → абсолютный путь, если он похож на путь; иначе None."""
    if tok.startswith(">"):            # редирект >file, >>file
        tok = tok.lstrip(">")
    if "=" in tok and not tok.startswith(("/", "~", ".")):
        tok = tok.split("=", 1)[1]     # --opt=/path, VAR=/path
    if not tok or tok.startswith("-") or "://" in tok:
        return None
    if tok.startswith("~"):
        tok = os.path.expanduser(tok)
    if tok.startswith("/") or tok.startswith("../") or tok == "..":
        return os.path.realpath(tok if os.path.isabs(tok) else os.path.join(cwd, tok))
    return None


def candidate_paths(tool: str, tool_input: dict, cwd: str) -> list[str]:
    out: list[str] = []
    if tool in FILE_TOOLS:
        for k in PATH_KEYS:
            v = tool_input.get(k)
            if isinstance(v, str) and v:
                out.append(os.path.realpath(
                    os.path.expanduser(v) if v.startswith("~") else
                    (v if os.path.isabs(v) else os.path.join(cwd, v))))
    elif tool in SHELL_TOOLS:
        cmd = tool_input.get("command")
        if isinstance(cmd, str):
            try:
                toks = shlex.split(cmd, posix=True)
            except ValueError:
                toks = cmd.split()
            for t in toks:
                for piece in (t.replace("|", " ").replace(";", " ").replace("&", " ")
                              .replace("(", " ").replace(")", " ").split() or [t]):
                    p = _expand(piece, cwd)
                    if p:
                        out.append(p)
    return out


def decide(payload: dict) -> dict:
    tool = str(payload.get("toolName") or payload.get("tool_name") or "")
    tin = payload.get("toolInput") or payload.get("tool_input") or {}
    cwd = str(payload.get("cwd") or payload.get("workspaceRoot") or os.getcwd())
    if not isinstance(tin, dict):
        return {"decision": "defer"}
    for p in candidate_paths(tool, tin, cwd):
        if not _inside(p, cwd) and not _is_safe(p):
            return {"decision": "ask",
                    "reason": f"Hedgehog: access outside the working directory: {p}"}
    return {"decision": "defer"}


def main() -> None:
    try:
        out = decide(json.loads(sys.stdin.read() or "{}"))
    except Exception:  # noqa: BLE001 — fail-open
        out = {"decision": "defer"}
    sys.stdout.write(json.dumps(out) + "\n")


if __name__ == "__main__":
    main()
