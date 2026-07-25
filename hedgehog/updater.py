"""Самообновление Ёжика: git pull своего исходника + перезапуск процесса.

Работает для установок из git-клона (режимы «Чистый сервер» и «В контейнер»
клонируют публичный репозиторий). Обновление инициирует клиент фреймом
`update_self` — авторизация тем же bearer-токеном, что и WS, поэтому SSH не
нужен. Это критично для серверов, добавленных ТОЛЬКО по порту Ёжика.

Механизм намеренно простой: Ёжик делает `git fetch`+`reset --hard` в своём
репозитории, при необходимости доставляет зависимости, затем перезапускает
сам себя через os.execv (тот же интерпретатор, свежие модули с диска). Окружение
(порты, токен) сохраняется. Супервизор-loop / docker `--restart` — лишь
страховка на случай, если процесс всё же завершится.
"""
from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass
class UpdateResult:
    ok: bool
    changed: bool = False
    old: str = ""
    new: str = ""
    message: str = ""


def _run(args: list[str], cwd: Path) -> tuple[int, str]:
    try:
        proc = subprocess.run(
            args, cwd=str(cwd), capture_output=True, text=True, timeout=180)
    except (OSError, subprocess.SubprocessError) as e:
        return 1, f"{type(e).__name__}: {e}"
    return proc.returncode, (proc.stdout + proc.stderr).strip()


def repo_root() -> Path | None:
    """Корень git-репозитория, из которого запущен Ёжик (где лежит пакет
    hedgehog). None — если это не git-установка (обновление недоступно)."""
    here = Path(__file__).resolve().parent  # .../hedgehog
    code, out = _run(["git", "rev-parse", "--show-toplevel"], here)
    if code != 0 or not out:
        return None
    return Path(out)


def current_sha(root: Path | None = None) -> str:
    root = root or repo_root()
    if root is None:
        return ""
    code, out = _run(["git", "rev-parse", "--short", "HEAD"], root)
    return out if code == 0 else ""


def _requirements(root: Path) -> Path | None:
    for rel in ("requirements.txt", "server/requirements.txt"):
        p = root / rel
        if p.is_file():
            return p
    return None


def pull_latest() -> UpdateResult:
    """git fetch + hard reset на текущую ветку + (при изменении) pip install.
    Блокирующая — вызывать через asyncio.to_thread."""
    root = repo_root()
    if root is None:
        return UpdateResult(
            ok=False, message="не git-установка — обновление недоступно")

    old = current_sha(root)

    # текущая ветка (обычно main); detached HEAD → main
    code, branch = _run(["git", "rev-parse", "--abbrev-ref", "HEAD"], root)
    if code != 0 or not branch or branch == "HEAD":
        branch = "main"

    req = _requirements(root)
    req_before = req.read_bytes() if req else b""

    # fetch + hard reset — работает и на shallow (--depth 1) клоне
    code, out = _run(["git", "fetch", "--depth", "1", "origin", branch], root)
    if code != 0:
        return UpdateResult(ok=False, old=old, message=f"git fetch: {out[-300:]}")
    code, out = _run(["git", "reset", "--hard", f"origin/{branch}"], root)
    if code != 0:
        return UpdateResult(ok=False, old=old, message=f"git reset: {out[-300:]}")

    new = current_sha(root)
    changed = bool(new) and new != old

    # зависимости — только если requirements.txt изменился (обычно нет)
    if changed and req and req.read_bytes() != req_before:
        code, out = _run(
            [sys.executable, "-m", "pip", "install", "-q", "-r", str(req)], root)
        if code != 0:
            return UpdateResult(ok=False, old=old, new=new, changed=changed,
                                message=f"pip install: {out[-300:]}")

    msg = f"обновлено {old} → {new}" if changed else f"уже актуально ({old})"
    return UpdateResult(ok=True, changed=changed, old=old, new=new, message=msg)


def restart_in_place() -> None:
    """Перезапуск процесса с обновлённым кодом. execv переиспользует тот же
    интерпретатор и заново импортирует модули с диска; окружение (порты,
    токен) наследуется. Слушающие сокеты закрываются (CLOEXEC) → новый
    процесс переприбиндивается."""
    os.execv(sys.executable, [sys.executable, "-m", "hedgehog.main"])
