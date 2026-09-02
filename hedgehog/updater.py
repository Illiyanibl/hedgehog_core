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
import time
from dataclasses import dataclass
from pathlib import Path

# git fetch к GitHub изредка троттлится на анонимном HTTPS (rate-limit отдаёт
# не-протокольный ответ → git не парсит его и в отчаянии просит логин:
# «could not read Username» / «expected flush after ref listing»). Повторяем
# с нарастающей паузой — переживаем транзиентные сбои/лимиты.
_FETCH_BACKOFF = (1.5, 4.0, 9.0)   # паузы между попытками; попыток = len+1


@dataclass
class UpdateResult:
    ok: bool
    changed: bool = False
    old: str = ""
    new: str = ""
    message: str = ""


def _run(args: list[str], cwd: Path) -> tuple[int, str]:
    # GIT_TERMINAL_PROMPT=0 / GIT_ASKPASS=true: git НИКОГДА не зависает в ожидании
    # логина (нет TTY) — падает быстро с понятным кодом, а не «No such device».
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "true"}
    try:
        proc = subprocess.run(
            args, cwd=str(cwd), capture_output=True, text=True, timeout=180,
            env=env)
    except (OSError, subprocess.SubprocessError) as e:
        return 1, f"{type(e).__name__}: {e}"
    return proc.returncode, (proc.stdout + proc.stderr).strip()


def _fetch(root: Path, branch: str) -> tuple[int, str]:
    """git fetch с ретраями (см. _FETCH_BACKOFF) — гасит транзиентный троттлинг
    анонимного HTTPS к GitHub. Возвращает результат последней попытки."""
    code, out = 1, ""
    for i in range(len(_FETCH_BACKOFF) + 1):
        code, out = _run(["git", "fetch", "--depth", "1", "origin", branch], root)
        if code == 0:
            return 0, out
        if i < len(_FETCH_BACKOFF):
            time.sleep(_FETCH_BACKOFF[i])
    return code, out


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

    # fetch + hard reset — работает и на shallow (--depth 1) клоне.
    # _fetch ретраит троттлинг анонимного HTTPS (см. _FETCH_BACKOFF).
    code, out = _fetch(root, branch)
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
