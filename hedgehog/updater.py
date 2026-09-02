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

# Ёжик обновляется ТОЛЬКО с публичного репозитория. Часть серверов была
# склонирована с приватного git.insapp.pro (токен в /root/.git-credentials —
# фактически дыра: root читает секрет к приватному git). Токен протух → git
# fetch отдавал HTTP 401. Публичный github токена не требует: на каждом апдейте
# перецеливаем origin сюда и тянем АНОНИМНО (credential.helper пустой) — 401
# и утечка токена исключены by design.
_PUBLIC_REMOTE = "https://github.com/Illiyanibl/hedgehog_core.git"

# git fetch по HTTPS изредка спотыкается (HTTP/2-фрейминг git↔GitHub, разовые
# сетевые сбои) → git не парсит ответ и просит логин («could not read Username»
# / «expected flush after ref listing»). Повторяем с нарастающей паузой.
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
    """git fetch к origin с ретраями (см. _FETCH_BACKOFF).

    credential.helper= (пустой) — НЕ слать никакой stored-токен: репозиторий
    публичный, тянем анонимно, протухший приватный токен не даёт 401.
    http.version=HTTP/1.1 — git по HTTP/2 к GitHub изредка спотыкается на
    фрейминге ответа («expected flush after ref listing»); форс 1.1 убирает флап.
    Ретрай добивает разовые сетевые сбои."""
    code, out = 1, ""
    for i in range(len(_FETCH_BACKOFF) + 1):
        code, out = _run(
            ["git", "-c", "credential.helper=", "-c", "http.version=HTTP/1.1",
             "fetch", "--depth", "1", "origin", branch], root)
        if code == 0:
            return 0, out
        if i < len(_FETCH_BACKOFF):
            time.sleep(_FETCH_BACKOFF[i])
    return code, out


def _ensure_public_origin(root: Path) -> str | None:
    """Перецелить origin на публичный репозиторий, если он смотрит в другое место
    (старый провижининг клонировал приватный git.insapp.pro). Идемпотентно.
    Возвращает прежний URL, если менялся, иначе None — для сообщения апдейта."""
    code, url = _run(["git", "remote", "get-url", "origin"], root)
    if code != 0:
        return None
    url = url.strip()
    if url == _PUBLIC_REMOTE:
        return None
    _run(["git", "remote", "set-url", "origin", _PUBLIC_REMOTE], root)
    return url


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

    # «Ссылаться только на публичный»: перецеливаем origin на публичный github,
    # если он смотрел на приватный источник (старый провижининг).
    repointed = _ensure_public_origin(root)

    # fetch + hard reset — работает и на shallow (--depth 1) клоне. _fetch тянет
    # АНОНИМНО (без stored-токена), с HTTP/1.1 и ретраями.
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
    if repointed:
        msg += " · origin → публичный github"
    return UpdateResult(ok=True, changed=changed, old=old, new=new, message=msg)


def restart_in_place() -> None:
    """Перезапуск процесса с обновлённым кодом. execv переиспользует тот же
    интерпретатор и заново импортирует модули с диска; окружение (порты,
    токен) наследуется. Слушающие сокеты закрываются (CLOEXEC) → новый
    процесс переприбиндивается."""
    os.execv(sys.executable, [sys.executable, "-m", "hedgehog.main"])
