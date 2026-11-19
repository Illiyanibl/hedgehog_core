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

import importlib.metadata
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from .i18n import Msg

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
    # манифест совместимости: {"sdk_before","sdk_after","sdk_pinned","updated",
    # "error","broken"}; {} — манифеста нет. §cli-pins: + "clis": {cli:
    # {"before","after","pinned","updated","error"}} — только установленные CLI
    # с записью в compat.json (ключа нет, если таких нет)
    cli: dict = field(default_factory=dict)


SDK_DIST = "claude-agent-sdk"
_PIP_TIMEOUT = 600
_IMPORT_TIMEOUT = 60
_BUDGET = 900          # общий бюджет pull_latest, сек
_VER_RE = re.compile(
    r"^\d+(\.\d+){1,3}((a|b|rc)\d+)?(\.post\d+)?(\.dev\d+)?$")
_PIP_FLAGS = ["--no-input", "--disable-pip-version-check"]


def _run(args: list[str], cwd: Path, timeout: int = 180) -> tuple[int, str]:
    # GIT_TERMINAL_PROMPT=0 / GIT_ASKPASS=true: git НИКОГДА не зависает в ожидании
    # логина (нет TTY) — падает быстро с понятным кодом, а не «No such device».
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "true"}
    try:
        proc = subprocess.run(
            args, cwd=str(cwd), capture_output=True, text=True, timeout=timeout,
            env=env)
    except (OSError, subprocess.SubprocessError) as e:
        return 1, f"{type(e).__name__}: {e}"
    return proc.returncode, (proc.stdout + proc.stderr).strip()


def _left(deadline: float | None, step: float) -> float:
    """Таймаут шага: min(step, остаток бюджета). <=0 — бюджет исчерпан."""
    if deadline is None:
        return step
    return min(step, deadline - time.monotonic())


def _fetch(root: Path, branch: str,
           deadline: float | None = None) -> tuple[int, str]:
    """git fetch к origin с ретраями (см. _FETCH_BACKOFF).

    credential.helper= (пустой) — НЕ слать никакой stored-токен: репозиторий
    публичный, тянем анонимно, протухший приватный токен не даёт 401.
    http.version=HTTP/1.1 — git по HTTP/2 к GitHub изредка спотыкается на
    фрейминге ответа («expected flush after ref listing»); форс 1.1 убирает флап.
    Ретрай добивает разовые сетевые сбои."""
    code, out = 1, ""
    for i in range(len(_FETCH_BACKOFF) + 1):
        t = _left(deadline, 180)
        if t <= 0:
            return 1, "budget exhausted"
        code, out = _run(
            ["git", "-c", "credential.helper=", "-c", "http.version=HTTP/1.1",
             "fetch", "--depth", "1", "origin", branch], root, timeout=t)
        if code == 0:
            return 0, out
        if i < len(_FETCH_BACKOFF):
            time.sleep(_FETCH_BACKOFF[i])
    return code, out


def read_compat(pkg_dir: Path | None = None) -> dict | None:
    """Читает hedgehog/compat.json (манифест совместимой версии SDK) С ДИСКА.
    None — файла нет / битый JSON / неверные типы. Исключений не бросает."""
    pkg_dir = pkg_dir or Path(__file__).resolve().parent
    try:
        data = json.loads((pkg_dir / "compat.json").read_text(encoding="utf-8"))
        sdk = data["claude_agent_sdk"]
        ver = sdk["version"]
    except (OSError, ValueError, KeyError, TypeError):
        return None
    if not isinstance(ver, str) or not _VER_RE.match(ver.strip()):
        return None       # только точная версия (никаких «,>0», «.*», «; x»)
    return {"claude_agent_sdk": {**sdk, "version": ver.strip()}}


def installed_version(dist: str = SDK_DIST) -> str | None:
    try:
        return importlib.metadata.version(dist)
    except Exception:  # noqa: BLE001  (PackageNotFoundError и порча метаданных)
        return None


def _pip_err(out: str) -> str:
    """Краткая причина из вывода pip: последняя строка с «ERROR:» (≤300)."""
    lines = [ln.strip() for ln in out.splitlines() if ln.strip()]
    errs = [ln for ln in lines if "ERROR:" in ln]
    return (errs or lines or ["no output"])[-1][:300]


def _sdk_importable(root: Path, deadline: float | None = None) -> bool:
    t = _left(deadline, _IMPORT_TIMEOUT)
    if t <= 0:
        return False
    code, _ = _run([sys.executable, "-c", "import claude_agent_sdk"], root,
                   timeout=t)
    return code == 0


def ensure_compat(root: Path, pkg_dir: Path | None = None,
                  deadline: float | None = None) -> dict:
    """НАСТОЯЩИЙ ПИН: приводит установленный claude-agent-sdk ровно к версии
    из compat.json — и вверх, и вниз; SDK нет → ставит пин. После установки
    проверяет `import claude_agent_sdk`; при падении pip или импорта
    переустанавливает прежнюю версию (если была) и проверяет снова. Если SDK
    так и не импортируется — cli["broken"]=True (pull_latest вернёт ok=False и
    НЕ даст рестарт в битый SDK). Не бросает; ошибка → cli["error"].
    {} — манифеста нет.

    pip заменяет файлы SDK на диске: уже запущенные CLI-процессы держат старый
    inode и доживают на прежней версии; новая подхватывается после рестарта
    (restart_in_place → execv сбрасывает кэши импорта)."""
    compat = read_compat(pkg_dir)
    if compat is None:
        return {}
    pinned = compat["claude_agent_sdk"]["version"]
    before = installed_version()
    cli: dict = {"sdk_before": before, "sdk_after": before,
                 "sdk_pinned": pinned, "updated": False, "error": None,
                 "broken": False}
    if before == pinned:
        return cli
    if _left(deadline, _PIP_TIMEOUT) <= 5:
        cli["error"] = "budget exhausted"
        return cli

    def _pip(ver: str) -> tuple[int, str]:
        t = _left(deadline, _PIP_TIMEOUT)
        if t <= 0:
            return 1, "ERROR: budget exhausted"
        return _run([sys.executable, "-m", "pip", "install", *_PIP_FLAGS,
                     f"{SDK_DIST}=={ver}"], root, timeout=t)

    code, out = _pip(pinned)
    err = None
    if code != 0:
        err = f"pip install {SDK_DIST}=={pinned}: {_pip_err(out)}"
    elif not _sdk_importable(root, deadline):
        err = f"import claude_agent_sdk failed after install of {pinned}"
    if err is None:
        cli["sdk_after"] = installed_version() or pinned
        cli["updated"] = True
        return cli

    cli["error"] = err[:300]
    if before is not None:           # откат на прежнюю версию
        _pip(before)
    cli["sdk_after"] = installed_version()
    if not _sdk_importable(root, deadline):
        cli["broken"] = True
    return cli


def ensure_clis(root: Path, pkg_dir: Path | None = None,
                deadline: float | None = None) -> dict:
    """§cli-pins: пины сторонних CLI (compat.json "clis") — только для
    УСТАНОВЛЕННЫХ; политика HEDGEHOG_CLI_AUTO_UPDATE (1 — пин как минимум,
    0 — точный). Ошибки не фатальны (в отчёте). {cli: {...}}."""
    from .core import cli_install
    try:
        return cli_install.ensure_pins(deadline=deadline, pkg_dir=pkg_dir)
    except Exception as e:  # noqa: BLE001 — апдейт кода важнее пинов CLI
        return {"_error": f"{type(e).__name__}: {e}"[:300]}


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


def pull_latest(process_sha: str = "") -> UpdateResult:
    """git fetch + hard reset на текущую ветку + (при изменении) pip install.
    Блокирующая — вызывать через asyncio.to_thread.

    process_sha — короткий SHA, на котором РЕАЛЬНО работает текущий процесс
    (server._SERVER_COMMIT, снят при старте). M5: без него ловится «залипание в
    полуобновлённом»: прошлый апдейт сделал reset --hard (диск→B), но pip/рестарт
    упали → процесс остаётся на A, а диск уже B. Тогда повторный апдейт видел бы
    old(B)==new(B) → «уже актуально», рестарта нет → навсегда на старом коде.
    Поэтому «изменилось» = диск ПОСЛЕ reset ≠ SHA процесса (а не ≠ диск ДО)."""
    deadline = time.monotonic() + _BUDGET      # общий бюджет всего апдейта
    root = repo_root()
    if root is None:
        return UpdateResult(
            ok=False, message=Msg("update.not_git"))

    disk_before = current_sha(root)
    old = process_sha or disk_before      # от чего реально уходим (версия процесса)

    # текущая ветка (обычно main); detached HEAD → main
    code, branch = _run(["git", "rev-parse", "--abbrev-ref", "HEAD"], root)
    if code != 0 or not branch or branch == "HEAD":
        branch = "main"

    req = _requirements(root)
    try:
        req_before = req.read_bytes() if req else b""   # guard: файл могли снести
    except OSError:
        req_before = b""

    # fetch + hard reset — работает и на shallow (--depth 1) клоне. _fetch тянет
    # АНОНИМНО (без stored-токена), с HTTP/1.1 и ретраями.
    code, out = _fetch(root, branch, deadline)
    if code != 0:
        return UpdateResult(ok=False, old=old, message=f"git fetch: {out[-300:]}")
    code, out = _run(["git", "reset", "--hard", f"origin/{branch}"], root)
    if code != 0:
        return UpdateResult(ok=False, old=old, message=f"git reset: {out[-300:]}")

    new = current_sha(root)
    # M5: сверяем с версией ПРОЦЕССА (fallback на disk_before, если SHA процесса
    # неизвестен) — иначе провалившийся ранее апдейт больше не рестартанёт.
    ref = process_sha or disk_before
    changed = bool(new) and new != ref

    # зависимости: если requirements.txt изменился в этом pull ЛИБО диск уже был
    # впереди процесса (прошлый апдейт сделал reset, но deps для B могли не
    # доставиться) — переустанавливаем, чтобы не рестартовать в код без зависимостей.
    try:
        req_after = req.read_bytes() if req else b""
    except OSError:
        req_after = b""
    stale_disk = bool(process_sha) and disk_before != process_sha
    pip_fail = None
    if changed and req and (req_after != req_before or stale_disk):
        # requirements.txt содержит `claude-agent-sdk==<пин>` (зеркало compat.json)
        t = _left(deadline, _PIP_TIMEOUT)
        if t <= 0:
            pip_fail = "budget exhausted"
        else:
            code, out = _run(
                [sys.executable, "-m", "pip", "install", *_PIP_FLAGS,
                 "-r", str(req)], root, timeout=t)
            if code != 0:
                pip_fail = _pip_err(out)

    # манифест совместимого SDK — ВСЕГДА после reset/pip (свежий с диска),
    # независимо от changed: закрывает любое расхождение с requirements.
    cli = ensure_compat(root, deadline=deadline)

    if pip_fail is not None:
        return UpdateResult(ok=False, old=old, new=new, changed=changed,
                            message=f"pip install: {pip_fail}", cli=cli)
    if cli.get("broken"):
        # SDK не импортируется даже после отката — рестарт в него запрещён
        return UpdateResult(ok=False, old=old, new=new, changed=False,
                            message=f"claude-agent-sdk: {cli.get('error')}", cli=cli)
    # §cli-pins: сторонние CLI — после SDK, в общем бюджете; любое реальное
    # обновление → рестарт (процессы CLI пересоздадутся на новой версии).
    clis = ensure_clis(root, deadline=deadline)
    if clis:
        cli = {**cli, "clis": clis}
    clis_updated = [f"{name} {r.get('before') or '—'} → {r.get('after') or '—'}"
                    for name, r in clis.items()
                    if isinstance(r, dict) and r.get("updated")]
    sdk_only = clis_only = False
    if cli.get("updated") and not changed:
        changed = sdk_only = True
    if clis_updated and not changed:
        changed = clis_only = True

    if sdk_only:
        msg = Msg("update.sdk_updated", before=cli.get("sdk_before") or "—",
                  after=cli.get("sdk_after") or "—")
    elif clis_only:
        msg = Msg("update.clis_updated", list=", ".join(clis_updated))
    elif changed:
        msg = Msg("update.updated", old=old, new=new)
    else:
        msg = Msg("update.up_to_date", version=new or old)
    return UpdateResult(ok=True, changed=changed, old=old, new=new, message=msg, cli=cli)


def restart_in_place() -> None:
    """Перезапуск процесса с обновлённым кодом. execv переиспользует тот же
    интерпретатор и заново импортирует модули с диска; окружение (порты,
    токен) наследуется. Слушающие сокеты закрываются (CLOEXEC) → новый
    процесс переприбиндивается. execv также сбрасывает кэши импорта: pip мог
    заменить файлы SDK, запущенные CLI держат старый inode. Доп. аргументы запуска (sys.argv[1:]) сохраняем,
    иначе рестарт после апдейта терял бы переданные флаги."""
    os.execv(sys.executable,
             [sys.executable, "-m", "hedgehog.main", *sys.argv[1:]])
