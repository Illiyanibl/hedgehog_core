"""§cli-pins: установка и обновление сторонних CLI (Codex, Grok, Antigravity)
ровно до версии из hedgehog/compat.json ("clis").

Синхронный модуль: вызывать из потока (asyncio.to_thread). Без shell — только
argv-списки, у каждого процесса таймаут; загрузка — urllib (только https, в т.ч.
редиректы), лимит размера, хэш проверяется ДО распаковки/замены; временные
файлы — внутри целевого каталога (атомарный os.replace на той же ФС).

Способы установки:
  * codex  — npm (бинарь лежит в node_modules/@openai/codex) → `npm i -g
    @openai/codex@<v>`; управляемый каталог → пакет GitHub-релиза
    codex-package-<triple>.tar.gz (sha256 из GitHub API) в codex-<v>-<rnd>/ и
    атомарная смена симлинка <dir>/codex. Прочие раскладки не трогаем.
  * grok   — управляемый каталог → бинарь https://x.ai/cli/grok-<v>-<plat>[.gz];
    иначе встроенный установщик `grok update --version <v>`.
  * antigravity — tar.gz из GCS (sha512 из манифеста) → файл `antigravity` из
    архива атомарно заменяет бинарь по пути find_binary (или <dir>/agy).
После установки `--version` обязан совпасть с пином, иначе откат на прежний
бинарь (бэкап файла / прежний симлинк / npm|grok update прежней версии).
"""

from __future__ import annotations

import asyncio
import gzip
import hashlib
import json
import os
import platform
import re
import secrets
import shutil
import subprocess
import tarfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

import structlog

from . import cli_registry

log = structlog.get_logger("cli_install")

INSTALLABLE = ("codex", "grok", "antigravity")

# Версия CLI: PEP 440-подобная (как пин SDK в updater._VER_RE) ЛИБО semver с
# pre-release через дефис (grok 0.1.151-alpha.2, codex 0.170.0-alpha.1).
# Никаких пробелов/операторов — значение уходит в argv (`@openai/codex@<v>`).
_VER_RE = re.compile(
    r"^\d+(\.\d+){1,3}"
    r"(((a|b|rc)\d+)?(\.post\d+)?(\.dev\d+)?|-[0-9A-Za-z]+(\.[0-9A-Za-z]+)*)$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SHA512_RE = re.compile(r"^[0-9a-f]{128}$")
_VERSION_IN_OUTPUT = re.compile(r"(?<![\w.])(\d+\.\d+(?:\.\d+){0,2}(?:-[0-9A-Za-z.]+)?)")

# разрешённые источники загрузки (префиксы https-URL)
_URL_PREFIXES = {
    "codex": ("https://github.com/openai/codex/releases/download/",),
    "grok": ("https://x.ai/cli/",
             "https://storage.googleapis.com/grok-build-public-artifacts/cli/"),
    "antigravity": ("https://storage.googleapis.com/antigravity-public/antigravity-cli/",),
}
# какой хэш обязателен для ассета (grok: xAI хэшей не публикует → опционально)
_HASH_KIND = {"codex": "sha256", "grok": "sha256", "antigravity": "sha512"}
_HASH_REQUIRED = {"codex": True, "grok": False, "antigravity": True}
PLATFORMS = ("linux-x86_64", "linux-aarch64")
CODEX_TRIPLES = {"linux-x86_64": "x86_64-unknown-linux-musl",
                 "linux-aarch64": "aarch64-unknown-linux-musl"}

INSTALL_TIMEOUT = 900          # одна установка/обновление CLI, сек
_VERSION_TIMEOUT = 20
_NPM_TIMEOUT = 600
_GROK_UPDATE_TIMEOUT = 600
_ROLLBACK_TIMEOUT = 300
_READ_TIMEOUT = 60             # сокет urllib (на чтение блока)
_MAX_DOWNLOAD = 700 * 1024 * 1024     # архив/бинарь
_MAX_EXTRACT = 1024 * 1024 * 1024     # распакованное суммарно
_MAX_BINARY = 600 * 1024 * 1024       # один исполняемый файл
_CHUNK = 1 << 20


class InstallError(RuntimeError):
    pass


# ---------------------------------------------------------------- версии ----

def parse_version_output(text: str) -> str | None:
    """Версия из вывода `<cli> --version`: "codex-cli 0.167.2",
    "grok 1.0.77 (50ca579fa996) [stable]", "1.5.10"."""
    for line in (text or "").splitlines():
        m = _VERSION_IN_OUTPUT.search(line.strip())
        if m:
            return m.group(1)
    return None


def _fallback_key(v: str) -> tuple:
    """Ключ сравнения без packaging: числа + pre-release ниже релиза."""
    m = re.match(r"^(\d+(?:\.\d+)*)(.*)$", v.strip())
    if not m:
        return ((), 0, v)
    nums = tuple(int(x) for x in m.group(1).split("."))
    while nums and nums[-1] == 0:
        nums = nums[:-1]
    rest = m.group(2).lstrip("-.")
    if not rest:
        return (nums, 2, ())
    if rest.startswith("post"):
        return (nums, 3, _pre_parts(rest))
    return (nums, 1, _pre_parts(rest))        # a/b/rc/alpha/beta/dev → раньше релиза


def _pre_parts(rest: str) -> tuple:
    out = []
    for p in re.findall(r"\d+|[A-Za-z]+", rest):
        out.append((1, int(p), "") if p.isdigit() else (0, 0, p.lower()))
    return tuple(out)


def compare_versions(a: str, b: str) -> int:
    """-1 / 0 / 1. packaging.version, если есть и разбирает обе; иначе свой разбор."""
    try:
        from packaging.version import Version
        va, vb = Version(a), Version(b)
        return (va > vb) - (va < vb)
    except Exception:  # noqa: BLE001 — нет packaging / нестандартная строка
        ka, kb = _fallback_key(a), _fallback_key(b)
        return (ka > kb) - (ka < kb)


# ------------------------------------------------------------- манифест ----

def platform_key() -> str | None:
    if platform.system().lower() != "linux":
        return None
    arch = {"x86_64": "x86_64", "amd64": "x86_64",
            "aarch64": "aarch64", "arm64": "aarch64"}.get(platform.machine().lower())
    return f"linux-{arch}" if arch else None


def _valid_url(cli: str, url: Any) -> bool:
    if not isinstance(url, str) or len(url) > 512:
        return False
    if any(ch.isspace() for ch in url) or ".." in url or "\\" in url:
        return False
    try:
        u = urllib.parse.urlsplit(url)
    except ValueError:
        return False
    if u.scheme != "https" or u.query or u.fragment or "@" in u.netloc:
        return False
    return any(url.startswith(p) and len(url) > len(p)
               for p in _URL_PREFIXES.get(cli, ()))


def validate_entry(cli: str, raw: Any) -> dict | None:
    """Строгая проверка записи compat.json["clis"][cli]; None — невалидна.
    Форма: {"version": "...", "assets": {"linux-x86_64": {"url", "sha256"|"sha512"}}}."""
    if cli not in INSTALLABLE or not isinstance(raw, dict):
        return None
    ver = raw.get("version")
    if not isinstance(ver, str) or not _VER_RE.match(ver.strip()):
        return None
    out: dict = {"version": ver.strip(), "assets": {}}
    assets = raw.get("assets", {})
    if not isinstance(assets, dict):
        return None
    kind = _HASH_KIND[cli]
    for plat, a in assets.items():
        if plat not in PLATFORMS or not isinstance(a, dict):
            return None
        if not _valid_url(cli, a.get("url")):
            return None
        digest = a.get(kind)
        if digest is None and _HASH_REQUIRED[cli]:
            return None
        rx = _SHA512_RE if kind == "sha512" else _SHA256_RE
        if digest is not None and (not isinstance(digest, str) or not rx.match(digest)):
            return None
        other = {"sha256", "sha512"} - {kind}
        if any(k in a for k in other):
            return None
        rec = {"url": a["url"]}
        if digest is not None:
            rec[kind] = digest
        out["assets"][plat] = rec
    if cli in ("codex", "antigravity") and not out["assets"]:
        return None
    return out


def read_pins(pkg_dir: Path | None = None) -> dict[str, dict]:
    """Валидные записи compat.json["clis"]; невалидная запись пропускается (лог),
    остальные работают. {} — нет файла/раздела. Не бросает."""
    pkg_dir = pkg_dir or Path(__file__).resolve().parent.parent
    try:
        data = json.loads((pkg_dir / "compat.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    clis = data.get("clis") if isinstance(data, dict) else None
    if not isinstance(clis, dict):
        return {}
    out = {}
    for cli, raw in clis.items():
        entry = validate_entry(cli, raw)
        if entry is None:
            log.warning("cli_install.bad_entry", cli=str(cli)[:40])
            continue
        out[cli] = entry
    return out


def asset_for(cli: str, entry: dict, plat: str | None = None) -> dict | None:
    """Ассет записи для платформы сервера; у grok без явных ассетов — URL по
    схеме официального установщика (без хэша — его xAI не публикует)."""
    plat = plat or platform_key()
    if plat is None:
        return None
    a = entry.get("assets", {}).get(plat)
    if a is not None:
        return a
    if cli == "grok":
        return {"url": f"https://x.ai/cli/grok-{entry['version']}-{plat}.gz"}
    return None


def installable(cli: str, pins: dict | None = None) -> bool:
    """Есть валидная запись и ассет для этой платформы."""
    pins = read_pins() if pins is None else pins
    entry = pins.get(cli)
    return entry is not None and asset_for(cli, entry) is not None


# ------------------------------------------------------------ процессы ----

def _tool_env(cli: str, binary: str | None) -> dict[str, str]:
    """env служебных вызовов CLI (--version/npm/grok update): белый список без
    управляемого GROK_HOME (установщик grok живёт в ~/.grok) и без флага
    GROK_DISABLE_AUTOUPDATER (не мешать явному `grok update`). agy не должен
    обновлять себя в фоне, пока мы меняем его файл."""
    env = cli_registry.spawn_env(cli, binary)
    for k in ("GROK_HOME", "GROK_DISABLE_AUTOUPDATER"):
        env.pop(k, None)
    if cli == "antigravity":
        env["AGY_CLI_DISABLE_AUTO_UPDATE"] = "1"
    if cli == "codex":
        for k, v in os.environ.items():
            if k.lower().startswith("npm_config_"):
                env[k] = v
    return env


def _run(argv: list[str], *, timeout: float, env: dict | None = None
         ) -> tuple[int, str]:
    if timeout <= 0:
        return 1, "budget exhausted"
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                           env=env, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError) as e:
        return 1, f"{type(e).__name__}: {e}"
    return p.returncode, ((p.stdout or "") + (p.stderr or "")).strip()


def installed_version(cli: str, binary: str | None = None,
                      timeout: float = _VERSION_TIMEOUT) -> str | None:
    """Версия установленного CLI по `<bin> --version`; None — нет/не разобрать."""
    binary = binary or cli_registry.find_binary(cli)
    if not binary:
        return None
    code, out = _run([binary, "--version"], timeout=timeout,
                     env=_tool_env(cli, binary))
    if code != 0:
        return None
    return parse_version_output(out)


class _Ctx:
    def __init__(self, timeout: float, cancel: threading.Event | None):
        self.deadline = time.monotonic() + timeout
        self.cancel = cancel

    def left(self, step: float) -> float:
        return min(step, self.deadline - time.monotonic())

    def check(self) -> None:
        if self.cancel is not None and self.cancel.is_set():
            raise InstallError("cancelled")
        if time.monotonic() > self.deadline:
            raise InstallError("timeout")


# ------------------------------------------------------------- загрузка ----

class _HttpsOnlyRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not str(newurl).lower().startswith("https://"):
            raise urllib.error.URLError(f"refusing non-https redirect to {newurl!r}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_opener = urllib.request.build_opener(_HttpsOnlyRedirect)


def _open_url(url: str, timeout: float):
    """Открыть URL (точка подмены в тестах). Только https."""
    if not url.lower().startswith("https://"):
        raise InstallError("only https downloads are allowed")
    req = urllib.request.Request(url, headers={"User-Agent": "hedgehog-cli-install"})
    return _opener.open(req, timeout=timeout)


def _download(url: str, dest: Path, ctx: _Ctx, max_bytes: int = _MAX_DOWNLOAD
              ) -> dict[str, str]:
    """Скачать в dest (поток, лимит размера) → {"sha256","sha512"}."""
    h256, h512 = hashlib.sha256(), hashlib.sha512()
    total = 0
    ctx.check()
    try:
        with _open_url(url, max(1.0, ctx.left(_READ_TIMEOUT))) as resp, \
                open(dest, "wb") as f:
            cl = (getattr(resp, "headers", None) or {}).get("Content-Length")
            if cl and str(cl).isdigit() and int(cl) > max_bytes:
                raise InstallError(f"download too large ({cl} bytes)")
            while True:
                ctx.check()
                chunk = resp.read(_CHUNK)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise InstallError("download too large")
                f.write(chunk)
                h256.update(chunk)
                h512.update(chunk)
    except InstallError:
        raise
    except (OSError, urllib.error.URLError, ValueError) as e:
        raise InstallError(f"download failed: {type(e).__name__}: {e}") from e
    if total == 0:
        raise InstallError("empty download")
    return {"sha256": h256.hexdigest(), "sha512": h512.hexdigest()}


def _check_hash(cli: str, digests: dict[str, str], asset: dict) -> None:
    kind = _HASH_KIND[cli]
    want = asset.get(kind)
    if want is None:
        if _HASH_REQUIRED[cli]:
            raise InstallError(f"{kind} missing in compat entry")
        log.warning("cli_install.no_hash", cli=cli, url=asset.get("url"))
        return
    if digests.get(kind) != want:
        raise InstallError(f"{kind} mismatch")


# ------------------------------------------------------------ файлы/архивы ----

def _within(root: Path, p: Path) -> bool:
    try:
        p.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def _copy_stream(src, dst: Path, ctx: _Ctx, limit: int, mode: int) -> int:
    n = 0
    fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(fd, "wb") as out:
        while True:
            ctx.check()
            chunk = src.read(_CHUNK)
            if not chunk:
                break
            n += len(chunk)
            if n > limit:
                raise InstallError("extracted file too large")
            out.write(chunk)
    os.chmod(dst, mode)
    return n


def _safe_extract(archive: Path, dest: Path, ctx: _Ctx) -> None:
    """Распаковать tar.gz БЕЗ tarfile.extractall: только обычные файлы, каталоги
    и относительные симлинки внутрь dest; без абсолютных путей и «..»; лимит
    суммарного размера; права файлов 0755/0644."""
    dest.mkdir(mode=0o755)
    total = 0
    try:
        tf = tarfile.open(archive, "r:gz")
    except (tarfile.TarError, OSError) as e:
        raise InstallError(f"bad archive: {e}") from e
    with tf:
        for m in tf:
            ctx.check()
            name = m.name
            while name.startswith("./"):
                name = name[2:]
            if not name or name == ".":
                continue
            parts = Path(name).parts
            if name.startswith("/") or ".." in parts:
                raise InstallError(f"unsafe path in archive: {m.name!r}")
            target = dest.joinpath(*parts)
            if not _within(dest, target.parent):
                raise InstallError(f"unsafe path in archive: {m.name!r}")
            if m.isdir():
                target.mkdir(mode=0o755, parents=True, exist_ok=True)
            elif m.isfile():
                total += m.size
                if total > _MAX_EXTRACT:
                    raise InstallError("archive too large when extracted")
                target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                src = tf.extractfile(m)
                if src is None:
                    raise InstallError(f"cannot read {m.name!r}")
                with src:
                    _copy_stream(src, target, ctx, _MAX_BINARY,
                                 0o755 if m.mode & 0o111 else 0o644)
            elif m.issym():
                link = m.linkname
                if link.startswith("/") or not _within(
                        dest, (target.parent / link)):
                    raise InstallError(f"unsafe symlink in archive: {m.name!r}")
                target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                os.symlink(link, target)
            else:
                raise InstallError(f"unsupported archive member: {m.name!r}")


def _extract_member(archive: Path, member: str, dest: Path, ctx: _Ctx) -> None:
    """Достать один обычный файл member из tar.gz в dest (0755)."""
    try:
        tf = tarfile.open(archive, "r:gz")
    except (tarfile.TarError, OSError) as e:
        raise InstallError(f"bad archive: {e}") from e
    with tf:
        for m in tf:
            ctx.check()
            name = m.name
            while name.startswith("./"):
                name = name[2:]
            if name == member:
                if not m.isfile():
                    raise InstallError(f"{member!r} in archive is not a file")
                src = tf.extractfile(m)
                if src is None:
                    raise InstallError(f"cannot read {member!r}")
                with src:
                    _copy_stream(src, dest, ctx, _MAX_BINARY, 0o755)
                return
    raise InstallError(f"{member!r} not found in archive")


def _gunzip(src: Path, dest: Path, ctx: _Ctx) -> None:
    try:
        with gzip.open(src, "rb") as g:
            _copy_stream(g, dest, ctx, _MAX_BINARY, 0o755)
    except (OSError, EOFError, gzip.BadGzipFile) as e:
        raise InstallError(f"bad gzip: {e}") from e


def _swap_file(target: Path, new: Path) -> Path | None:
    """Атомарно поставить new на место target; прежний файл → бэкап (hardlink,
    иначе копия). Возвращает путь бэкапа (None — target не было)."""
    bak = None
    if os.path.lexists(target):
        bak = target.with_name(f".{target.name}.hedgehog-bak")
        if os.path.lexists(bak):
            os.unlink(bak)
        try:
            os.link(target, bak, follow_symlinks=False)
        except OSError:
            shutil.copy2(target, bak, follow_symlinks=False)
    os.replace(new, target)
    return bak


def _restore_file(target: Path, bak: Path | None) -> None:
    try:
        if bak is not None:
            os.replace(bak, target)
        elif os.path.lexists(target):
            os.unlink(target)
    except OSError as e:
        log.error("cli_install.restore_failed", target=str(target), err=repr(e))


def _drop(p: Path | None) -> None:
    if p is None:
        return
    try:
        if p.is_dir() and not p.is_symlink():
            shutil.rmtree(p, ignore_errors=True)
        elif os.path.lexists(p):
            os.unlink(p)
    except OSError:
        pass


def _version_of(cli: str, binary: str, ctx: _Ctx) -> str | None:
    return installed_version(cli, binary, timeout=max(1.0, ctx.left(_VERSION_TIMEOUT)))


def _expect_version(cli: str, binary: str, pin: str, ctx: _Ctx) -> str:
    got = _version_of(cli, binary, ctx)
    if got is None or compare_versions(got, pin) != 0:
        raise InstallError(f"{cli} --version reports {got or 'nothing'}, expected {pin}")
    return got


# ---------------------------------------------------------- способы установки ----

def _staged_binary(cli: str, entry: dict, asset: dict, workdir: Path,
                   ctx: _Ctx) -> Path:
    """grok/agy: скачать, сверить хэш, получить исполняемый файл в workdir."""
    url = asset["url"]
    payload = workdir / "payload"
    digests = _download(url, payload, ctx)
    _check_hash(cli, digests, asset)          # ДО распаковки/замены
    out = workdir / "binary"
    path = urllib.parse.urlsplit(url).path
    if path.endswith((".tar.gz", ".tgz")):
        _extract_member(payload, "antigravity" if cli == "antigravity" else cli,
                        out, ctx)
    elif path.endswith(".gz"):
        _gunzip(payload, out, ctx)
    else:
        os.replace(payload, out)
        os.chmod(out, 0o755)
    _drop(payload)
    _expect_version(cli, str(out), entry["version"], ctx)   # до замены
    return out


def _install_file(cli: str, entry: dict, target: Path, ctx: _Ctx) -> str:
    """Скачать бинарь и атомарно заменить файл target (бэкап → откат)."""
    asset = asset_for(cli, entry)
    if asset is None:
        raise InstallError(f"no {cli} build for platform {platform_key()}")
    target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    work = Path(_mkdtemp(target.parent, f".{cli}-dl-"))
    try:
        staged = _staged_binary(cli, entry, asset, work, ctx)
        bak = _swap_file(target, staged)
        try:
            got = _expect_version(cli, str(target), entry["version"], ctx)
        except InstallError:
            _restore_file(target, bak)
            raise
        _drop(bak)
        return got
    finally:
        _drop(work)


_STALE_AGE = 3600


def _mkdtemp(parent: Path, prefix: str) -> str:
    """Каталог загрузки внутри целевого (та же ФС → атомарный os.replace).
    Заодно подметаем брошенные прошлыми прерванными установками (рестарт
    процесса посреди загрузки) старше часа."""
    import tempfile
    now = time.time()
    for old in parent.glob(prefix + "*"):
        try:
            if now - old.lstat().st_mtime > _STALE_AGE:
                _drop(old)
        except OSError:
            pass
    return tempfile.mkdtemp(prefix=prefix, dir=str(parent))


def _install_codex_package(entry: dict, cli_dir: Path, ctx: _Ctx) -> str:
    """Пакет GitHub-релиза Codex → <dir>/codex-<v>-<rnd>/, симлинк <dir>/codex
    атомарно на bin/codex; при сбое — симлинк на прежнюю цель."""
    asset = asset_for("codex", entry)
    if asset is None:
        raise InstallError(f"no codex build for platform {platform_key()}")
    cli_dir.mkdir(mode=0o755, parents=True, exist_ok=True)
    ver = entry["version"]
    work = Path(_mkdtemp(cli_dir, ".codex-dl-"))
    final: Path | None = None
    try:
        arc = work / "pkg.tar.gz"
        digests = _download(asset["url"], arc, ctx)
        _check_hash("codex", digests, asset)
        root = work / "pkg"
        _safe_extract(arc, root, ctx)
        _drop(arc)
        exe = root / "bin" / "codex"
        if not exe.is_file() or exe.is_symlink():
            raise InstallError("codex package has no bin/codex")
        os.chmod(exe, 0o755)
        _expect_version("codex", str(exe), ver, ctx)
        final = cli_dir / f"codex-{ver}-{secrets.token_hex(3)}"
        os.rename(root, final)
        link = cli_dir / "codex"
        prev = os.readlink(link) if link.is_symlink() else None
        tmp_link = cli_dir / f".codex-link-{secrets.token_hex(3)}"
        os.symlink(f"{final.name}/bin/codex", tmp_link)
        bak = None
        if os.path.lexists(link) and prev is None:      # обычный файл на месте ссылки
            bak = _swap_file(link, tmp_link)
        else:
            os.replace(tmp_link, link)
        try:
            got = _expect_version("codex", str(link), ver, ctx)
        except InstallError:
            if prev is not None:
                t = cli_dir / f".codex-link-{secrets.token_hex(3)}"
                os.symlink(prev, t)
                os.replace(t, link)
            else:
                _restore_file(link, bak)
            raise
        _drop(bak)
        keep = {final.name, Path(prev).parts[0] if prev else ""}
        for old in cli_dir.glob("codex-*"):          # прежние версии, кроме отката
            if old.is_dir() and old.name not in keep:
                _drop(old)
        final = None
        return got
    finally:
        _drop(work)
        if final is not None:
            _drop(final)


def _npm_for(binary: str) -> str | None:
    cand = Path(binary).parent / "npm"
    if cand.is_file() and os.access(cand, os.X_OK):
        return str(cand)
    return shutil.which("npm")


def _npm_install(binary: str, ver: str, ctx: _Ctx) -> None:
    npm = _npm_for(binary)
    if npm is None:
        raise InstallError("npm not found next to codex")
    code, out = _run([npm, "install", "-g", "--no-fund", "--no-audit",
                      f"@openai/codex@{ver}"],
                     timeout=ctx.left(_NPM_TIMEOUT), env=_tool_env("codex", npm))
    if code != 0:
        raise InstallError(f"npm install @openai/codex@{ver}: {_last_line(out)}")


def _grok_update(binary: str, ver: str, ctx: _Ctx) -> None:
    """Встроенный установщик grok. `--version X` ЗАКРЕПЛЯЕТ версию: grok сам
    пишет `[cli] auto_update = false` в ~/.grok/config.toml. Поэтому при
    включённом самообновлении (HEDGEHOG_CLI_AUTO_UPDATE=1, пин = минимум) зовём
    `grok update` без версии — ставит последнюю (≥ пина) и не выключает
    самообновление; точная версия — только при выключенном."""
    pin = not cli_registry.cli_auto_update()
    argv = [binary, "update", "--version", ver] if pin else [binary, "update"]
    code, out = _run(argv, timeout=ctx.left(_GROK_UPDATE_TIMEOUT),
                     env=_tool_env("grok", binary))
    if code != 0:
        raise InstallError(f"grok {' '.join(argv[1:])}: {_last_line(out)}")
    _relink_grok(binary)


def _grok_home_bin() -> Path:
    return Path.home() / ".grok" / "bin" / "grok"


def _relink_grok(binary: str) -> None:
    """`grok update` кладёт новую версию в ~/.grok/downloads/grok-<v>-… и
    переводит ~/.grok/bin/grok; наша ссылка (напр. /opt/grok/bin/grok) могла
    смотреть прямо на старый файл. Перенаправляем её на ~/.grok/bin/grok —
    тогда и последующие самообновления grok подхватываются. Обычный файл
    (не ссылку) не трогаем."""
    home = _grok_home_bin()
    link = Path(binary)
    if not link.is_symlink() or not home.exists():
        return
    if link.absolute() == home.absolute():
        return
    if os.path.realpath(link) == os.path.realpath(home):
        return
    tmp = link.parent / f".grok-link-{secrets.token_hex(3)}"
    try:
        os.symlink(str(home), tmp)
        os.replace(tmp, link)
    except OSError as e:      # чужой каталог без прав — сам апдейт уже успешен
        log.warning("cli_install.grok_relink_failed", link=str(link), err=repr(e))
        try:
            os.unlink(tmp)
        except OSError:
            pass
        return
    log.info("cli_install.grok_relinked", link=str(link), target=str(home))


def _last_line(out: str) -> str:
    lines = [ln.strip() for ln in (out or "").splitlines() if ln.strip()]
    errs = [ln for ln in lines if "err" in ln.lower()]
    return (errs or lines or ["no output"])[-1][:300]


def _in_managed(binary: str) -> bool:
    d = cli_registry.managed_cli_dir()
    if d is None:
        return False
    try:
        Path(binary).absolute().relative_to(d.absolute())
        return True
    except ValueError:
        return False


def install_method(cli: str, binary: str) -> str | None:
    """Как поставлен существующий бинарь: npm | managed | grok-update | file;
    None — раскладка, которую Ёжик не обновляет."""
    if cli == "codex":
        real = os.path.realpath(binary).replace("\\", "/")
        if "/node_modules/@openai/codex/" in real:
            return "npm"
        if _in_managed(binary):
            return "managed"
        return None
    if cli == "grok":
        return "managed" if _in_managed(binary) else "grok-update"
    if cli == "antigravity":
        return "file"
    return None


def _do_update(cli: str, entry: dict, binary: str, before: str | None,
               ctx: _Ctx) -> str:
    """Обновить существующую установку тем же способом. → установленная версия."""
    ver = entry["version"]
    method = install_method(cli, binary)
    if method is None:
        raise InstallError(f"unsupported {cli} install layout: {binary}")
    if method == "managed" and cli == "codex":
        return _install_codex_package(entry, Path(binary).parent, ctx)
    if method in ("managed", "file"):
        return _install_file(cli, entry, Path(os.path.realpath(binary)), ctx)
    # npm / grok-update: внешний установщик; откат — им же на прежнюю версию
    run_install = _npm_install if method == "npm" else _grok_update
    # grok при самообновлении ставит последнюю версию: пин — минимум.
    minimum = method == "grok-update" and cli_registry.cli_auto_update()
    try:
        run_install(binary, ver, ctx)
        if minimum:
            got = _version_of(cli, binary, ctx)
            if got is None or compare_versions(got, ver) < 0:
                raise InstallError(
                    f"{cli} --version reports {got}, expected >= {ver}")
            return got
        return _expect_version(cli, binary, ver, ctx)
    except InstallError:
        if before and not minimum:   # откат `--version` закрепил бы версию grok'а
            rb = _Ctx(_ROLLBACK_TIMEOUT, None)   # откат — свой бюджет, не общий
            try:
                run_install(binary, before, rb)
            except InstallError as e2:
                log.error("cli_install.rollback_failed", cli=cli, err=str(e2))
        raise


# ------------------------------------------------------------ публичный API ----

def _result(before, pinned) -> dict:
    return {"before": before, "after": before, "pinned": pinned,
            "updated": False, "error": None}


def update(cli: str, entry: dict, binary: str | None = None, *,
           timeout: float = INSTALL_TIMEOUT,
           cancel: threading.Event | None = None) -> dict:
    """Привести существующую установку к entry["version"]. Не бросает."""
    binary = binary or cli_registry.find_binary(cli)
    pinned = entry["version"]
    if binary is None:
        return {**_result(None, pinned), "error": "not installed"}
    ctx = _Ctx(timeout, cancel)
    before = _version_of(cli, binary, ctx)
    res = _result(before, pinned)
    try:
        res["after"] = _do_update(cli, entry, binary, before, ctx)
        res["updated"] = True
        log.info("cli_install.updated", cli=cli, before=before, after=res["after"])
    except (InstallError, OSError) as e:
        # OSError: каталог бинаря без прав записи / ENOSPC — ошибка этого CLI,
        # а не всего ensure_pins (остальные CLI обрабатываются дальше).
        res["error"] = str(e)[:300]
        res["after"] = installed_version(cli, binary)
        log.warning("cli_install.update_failed", cli=cli, err=res["error"])
    return res


def install(cli: str, entry: dict, *, timeout: float = INSTALL_TIMEOUT,
            cancel: threading.Event | None = None,
            cli_dir: Path | None = None) -> dict:
    """Чистая установка ровно entry["version"] в управляемый каталог. Не бросает.
    → {"ok","version","binary","error"}."""
    cli_dir = cli_dir or cli_registry.managed_cli_dir()
    out = {"ok": False, "version": None, "binary": None, "error": None}
    if cli_dir is None:
        out["error"] = "managed CLI directory is not configured"
        return out
    spec = cli_registry.spec_for(cli)
    if cli not in INSTALLABLE or spec is None or not spec.binary:
        out["error"] = f"{cli} cannot be installed"
        return out
    ctx = _Ctx(timeout, cancel)
    try:
        if cli == "codex":
            got = _install_codex_package(entry, cli_dir, ctx)
        else:
            got = _install_file(cli, entry, cli_dir / spec.binary, ctx)
        out.update(ok=True, version=got, binary=str(cli_dir / spec.binary))
        log.info("cli_install.installed", cli=cli, version=got, dir=str(cli_dir))
    except (InstallError, OSError) as e:
        out["error"] = str(e)[:300]
        log.warning("cli_install.install_failed", cli=cli, err=out["error"])
    return out


def ensure_installed(cli: str, *, timeout: float = INSTALL_TIMEOUT,
                     cancel: threading.Event | None = None) -> dict:
    """Сервер (set_cli/create_chat на отсутствующий CLI): поставить пин, если
    бинаря нет. {"ok", "version", "binary", "error"}."""
    binary = cli_registry.find_binary(cli)
    if binary is not None:
        return {"ok": True, "version": None, "binary": binary, "error": None}
    entry = read_pins().get(cli)
    if entry is None:
        return {"ok": False, "version": None, "binary": None,
                "error": f"no pinned version for {cli}"}
    return install(cli, entry, timeout=timeout, cancel=cancel)


def needs_update(installed: str | None, pinned: str, auto_update: bool) -> bool:
    """Политика: auto_update — пин МИНИМУМ (только installed < pin);
    иначе — ТОЧНЫЙ (любое расхождение, и вниз)."""
    if installed is None:
        return False          # версию не разобрать — не трогаем (ошибка в отчёте)
    c = compare_versions(installed, pinned)
    return c < 0 if auto_update else c != 0


def ensure_pins(deadline: float | None = None, pkg_dir: Path | None = None,
                auto_update: bool | None = None) -> dict[str, dict]:
    """update_self: для УСТАНОВЛЕННЫХ CLI с записью в compat — привести к пину
    по политике (минимум/точно). Отсутствующие не ставим. Общий бюджет deadline.
    → {cli: {"before","after","pinned","updated","error"}}. Не бросает."""
    auto = cli_registry.cli_auto_update() if auto_update is None else auto_update
    out: dict[str, dict] = {}
    for cli, entry in read_pins(pkg_dir).items():
        binary = cli_registry.find_binary(cli)
        if binary is None:
            continue
        left = INSTALL_TIMEOUT if deadline is None else deadline - time.monotonic()
        before = installed_version(cli, binary,
                                   timeout=max(1.0, min(_VERSION_TIMEOUT, left)))
        res = _result(before, entry["version"])
        if before is None:
            res["error"] = "cannot determine installed version"
        elif needs_update(before, entry["version"], auto):
            left = INSTALL_TIMEOUT if deadline is None else deadline - time.monotonic()
            if left <= 5:
                res["error"] = "budget exhausted"
            else:
                res = update(cli, entry, binary, timeout=min(INSTALL_TIMEOUT, left))
        out[cli] = res
    return out


# ----------------------------------------- барьер сессий: установка в полёте ----

_pending: dict[str, asyncio.Task] = {}


def track(cli: str, task: asyncio.Task) -> None:
    """Сервер регистрирует фоновую установку CLI — сессии ждут её до запуска."""
    _pending[cli] = task
    task.add_done_callback(lambda t, c=cli: _pending.pop(c, None)
                           if _pending.get(c) is t else None)


def is_pending(cli: str) -> bool:
    t = _pending.get(cli)
    return t is not None and not t.done()


async def wait_pending(cli: str, timeout: float = INSTALL_TIMEOUT + 60) -> None:
    """Дождаться идущей установки CLI (если есть, в этом же цикле событий)."""
    t = _pending.get(cli)
    if t is None or t.done():
        return
    try:
        if t.get_loop() is not asyncio.get_running_loop():
            return
    except RuntimeError:
        return
    try:
        await asyncio.wait_for(asyncio.shield(t), timeout)
    except asyncio.CancelledError:
        if t.cancelled():
            return              # отменили установку (shutdown), а не нас
        raise
    except Exception:  # noqa: BLE001 — таймаут/сбой установки: дальше — CLI_UNAVAILABLE
        return
