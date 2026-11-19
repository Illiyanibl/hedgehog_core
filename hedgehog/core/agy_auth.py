"""§multi-cli (§18.7): авторизация Antigravity CLI на сервере (Google OAuth).

`agy acp --login` — вход «из терминала без браузера»: печатает ссылку, ждёт код
(или полный URL страницы) со stdin, по успеху сохраняет токен у самого `agy` и
завершается кодом 0. PTY не нужен — обычные каналы. Интерфейс как у
`AuthManager` (Claude): `running`, `start()`, `submit_code()`, `stop()`;
фреймы `auth_link` / `auth_result` уходят через переданный broadcast (с
`cliType: "antigravity"`). Один флоу одновременно; повторный `start()` пере-шлёт
ссылку (`already_running`).
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

import structlog

from ..i18n import Msg
from .auth_flow import ANSI_RE, URL_RE, SubprocessAuthFlow

log = structlog.get_logger("agy_auth")

CLI_TYPE = "antigravity"

_ANSI_RE, _URL_RE = ANSI_RE, URL_RE


# Режимы API-ключа/шлюза (Gemini API) — отдельный «домашний» каталог
# <data_dir>/agy-home-alt с settings.json {"modelProvider": "gemini"}; ключ — в
# env GEMINI_API_KEY (agy читает только его), свой endpoint — GOOGLE_GEMINI_BASE_URL.
# Личные настройки ~/.gemini/antigravity-cli и вход Google не затрагиваются.
_config = None


def configure(config) -> None:
    global _config
    _config = config


def alt_record() -> dict:
    """Активный нестандартный способ Antigravity ({} — вход Google)."""
    if _config is None:
        return {}
    from . import auth_store
    rec = auth_store.load(_config, CLI_TYPE)
    if rec.get("method") in (auth_store.API_KEY, auth_store.GATEWAY) and rec.get("api_key"):
        return rec
    return {}


def alt_home() -> Path | None:
    return _config.data_dir / "agy-home-alt" if _config is not None else None


def prepare_alt_home() -> Path | None:
    home = alt_home()
    if home is None or not alt_record():
        return None
    cli_dir = home / ".gemini" / "antigravity-cli"
    cli_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(home, 0o700)
    settings = cli_dir / "settings.json"
    want = '{"modelProvider": "gemini"}\n'
    try:
        if not settings.exists() or settings.read_text("utf-8") != want:
            settings.write_text(want, "utf-8")
    except OSError as e:
        log.warning("agy_auth.alt_settings_failed", err=str(e))
    return home


def agy_extra_env(*, with_home: bool = False) -> dict[str, str]:
    """env процессов agy в режиме ключа/шлюза. with_home — подменить HOME (нужно
    `agy models`, у которого нет --gemini-dir; сессии ACP HOME не трогаем:
    агент выполняет команды пользователя)."""
    rec = alt_record()
    home = prepare_alt_home()
    if home is None:
        return {}
    env = {"GEMINI_API_KEY": rec["api_key"]}
    if rec.get("base_url"):
        env["GOOGLE_GEMINI_BASE_URL"] = rec["base_url"]
    if with_home:
        env["HOME"] = str(home)
    return env


def agy_server_args() -> list[str]:
    """Доп. аргументы `agy acp` в режиме ключа/шлюза."""
    home = prepare_alt_home()
    return ["--gemini-dir", str(home / ".gemini")] if home is not None else []


def apply_alt(rec: dict) -> None:
    """rec={} — снести альт-каталог (выход из режима ключа/шлюза)."""
    from . import auth_store
    home = alt_home()
    if home is None:
        return
    if rec:
        prepare_alt_home()
    else:
        auth_store.rmtree_logged(home)


def token_path() -> Path:
    """Файл OAuth-токена `agy` (env HEDGEHOG_AGY_TOKEN переопределяет)."""
    override = os.environ.get("HEDGEHOG_AGY_TOKEN")
    if override:
        return Path(override)
    return Path.home() / ".gemini" / "antigravity-cli" / "antigravity-oauth-token"


def is_logged_in() -> bool:
    p = token_path()
    try:
        return p.is_file() and p.stat().st_size > 0
    except OSError:
        return False


def logout() -> bool:
    """Удалить токен (разлогин). True — файл был."""
    p = token_path()
    try:
        existed = p.exists()
        p.unlink(missing_ok=True)
        return existed
    except OSError as e:
        log.warning("agy_auth.logout_failed", err=str(e))
        return False


_LOGIN_HOSTS = frozenset({"accounts.google.com"})


def _is_login_url(url: str) -> bool:
    """Только https и ТОЧНЫЙ хост Google-входа (не подстрока: иначе
    https://evil.example/?x=accounts.google.com прошла бы клиенту как ссылка)."""
    from urllib.parse import urlsplit
    try:
        u = urlsplit(url)
        return u.scheme == "https" and (u.hostname or "").lower() in _LOGIN_HOSTS
    except ValueError:
        return False


def extract_login_url(text: str) -> str | None:
    """Первая ссылка входа (https://accounts.google.com/…) из вывода `agy`."""
    for line in _ANSI_RE.sub("", text).splitlines():
        m = _URL_RE.search(line.strip())
        if m and _is_login_url(m.group(0)):
            return m.group(0)
    return None


class AgyAuthManager(SubprocessAuthFlow):
    CLI = CLI_TYPE
    TAG = "agy-auth"
    STDIN = asyncio.subprocess.PIPE           # код подтверждения шлём в stdin

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self._url: str | None = None
        self._code_sent = False

    def default_argv(self, binary: str) -> list[str]:
        return [binary, "acp", "--login"]

    def _reset(self) -> None:
        self._url, self._code_sent, self._tail = None, False, []

    async def start(self) -> None:
        if self.running:
            if self._url:
                await self._broadcast("auth_link", {
                    "url": self._url, "already_running": True})
            return
        self._task = asyncio.create_task(self._flow(), name="agy-auth")

    async def submit_code(self, code: str) -> bool:
        proc = self._proc
        if not self.running or proc is None or proc.stdin is None:
            return False
        code = code.strip()
        if not code or any(c in code for c in "\r\n\x00"):
            return False             # код — одна строка; иначе в stdin ушли бы лишние
        try:
            proc.stdin.write(code.encode() + b"\n")
            await proc.stdin.drain()
        except (OSError, ConnectionError) as e:
            log.warning("agy_auth.code_write_failed", err=str(e))
            return False
        self._code_sent = True
        return True

    async def _pump(self) -> None:
        assert self._proc is not None and self._proc.stdout is not None
        async for raw in self._proc.stdout:
            line = _ANSI_RE.sub("", raw.decode(errors="replace")).rstrip()
            self._note(line)
            url = extract_login_url(line)
            if url and url != self._url:
                if self._code_sent:      # код не принят → CLI выдал новую ссылку
                    self._code_sent = False
                    await self._broadcast("auth_result", {
                        "ok": False, "retry": True,
                        "error": Msg("auth.code_rejected",
                                     detail=" ".join(self._tail[-3:-1])[:200])})
                self._url = url
                await self._broadcast("auth_link", {"url": url})
        code = await self._proc.wait()
        if code == 0 and is_logged_in():
            log.info("agy_auth.ok")
            await self._broadcast("auth_result", {"ok": True})
        else:
            await self._broadcast("auth_result", {
                "ok": False,
                "error": f"agy login failed (exit {code}): "
                         + " | ".join(self._tail[-3:])[:300]})
