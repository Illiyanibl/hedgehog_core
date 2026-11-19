"""§multi-cli (§21): авторизация Grok Build CLI (xAI) на сервере.

`grok login --device-auth` — вход по коду устройства: CLI печатает ссылку
(https://accounts.x.ai/oauth2/device?user_code=XXXX-XXXX) и код; пользователь
открывает ссылку в любом браузере и подтверждает код. Обратно в Ёжик ничего
слать не нужно: процесс сам завершается кодом 0 и сохраняет токен в
`~/.grok/auth.json`. Интерфейс как у `CodexAuthManager`; фреймы — `auth_link
{url, userCode}` и `auth_result` (с `cliType: "grok"`).

В отличие от `codex login`, `grok login` НЕ стирает действующий вход до успеха
(проверено на 1.0.77), но автозапуск при ложной ошибке авторизации всё равно
не стартует поверх живого токена (как у Codex): сначала явный logout.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import structlog

from ..i18n import Msg
from .auth_flow import ANSI_RE, URL_RE, SubprocessAuthFlow

log = structlog.get_logger("grok_auth")

CLI_TYPE = "grok"

_ANSI_RE, _URL_RE = ANSI_RE, URL_RE
_CODE_RE = re.compile(r"^[A-Z0-9]{4}-[A-Z0-9]{4,8}$")
_LOGIN_HOSTS = ("x.ai", "grok.com")


# Управляемый GROK_HOME Ёжика (data_dir/grok-home): отдельный конфиг с правилами
# прав (ask на все MCP, deny на секреты), свой auth.json и сессии — не трогает
# личный ~/.grok пользователя сервера. Задаётся сервером при старте.
_managed_home: Path | None = None
_protect_paths: list[str] = []


_config = None        # Config сервера: из него читаем активный способ входа (API-ключ/шлюз)


def configure_managed_home(home: Path | None, protect: list[str] | None = None,
                           config=None) -> None:
    global _managed_home, _protect_paths, _config
    _managed_home = home
    _protect_paths = list(protect or [])
    _config = config


def alt_record() -> dict:
    """Активный нестандартный способ Grok ({} — подписка): {method: api_key|gateway,
    api_key, base_url, models, active_id, api_backend}."""
    if _config is None:
        return {}
    from . import auth_store
    rec = auth_store.load(_config, CLI_TYPE)
    if rec.get("method") in (auth_store.API_KEY, auth_store.GATEWAY) and rec.get("api_key"):
        return rec
    return {}


def managed_home() -> Path | None:
    return _managed_home


def alt_home() -> Path | None:
    """GROK_HOME для режимов ключа/шлюза: БЕЗ auth.json подписки. Иначе Grok
    ходит на cli-chat-proxy.grok.com по токену подписки (проверено вживую:
    XAI_API_KEY и auth.preferred_method её не отключают) и промпты уходят xAI
    мимо шлюза."""
    return _managed_home.with_name(_managed_home.name + "-alt") if _managed_home else None


def apply_alt(rec: dict) -> None:
    """Побочные эффекты режима ключа/шлюза. rec={} — режим снят: сносим альт-каталог
    (config.toml с ключом шлюза и сессии). Кэш каталога моделей Grok сбрасываем
    всегда: список зависит от режима."""
    from . import auth_store
    from . import grok_rpc
    home = alt_home()
    if not rec and home is not None:
        auth_store.rmtree_logged(home)
    grok_rpc._cache.update(ts=0.0, stamp=None, data=None)


def protected_paths() -> list[str]:
    return list(_protect_paths)


def grok_home() -> Path:
    """GROK_HOME: явный env > управляемый каталог Ёжика > ~/.grok."""
    return Path(os.environ.get("GROK_HOME") or _managed_home
                or (Path.home() / ".grok"))


def token_path() -> Path:
    """Файл учётных данных Grok (env HEDGEHOG_GROK_TOKEN переопределяет)."""
    override = os.environ.get("HEDGEHOG_GROK_TOKEN")
    return Path(override) if override else grok_home() / "auth.json"


def is_logged_in() -> bool:
    p = token_path()
    try:
        if not p.is_file() or p.stat().st_size == 0:
            return False
        data = json.loads(p.read_text("utf-8"))
    except (OSError, ValueError):
        return False
    return isinstance(data, dict) and bool(data)


def logout() -> bool:
    """Удалить учётные данные (разлогин). True — файл был."""
    p = token_path()
    try:
        existed = p.exists()
        p.unlink(missing_ok=True)
        return existed
    except OSError as e:
        log.warning("grok_auth.logout_failed", err=str(e))
        return False


def _is_login_url(url: str) -> bool:
    """Только https и хост x.ai/grok.com (или поддомен) — точное сравнение хоста,
    не подстрока (защита от подсунутой в вывод чужой ссылки)."""
    try:
        u = urlsplit(url)
        host = (u.hostname or "").lower()
    except ValueError:
        return False
    return u.scheme == "https" and any(
        host == h or host.endswith("." + h) for h in _LOGIN_HOSTS)


def parse_device_login(text: str) -> tuple[str | None, str | None]:
    """Из вывода `grok login --device-auth`: (ссылка, одноразовый код). Код — из
    query `user_code` ссылки, иначе отдельной строкой XXXX-XXXX."""
    url = code = None
    for line in _ANSI_RE.sub("", text).splitlines():
        line = line.strip()
        if url is None:
            m = _URL_RE.search(line)
            if m and _is_login_url(m.group(0)):
                url = m.group(0)
                uc = parse_qs(urlsplit(url).query).get("user_code")
                if uc and _CODE_RE.match(uc[0]):
                    code = uc[0]
                continue
        if code is None and _CODE_RE.match(line):
            code = line
    return url, code


class GrokAuthManager(SubprocessAuthFlow):
    CLI = CLI_TYPE
    TAG = "grok-auth"
    needs_code = False        # код подтверждается на сайте, а не присылается в Ёжик

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self._link: dict | None = None

    def default_argv(self, binary: str) -> list[str]:
        return [binary, "login", "--device-auth"]

    def _spawn_extra_env(self) -> dict[str, str]:
        from . import grok_rpc
        return grok_rpc.grok_extra_env(for_login=True)

    def _reset(self) -> None:
        self._link, self._tail = None, []

    async def start(self) -> None:
        if self.running:
            if self._link:
                await self._broadcast("auth_link", {
                    **self._link, "already_running": True})
            return
        if is_logged_in():
            # H1: ok:false — входа не было; клиент покажет подсказку «выйдите и
            # войдите заново», сервер НЕ перезапускает сессии CLI
            await self._broadcast("auth_result", {
                "ok": False, "already_logged_in": True,
                "error": Msg("auth.already_logged_in")})
            return
        self._task = asyncio.create_task(self._flow(), name="grok-auth")

    async def submit_code(self, code: str) -> bool:
        return False

    async def _pump(self) -> None:
        assert self._proc is not None and self._proc.stdout is not None
        seen = ""
        async for raw in self._proc.stdout:
            line = _ANSI_RE.sub("", raw.decode(errors="replace")).rstrip()
            self._note(line)
            seen += line + "\n"
            if self._link is None:
                url, code = parse_device_login(seen)
                if url and code:
                    self._link = {"url": url, "userCode": code}
                    await self._broadcast("auth_link", dict(self._link))
        rc = await self._proc.wait()
        if rc == 0 and is_logged_in():
            log.info("grok_auth.ok")
            await self._broadcast("auth_result", {"ok": True})
        else:
            await self._broadcast("auth_result", {
                "ok": False,
                "error": f"grok login failed (exit {rc}): "
                         + " | ".join(self._tail[-3:])[:300]})
