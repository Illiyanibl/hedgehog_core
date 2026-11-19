"""Хранилище альтернативной авторизации по CLI (API-ключ / шлюз) и валидация
base_url (§auth). Один активный способ на CLI, общий для всех чатов сервера.

Файл `<data_dir>/auth.<cli>.json` (0600). У Claude прежнее имя `auth.json` и
прежний формат (`mode`: oauth|apikey|omniroute) — читаем через Config."""

from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import sys
from urllib.parse import urlsplit

import structlog

from ..config import Config, ensure_secure_dir, write_secret_file
from . import cli_registry

log = structlog.get_logger("auth_store")

# идентификаторы способов (cliStatus.authMethods[].id / activeMethod)
SUBSCRIPTION = "subscription"
API_KEY = "api_key"
GATEWAY = "gateway"

_CLAUDE_MODE = {"apikey": API_KEY, "omniroute": GATEWAY}
MAX_URL = 500


def _invalidate_secrets() -> None:
    from .secrets_redact import invalidate
    invalidate()


_CLI_NAME = re.compile(r"[a-z0-9_-]{1,32}")


def _path(config: Config, cli: str):
    # cliType приходит с клиента и попадает в имя файла — только безопасные символы
    if not isinstance(cli, str) or not _CLI_NAME.fullmatch(cli):
        raise ValueError(f"bad cli name {cli!r}")
    return config.data_dir / f"auth.{cli}.json"


def rmtree_logged(path) -> None:
    """Снести каталог; ошибки удаления — в лог (не молча): в каталоге мог лежать ключ."""
    if not os.path.lexists(path):
        return

    def _report(func, p, exc):
        e = exc[1] if isinstance(exc, tuple) else exc
        log.warning("alt_home.rmtree_failed", path=str(p), err=repr(e))
    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=lambda f, p, e: _report(f, p, e))
    else:
        shutil.rmtree(path, onerror=_report)


def load(config: Config, cli: str) -> dict:
    """Конфиг активного нестандартного способа CLI ({} — подписка)."""
    if cli == "claude":
        return config.load_auth_config()
    try:
        data = json.loads(_path(config, cli).read_text())
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def save(config: Config, cli: str, data: dict) -> None:
    if cli == "claude":
        config.save_auth_config(data)      # инвалидирует кэш секретов сам
        return
    ensure_secure_dir(config.data_dir)
    tmp = _path(config, cli).with_suffix(".json.tmp")
    write_secret_file(tmp, json.dumps(data, ensure_ascii=False))
    tmp.replace(_path(config, cli))
    _invalidate_secrets()


def clear(config: Config, cli: str) -> None:
    if cli == "claude":
        config.clear_auth_config()
        return
    try:
        _path(config, cli).unlink(missing_ok=True)
    except OSError:
        pass
    _invalidate_secrets()


def active_method(config: Config, cli: str) -> str:
    cfg = load(config, cli)
    if cli == "claude":
        return _CLAUDE_MODE.get(cfg.get("mode", "oauth"), SUBSCRIPTION)
    m = cfg.get("method")
    return m if m in (API_KEY, GATEWAY) and cfg.get("api_key") else SUBSCRIPTION


def detail(config: Config, cli: str) -> dict:
    """Несекретные подробности активного способа для клиента."""
    cfg = load(config, cli)
    out = {}
    if cfg.get("base_url"):
        out["base_url"] = cfg["base_url"]
    mid = cfg.get("active_id") or cfg.get("model")
    if mid:
        out["model"] = mid
    return out


def all_api_secrets(config: Config) -> list[str]:
    """Действующие ключи API всех CLI — для редакции секретов."""
    out = []
    for cli in cli_registry.CLI_SPECS:
        k = load(config, cli).get("api_key")
        if isinstance(k, str) and k:
            out.append(k)
    return out


# ---------- base_url ----------

def _internal_host(host: str) -> bool:
    """loopback / частные сети / имена без точки (docker-сервисы, localhost)."""
    if host in ("localhost",) or "." not in host and ":" not in host:
        return True
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return host.endswith((".local", ".internal", ".lan"))
    return ip.is_loopback or ip.is_private or ip.is_link_local


_METADATA_HOSTS = {"metadata.google.internal", "metadata", "instance-data"}
_METADATA_IPS = {ipaddress.ip_address("fd00:ec2::254")}


def _metadata_host(host: str) -> bool:
    """link-local (169.254/16, fe80::/10), облачные metadata-адреса: ключ и запрос
    пробы не должны уходить на сервис метаданных (SSRF к IAM-кредам)."""
    if host in _METADATA_HOSTS:
        return True
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_link_local or ip in _METADATA_IPS


def validate_base_url(url: str) -> str:
    """Нормализованный base_url или ValueError(i18n-ключ причины).
    https — везде; http — только для loopback/частных сетей/внутренних имён
    (ключ иначе ушёл бы открытым текстом); без userinfo/fragment/query."""
    if not isinstance(url, str) or not url.strip() or len(url) > MAX_URL:
        raise ValueError("auth.base_url_invalid")
    try:
        u = urlsplit(url.strip())
        host = (u.hostname or "").lower()
        _ = u.port
    except ValueError:
        raise ValueError("auth.base_url_invalid") from None
    if u.scheme not in ("http", "https") or not host or u.username or u.password \
            or u.fragment or u.query or _metadata_host(host):
        raise ValueError("auth.base_url_invalid")
    if u.scheme == "http" and not _internal_host(host) \
            and os.environ.get("HEDGEHOG_ALLOW_INSECURE_GATEWAY") != "1":
        raise ValueError("auth.base_url_insecure")
    return url.strip().rstrip("/")
