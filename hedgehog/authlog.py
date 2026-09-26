"""Аудит неудачных Bearer-авторизаций — источник для fail2ban.

Каждую неудачную проверку токена (WS-порт и файл-сервер) пишем в отдельный
файл СТАБИЛЬНОГО формата `data/auth_failures.log`. Контейнер логирует в stdout
(docker logs), поэтому обычный лог fail2ban не прочитать; том /data виден с
хоста (`/var/lib/docker/volumes/hedgehog-data/_data/auth_failures.log`) —
jail банит IP оттуда, в цепочке DOCKER-USER.

Формат строки (одна на отказ):
    <iso-utc> auth-failed ip=<IP> svc=<ws|file> path=<path>

IP берём из TCP-пира (X-Forwarded-For НЕ доверяем: порты 8765/8767 торчат
напрямую, без доверенного прокси — заголовок подделываем кто угодно).
"""
from __future__ import annotations

import datetime as _dt
import ipaddress
import re
from pathlib import Path

import structlog

from .config import Config

log = structlog.get_logger("authlog")

_CAP = 5 * 1024 * 1024  # хвост файла ≤ ~5 МБ (защита от флуда)

# Всё вне печатного ASCII (в т.ч. ПРОБЕЛ 0x20 — разделитель полей формата,
# перевод строки, DEL, не-ASCII) percent-экранируем. Иначе aiohttp
# percent-ДЕкодит `request.path` → `%0a` становится реальным \n и позволяет
# НЕаутентифицированному клиенту вписать поддельную строку в fail2ban-лог
# (бан произвольного IP / порча jail-regex).
_UNSAFE_FIELD = re.compile(r"[^\x21-\x7e]")


def _clean_field(s: str) -> str:
    """Оставляем только печатный ASCII; всё прочее (пробел/\\n/управляющие/
    не-ASCII) и сам '%' → валидный UTF-8 percent-encoding. '%' кодируем тоже,
    чтобы кодирование было инъективным (литеральный `%0A` не спутать с \\n)."""
    out: list[str] = []
    for ch in s:
        if "\x21" <= ch <= "\x7e" and ch != "%":
            out.append(ch)
        else:
            out.extend(f"%{b:02X}" for b in ch.encode("utf-8"))
    return "".join(out)


def _clean_ip(ip: str) -> str:
    """Валидный IP → канонич. форма; иначе метка (в лог не пускаем мусор,
    который поле ip формата не должен содержать)."""
    if ip == "-":
        return "-"
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        return "invalid"


def record_failure(config: Config, ip: str | None, svc: str, path: str) -> None:
    """Зафиксировать неудачную авторизацию: в общий лог (видимость) + в
    стабильный файл для fail2ban. Ошибки IO глушим — аудит не критичен.

    ip/path/svc санитизируются: поле формата не должно содержать пробел/\\n
    (иначе лог-инъекция в fail2ban, см. _UNSAFE_FIELD)."""
    ip = _clean_ip((ip or "-").strip() or "-")
    path = _clean_field((path or "-")[:200])
    svc = _clean_field(svc or "-")
    log.warning("auth.failed", ip=ip, svc=svc, path=path)
    try:
        f = config.auth_log_file
        f.parent.mkdir(parents=True, exist_ok=True)
        with f.open("a", encoding="utf-8") as fh:
            fh.write(f"{_dt.datetime.now(_dt.timezone.utc).isoformat()} "
                     f"auth-failed ip={ip} svc={svc} path={path}\n")
        if f.stat().st_size > _CAP + _CAP // 10:
            _truncate(f, _CAP)
    except OSError:
        pass


def _truncate(path: Path, cap: int) -> None:
    """Оставить последние cap байт (по границе строки)."""
    try:
        with path.open("rb") as fh:
            fh.seek(-cap, 2)
            tail = fh.read()
        nl = tail.find(b"\n")
        if nl != -1:
            tail = tail[nl + 1:]
        tmp = path.with_suffix(".log.tmp")
        tmp.write_bytes(tail)
        tmp.replace(path)
    except OSError:
        pass
