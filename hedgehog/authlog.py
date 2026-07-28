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
from pathlib import Path

import structlog

from .config import Config

log = structlog.get_logger("authlog")

_CAP = 5 * 1024 * 1024  # хвост файла ≤ ~5 МБ (защита от флуда)


def record_failure(config: Config, ip: str | None, svc: str, path: str) -> None:
    """Зафиксировать неудачную авторизацию: в общий лог (видимость) + в
    стабильный файл для fail2ban. Ошибки IO глушим — аудит не критичен."""
    ip = (ip or "-").strip() or "-"
    path = (path or "-")[:200]
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
