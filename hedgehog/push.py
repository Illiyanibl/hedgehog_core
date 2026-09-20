"""§push: клиентская сторона APNs-релея на Ёžike.

Ёžik сам в APNs не ходит. При агентском `notify` с ОФФЛАЙН-клиентом (нет
активных WS-соединений) Ёžik просит релей push.hedgehog.devolution.dev отправить пуш на
устройства, чьи notifyKey он запомнил (фрейм register_push). accountId (секрет
регистрации) Ёžik'у не выдаётся — только notifyKey (секрет отправки).
"""
from __future__ import annotations

import json
import time
from pathlib import Path

import aiohttp
import structlog

log = structlog.get_logger("push")

# Забываем устройства, не подключавшиеся дольше этого срока (не пушим на мёртвые).
KEY_TTL = 30 * 86400
# Потолок числа устройств на один Ёžik: защита от разрастания (реинсталлы дают
# новые UUID, битый клиент мог бы зациклить register_push). Держим самые свежие.
MAX_KEYS = 20


class PushKeys:
    """Персистентный набор notifyKey → last_seen (переживает отключение клиента)."""

    def __init__(self, path: Path):
        self._path = path
        self._keys: dict[str, float] = {}
        self._load()

    def _load(self) -> None:
        try:
            data = json.loads(self._path.read_text())
            if isinstance(data, dict):
                self._keys = {str(k): float(v) for k, v in data.items()}
        except (OSError, ValueError, TypeError):
            # Битый/чужой формат (в т.ч. float(None) → TypeError) не должен
            # ронять старт сервера — просто начинаем с пустого набора.
            self._keys = {}

    def _save(self) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            # Атомарно: tmp + replace — обрыв на середине не обнулит файл.
            tmp = self._path.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(self._keys))
            tmp.replace(self._path)
        except OSError as e:
            log.warning("push.keys_save_failed", err=str(e))

    def _prune(self) -> None:
        cutoff = time.time() - KEY_TTL
        self._keys = {k: t for k, t in self._keys.items() if t >= cutoff}
        # Кап: если после отсева всё равно больше потолка — оставляем хвост dict
        # (самые недавно перезаписанные — remember двигает ключ в конец).
        if len(self._keys) > MAX_KEYS:
            tail = list(self._keys.items())[-MAX_KEYS:]
            self._keys = dict(tail)

    def remember(self, notify_key: str) -> None:
        if not notify_key:
            return
        # Переставляем ключ в хвост (метка «самый свежий»), обновляя last_seen.
        self._keys.pop(notify_key, None)
        self._keys[notify_key] = time.time()
        self._prune()
        self._save()

    def keys(self) -> list[str]:
        self._prune()
        return list(self._keys.keys())


async def send(relay_url: str, notify_key: str, title: str, body: str,
               chat_id: str | None = None) -> None:
    """Fire-and-forget: попросить релей отправить один пуш. Ошибки — в лог,
    не пробрасываем (пуш не должен ломать основной notify-путь)."""
    payload: dict[str, str] = {
        "notifyKey": notify_key, "title": title, "body": body,
    }
    if chat_id:
        payload["chatId"] = chat_id
    url = relay_url.rstrip("/") + "/v1/notify"
    try:
        timeout = aiohttp.ClientTimeout(total=10)
        async with aiohttp.ClientSession(timeout=timeout) as s:
            async with s.post(url, json=payload) as r:
                txt = (await r.text())[:120]
                log.info("push.sent", status=r.status, resp=txt)
    except Exception as e:  # noqa: BLE001 — сеть/таймаут не должны падать наверх
        log.warning("push.send_failed", err=str(e))
