"""§push: клиентская сторона APNs-релея на Ёžike.

Ёžik сам в APNs не ходит. При агентском `notify` с ОФФЛАЙН-клиентом (нет
активных WS-соединений) Ёžik просит релей push.hedgehog.devolution.dev отправить пуш на
устройства, чьи notifyKey он запомнил (фрейм register_push). accountId (секрет
регистрации) Ёžik'у не выдаётся — только notifyKey (секрет отправки).
"""
from __future__ import annotations

import hashlib
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


def _ordered(relay_urls: list[str], notify_key: str) -> list[str]:
    """Порядок обхода связки для устройства: ротируем список по стабильному
    хешу notify_key (hashlib, не встроенный hash — тот солёный per-process).
    Даёт «домашний» релей на устройство + равномерное распределение нагрузки."""
    urls = [u for u in relay_urls if u]
    if len(urls) <= 1:
        return urls
    h = int(hashlib.sha256(notify_key.encode()).hexdigest(), 16)
    i = h % len(urls)
    return urls[i:] + urls[:i]


async def send(relay_urls: list[str], notify_key: str, title: str, body: str,
               chat_id: str | None = None) -> bool:
    """Fire-and-forget с FAILOVER по связке релеев. Идём по списку (ротирован по
    notify_key), пока какой-то не отправит. Правила перехода к следующему:
      • sent:true            → успех, стоп (True);
      • reason == "quota"    → лимит юзера, стоп (False) — не обходим квоту
        (ПРИМ.: квота у каждого релея своя (per-node sqlite) — при падении
        домашнего релея failover на соседа даёт СВОЮ квоту, т.е. в окне отказа
        суточный лимит эффективно множится до ~N×. Устранимо только общим
        состоянием — вне scope; для best-effort пуша приемлемо);
      • apns_status == 410   → токен мёртв (Unregistered) — на всех релеях он
        одинаков (клиент регает один apnsToken всем), перебор бессмыслен → стоп;
      • unregistered(row miss)/sent:false, не-2xx, таймаут, ошибка → следующий.
    Ошибки не пробрасываем (пуш не должен ломать основной notify-путь)."""
    payload: dict[str, str] = {
        "notifyKey": notify_key, "title": title, "body": body,
    }
    if chat_id:
        payload["chatId"] = chat_id
    timeout = aiohttp.ClientTimeout(total=10)
    for base in _ordered(relay_urls, notify_key):
        url = base.rstrip("/") + "/v1/notify"
        try:
            async with aiohttp.ClientSession(timeout=timeout) as s:
                async with s.post(url, json=payload) as r:
                    data = {}
                    try:
                        data = await r.json(content_type=None)
                    except Exception:  # noqa: BLE001
                        data = {}
                    if r.status == 200 and data.get("sent"):
                        log.info("push.sent", url=base)
                        return True
                    reason = str(data.get("reason", "")) if isinstance(data, dict) else ""
                    if reason == "quota":
                        log.info("push.quota", url=base)
                        return False
                    if isinstance(data, dict) and data.get("apns_status") == 410:
                        # Мёртвый токен (Unregistered) — идентичен на всех релеях.
                        log.info("push.token_dead", url=base)
                        return False
                    log.info("push.relay_skip", url=base, status=r.status,
                             reason=reason)
        except Exception as e:  # noqa: BLE001 — сеть/таймаут → следующий релей
            log.warning("push.relay_failed", url=base, err=str(e))
    log.warning("push.all_relays_failed", key=notify_key[-6:])
    return False
