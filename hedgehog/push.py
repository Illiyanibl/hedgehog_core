"""§push: клиентская сторона APNs-релея на Ёžike.

Ёžik сам в APNs не ходит. При агентском `notify` Ёžik доставляет каждому
известному устройству ровно один раз: подписанным на этот чат — напрямую по WS,
а ОФФЛАЙН-устройствам (нет живого соединения на чат) просит релей
push.hedgehog.devolution.dev прислать APNs-пуш (по notifyKey, запомненному
фреймом register_push). Один Apple-аккаунт может иметь несколько устройств —
маршрутизация per-device по deviceId. accountId (секрет регистрации) Ёžik'у не
выдаётся — только notifyKey (секрет отправки).
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
    """Персистентно: deviceId → (notifyKey, last_seen). Один Apple-аккаунт может
    иметь НЕСКОЛЬКО устройств — храним каждое отдельно, чтобы пушить ровно тем,
    кто оффлайн. Перерегистрация устройства обновляет его notifyKey/last_seen.

    Устройства СТАРОГО клиента (без deviceId) кладём под синтетический ключ =
    сам notifyKey: он никогда не совпадёт с реальным deviceId живого соединения
    → такое устройство всегда считается оффлайн и пуш ему уходит (совместимость).
    """

    def __init__(self, path: Path):
        self._path = path
        # device_id -> {"notifyKey": str, "ts": float}
        self._devs: dict[str, dict] = {}
        self._load()

    def _load(self) -> None:
        try:
            data = json.loads(self._path.read_text())
        except (OSError, ValueError, TypeError):
            data = None
        out: dict[str, dict] = {}
        if isinstance(data, dict):
            for k, v in data.items():
                try:
                    if isinstance(v, dict) and v.get("notifyKey"):
                        # Новый формат: deviceId → {notifyKey, ts}.
                        out[str(k)] = {"notifyKey": str(v["notifyKey"]),
                                       "ts": float(v.get("ts") or 0)}
                    else:
                        # Старый формат {notifyKey: ts}: ключ И есть notifyKey,
                        # используем его же как синтетический deviceId.
                        out[str(k)] = {"notifyKey": str(k), "ts": float(v)}
                except (ValueError, TypeError):
                    continue  # битую запись пропускаем, старт не роняем
        self._devs = out

    def _save(self) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            # Атомарно: tmp + replace — обрыв на середине не обнулит файл.
            tmp = self._path.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(self._devs))
            tmp.replace(self._path)
        except OSError as e:
            log.warning("push.keys_save_failed", err=str(e))

    def _prune(self) -> None:
        cutoff = time.time() - KEY_TTL
        self._devs = {d: r for d, r in self._devs.items()
                      if r.get("ts", 0) >= cutoff}
        # Кап: если после отсева больше потолка — оставляем хвост dict (самые
        # недавно перезаписанные — remember двигает запись в конец).
        if len(self._devs) > MAX_KEYS:
            tail = list(self._devs.items())[-MAX_KEYS:]
            self._devs = dict(tail)

    def remember(self, notify_key: str, device_id: str = "") -> None:
        if not notify_key:
            return
        # Без deviceId (старый клиент) — синтетический ключ = notifyKey.
        dev = device_id or notify_key
        # Апгрейд клиента: раньше устройство регистрировалось БЕЗ deviceId
        # (синтетический ключ = notifyKey), теперь пришёл реальный deviceId с тем
        # же notifyKey — убираем старую синтетическую запись, иначе устройство
        # задвоится в реестре и получит пуш дважды (до KEY_TTL).
        if device_id and device_id != notify_key:
            self._devs.pop(notify_key, None)
        # Переставляем в хвост (метка «самый свежий»), обновляя last_seen.
        self._devs.pop(dev, None)
        self._devs[dev] = {"notifyKey": notify_key, "ts": time.time()}
        self._prune()
        self._save()

    def devices(self) -> list[tuple[str, str]]:
        """Список (deviceId, notifyKey) живых (не протухших) устройств."""
        self._prune()
        return [(d, r["notifyKey"]) for d, r in self._devs.items()]

    def keys(self) -> list[str]:
        """Только notifyKey'и (совместимость)."""
        self._prune()
        return [r["notifyKey"] for r in self._devs.values()]


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
