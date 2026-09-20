#!/usr/bin/env python3
"""§push: релей APNs для Ёžika (push.hedgehog.devolution.dev).

Единственное место, где живёт Apple-ключ .p8. Клиент регистрирует device-token,
Ёžik при агентском уведомлении и оффлайн-клиенте просит релей отправить пуш.

Раздельные секреты (радиус компрометации сервера ограничен):
  • accountId — знает ТОЛЬКО клиент; нужен для /register. Серверам НЕ выдаётся.
  • notifyKey — клиент выдаёт своим Ёžik-серверам; нужен для /notify.
Скомпрометированный сервер знает лишь notifyKey → максимум спам в пределах
квоты; НЕ может перерегистрировать/перехватить токен (нужен accountId).

Endpoints (за TLS Caddy, домен push.hedgehog.devolution.dev, штатный LE-серт — CA-валидация):
  POST /v1/register  {accountId, notifyKey, apnsToken, tier, env}
  POST /v1/notify    {notifyKey, title, body, chatId?}
  GET  /v1/health

APNs: HTTP/2, ES256-JWT (kid=Key ID, iss=Team ID), apns-topic=bundle id.
Хранилище: SQLite (WAL). Секрет — только .p8.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
from collections import deque
from datetime import datetime, timezone

import aiosqlite
import httpx
import jwt  # PyJWT
from aiohttp import web

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s push %(message)s")
log = logging.getLogger("push")

# --- конфиг (идентификаторы не секретны; секрет — только .p8) ----------------
KEY_PATH = os.environ.get("APNS_KEY_PATH", "/secrets/AuthKey.p8")
KEY_ID = os.environ.get("APNS_KEY_ID", "3D9RXCJ6FJ")
TEAM_ID = os.environ.get("APNS_TEAM_ID", "RW4MGD4RTB")
TOPIC = os.environ.get("APNS_TOPIC", "red.ecorp.DevolutionHedgehog")
DEFAULT_ENV = os.environ.get("APNS_DEFAULT_ENV", "sandbox")  # sandbox|production
DB_PATH = os.environ.get("PUSH_DB_PATH", "/data/push.db")
PORT = int(os.environ.get("PUSH_PORT", "8080"))

APNS_HOST = {
    "sandbox": "https://api.sandbox.push.apple.com",
    "production": "https://api.push.apple.com",
}

# MVP-квота: пушей в сутки на accountId по тиру подписки (тир — от клиента).
TIER_DAILY = {"free": 5, "lite": 30, "full": 200, "sponsor": 200}
DEFAULT_DAILY = 5

EXPIRATION_SECS = 6 * 3600   # apns-expiration: протухший пуш не прилетит сутки спустя

# §contract: защита от модифицированного/злого Ёžика (крутится у пользователя).
# Enforced ЗДЕСЬ (не доверяем клиенту). БАН (5 мин, пустой 429 без деталей) — за
# СТРУКТУРНОЕ злоупотребление: флуд (rate), битый JSON, битый формат id, тело
# >MAX_BODY. Длинный текст НЕ банится — ОБРЕЗАется. Квота (сверх лимита пуш не
# уходит) — анти-спам; rate-limit — анти-ддос. Бан in-memory на каждом релее.
MAX_TEXT = 512              # обрезка title/body (символы; payload APNs ≤ 4KB)
MAX_BODY = 8192            # raw-тело запроса (байты); больше → 413 → бан
BAN_SECS = 300            # бан за структурное нарушение, сек
# Раздельные лимиты: notify (Ёžик, выделенный IP — строже) vs register (телефон,
# может быть за CGNAT — мягче, иначе забаним общий NAT-IP офиса/оператора).
REQ_LIMIT_NOTIFY = 60      # notify-запросов с IP за окно
REQ_LIMIT_REGISTER = 120   # register-запросов с IP за окно (CGNAT-запас)
REQ_WINDOW = 60           # окно рейт-лимита, сек
STATE_SWEEP = 120         # период чистки bans/hits, сек
# TTL устройства: строка удаляется, если не обновлялась дольше (легит-устройство
# рефрешит `updated` на каждом запуске/tier-change). Иначе register случайными id
# копит devices без конца → disk-DoS. Согласовано с Ёžik KEY_TTL=30д.
DEVICE_TTL = 45 * 86400
_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,200}$")   # accountId/notifyKey
_TOKEN_RE = re.compile(r"^[a-fA-F0-9]{64}$")       # apnsToken — ровно 64 hex


def _iso(ts: float) -> str:
    """Стандартизированное время (ISO-8601 UTC, секундная точность)."""
    return datetime.fromtimestamp(int(ts), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _client_ip(request: web.Request) -> str:
    """Реальный IP Ёžика из X-Real-IP, который ВЫСТАВЛЯЕТ доверенный Caddy
    (header_up X-Real-IP {remote_host} — перезаписывает клиентское значение).
    Клиентский X-Forwarded-For НЕ доверяем (его можно подделать). Fallback —
    peername (Caddy) на случай прямого обращения."""
    rip = request.headers.get("X-Real-IP", "").strip()
    if rip:
        return rip
    peer = request.transport.get_extra_info("peername") if request.transport else None
    return peer[0] if peer else "?"


def _ban(app: web.Application, ip: str, now: float, why: str) -> None:
    app["bans"][ip] = now + BAN_SECS
    log.warning("ban ip=%s why=%s for=%ds", ip, why, BAN_SECS)


def _banned(app: web.Application, ip: str, now: float) -> bool:
    until = app["bans"].get(ip)
    if until is None:
        return False
    if now < until:
        return True
    app["bans"].pop(ip, None)   # бан истёк
    return False


def _rate_ok(app: web.Application, ip: str, now: float, limit: int) -> bool:
    dq = app["hits"].get(ip)
    if dq is None:
        dq = deque()
        app["hits"][ip] = dq
    cutoff = now - REQ_WINDOW
    while dq and dq[0] < cutoff:
        dq.popleft()
    dq.append(now)
    return len(dq) <= limit


def _drop(request: web.Request) -> web.Response:
    """Ответ на забаненный/нарушивший запрос: ПУСТОЙ 429, без тела и деталей.
    Раньше рвали TCP (transport.abort), но за reverse-proxy Caddy это даёт
    клиенту 502 и провоцирует РЕТРАИ upstream (двойная обработка). Пустой 429 —
    атакующему бесполезен (нет reason/retry/ban-инфо), без 502/ретраев/лог-спама."""
    return web.Response(status=429)


async def _sweeper(app: web.Application):
    """Периодическая чистка: in-memory (bans/hits) + БД (протухшие devices/pushes,
    иначе register случайными id / брошенные аккаунты копят строки → disk-DoS)."""
    while True:
        await asyncio.sleep(STATE_SWEEP)
        now = _now()
        for ip in [k for k, until in app["bans"].items() if until <= now]:
            app["bans"].pop(ip, None)
        cutoff = now - REQ_WINDOW
        for ip in list(app["hits"].keys()):
            dq = app["hits"][ip]
            while dq and dq[0] < cutoff:
                dq.popleft()
            if not dq:
                app["hits"].pop(ip, None)
        # БД: удаляем устройства без рефреша дольше TTL и все пуши старше суток.
        try:
            db = app.get("db")
            if db is not None:
                await db.execute("DELETE FROM devices WHERE updated < ?",
                                 (now - DEVICE_TTL,))
                await db.execute("DELETE FROM pushes WHERE ts < ?", (now - 86400,))
                await db.commit()
        except Exception as e:  # noqa: BLE001 — чистка не должна ронять релей
            log.warning("sweep db prune failed: %s", e)


def _now() -> int:
    return int(time.time())


class Jwt:
    """ES256-JWT для APNs с кэшем (Apple: обновлять <1ч и не чаще)."""
    def __init__(self, key_pem: str):
        self._key = key_pem
        self._token = ""
        self._iat = 0

    def token(self) -> str:
        now = _now()
        if now - self._iat < 3000 and self._token:   # ~50 мин — переиспользуем
            return self._token
        self._token = jwt.encode(
            {"iss": TEAM_ID, "iat": now},
            self._key, algorithm="ES256", headers={"kid": KEY_ID})
        self._iat = now
        return self._token


async def init_db(db: aiosqlite.Connection):
    await db.execute("PRAGMA journal_mode=WAL")
    await db.execute("PRAGMA synchronous=NORMAL")
    await db.execute("PRAGMA busy_timeout=5000")
    await db.execute("""CREATE TABLE IF NOT EXISTS devices(
        account_id TEXT PRIMARY KEY,
        notify_key TEXT NOT NULL UNIQUE,
        apns_token TEXT NOT NULL,
        tier TEXT NOT NULL DEFAULT 'free',
        env TEXT NOT NULL DEFAULT 'sandbox',
        updated INTEGER NOT NULL)""")
    await db.execute("""CREATE TABLE IF NOT EXISTS pushes(
        account_id TEXT NOT NULL, ts INTEGER NOT NULL)""")
    await db.execute("CREATE INDEX IF NOT EXISTS ix_pushes ON pushes(account_id, ts)")
    await db.commit()


def _bad(msg: str, code: int = 400):
    return web.json_response({"ok": False, "error": msg}, status=code)


@web.middleware
async def guard(request: web.Request, handler):
    """§contract: сетевой заслон перед всеми ручками (кроме health).
    Бан-чек → рейт-лимит → размер тела. Нарушение → бан IP + silent-drop."""
    if request.path == "/v1/health":
        return await handler(request)
    ip = _client_ip(request)
    now = _now()
    if _banned(request.app, ip, now):
        return _drop(request)                       # молчим весь бан
    limit = REQ_LIMIT_REGISTER if request.path == "/v1/register" else REQ_LIMIT_NOTIFY
    if not _rate_ok(request.app, ip, now, limit):
        _ban(request.app, ip, now, "rate")          # флуд/ддос
        return _drop(request)
    try:
        return await handler(request)
    except web.HTTPRequestEntityTooLarge:
        _ban(request.app, ip, now, "body_too_large")   # тело > MAX_BODY (структурное)
        return _drop(request)


async def handle_register(request: web.Request) -> web.Response:
    ip = _client_ip(request)
    now = _now()
    try:
        d = await request.json()
    except web.HTTPException:
        raise                                        # 413 → ловит guard (бан)
    except Exception:
        _ban(request.app, ip, now, "bad_json")
        return _drop(request)
    if not isinstance(d, dict):                      # не-объект → бан
        _ban(request.app, ip, now, "bad_json")
        return _drop(request)
    acc = str(d.get("accountId") or "").strip()      # coerce: не-строки не роняют
    nkey = str(d.get("notifyKey") or "").strip()
    tok = str(d.get("apnsToken") or "").strip()
    tier = str(d.get("tier") or "free").strip().lower()
    env = str(d.get("env") or DEFAULT_ENV).strip().lower()
    # §contract: битые/нестандартные id — нарушение → бан. apnsToken строго 64 hex
    # (defense-in-depth: сужает разнообразие мусора и «чужой токен под своим acc»).
    if not (_ID_RE.match(acc) and _ID_RE.match(nkey) and _TOKEN_RE.match(tok)):
        _ban(request.app, ip, now, "bad_ids")
        return _drop(request)
    if env not in APNS_HOST:
        env = DEFAULT_ENV
    if tier not in TIER_DAILY:
        tier = "free"
    db = request.app["db"]
    # accountId — ключ владельца; notifyKey привязан к нему (UNIQUE). Перезапись
    # возможна только знающим accountId (клиентом), не сервером.
    try:
        await db.execute(
            """INSERT INTO devices(account_id, notify_key, apns_token, tier, env, updated)
               VALUES(?,?,?,?,?,?)
               ON CONFLICT(account_id) DO UPDATE SET
                 notify_key=excluded.notify_key, apns_token=excluded.apns_token,
                 tier=excluded.tier, env=excluded.env, updated=excluded.updated""",
            (acc, nkey, tok, tier, env, _now()))
        await db.commit()
    except aiosqlite.IntegrityError:
        # notifyKey уже привязан к ДРУГОМу accountId (UNIQUE) — попытка занять
        # чужой notifyKey. Split-secret держит (нужен и accountId), просто
        # отказываем без 500.
        await db.rollback()
        return web.json_response({"ok": False, "error": "conflict"}, status=409)
    return web.json_response({"ok": True})


async def _reserve(db: aiosqlite.Connection, acc: str, tier: str) -> tuple[int, int] | None:
    """§quota: АТОМАРНО занять слот суточной квоты — единым INSERT…SELECT WHERE
    count<limit (одно SQL-выражение → нет гонки read-then-insert между count и
    insert, даже при конкурентных notify). Возвращает (остаток слотов, rowid
    вставленной строки), или None если лимит исчерпан. Резерв ДО отправки в APNs
    → квота ограничивает число обращений к Apple (а не только успехи)."""
    limit = TIER_DAILY.get(tier, DEFAULT_DAILY)
    since = _now() - 86400
    cur = await db.execute(
        "INSERT INTO pushes(account_id, ts) SELECT ?, ? WHERE "
        "(SELECT COUNT(*) FROM pushes WHERE account_id=? AND ts>=?) < ?",
        (acc, _now(), acc, since, limit))
    await db.commit()
    if cur.rowcount == 0:
        return None                      # квота исчерпана — слот не выдан
    rowid = cur.lastrowid
    async with db.execute(
            "SELECT COUNT(*) FROM pushes WHERE account_id=? AND ts>=?",
            (acc, since)) as c:
        (used,) = await c.fetchone()
    return (max(0, limit - used), rowid)


async def _refund(db: aiosqlite.Connection, rowid: int, acc: str) -> None:
    """Вернуть слот по ТОЧНОМУ rowid (не MAX — иначе при конкуренции того же
    аккаунта можно снять чужую свежую бронь). Скоуп по account_id — belt-and-
    suspenders: даже при баге логики нельзя удалить строку чужого аккаунта.
    Только если до APNs не дошли."""
    await db.execute("DELETE FROM pushes WHERE rowid=? AND account_id=?", (rowid, acc))
    await db.commit()


async def _reset_at(db: aiosqlite.Connection, acc: str) -> float:
    """Когда освободится слот суточного окна = самый старый пуш в окне + 24ч."""
    since = _now() - 86400
    async with db.execute(
            "SELECT MIN(ts) FROM pushes WHERE account_id=? AND ts>=?",
            (acc, since)) as cur:
        (oldest,) = await cur.fetchone()
    return (oldest + 86400) if oldest else (_now() + 86400)


def _quota_resp(reset: float, now: float, sent: bool) -> web.Response:
    """Ответ с стандартизированным временем сброса лимита (+ Retry-After)."""
    retry = max(1, int(reset - now))
    body = {"ok": True, "sent": sent, "reset_at": _iso(reset), "retry_after": retry}
    if not sent:
        body["reason"] = "quota"
    r = web.json_response(body)
    r.headers["Retry-After"] = str(retry)
    return r


async def handle_notify(request: web.Request) -> web.Response:
    ip = _client_ip(request)
    now = _now()
    try:
        d = await request.json()
    except web.HTTPException:
        raise                                        # 413 → guard (бан)
    except Exception:
        _ban(request.app, ip, now, "bad_json")
        return _drop(request)
    if not isinstance(d, dict):                      # не-объект (список/строка) → бан
        _ban(request.app, ip, now, "bad_json")
        return _drop(request)
    nkey = str(d.get("notifyKey") or "").strip()     # coerce: не-строки не роняют
    # §contract: битый notifyKey — структурное нарушение → бан. Текст НЕ баним,
    # а обрезаем (кириллица/эмодзи не должны валить легитимного отправителя).
    if not _ID_RE.match(nkey):
        _ban(request.app, ip, now, "bad_notifyKey")
        return _drop(request)
    title = str(d.get("title") or "").strip()[:MAX_TEXT]
    body = str(d.get("body") or "").strip()[:MAX_TEXT]
    # chatId идёт в HTTP-заголовок (collapse-id) и payload → строго валидируем/
    # обрезаем (иначе control-байты = header-injection, длинный = раздув payload).
    chat_id = str(d.get("chatId") or "").strip()[:128]
    if chat_id and not _ID_RE.match(chat_id):
        chat_id = ""                                 # битый chatId — просто игнор
    db = request.app["db"]
    async with db.execute(
            "SELECT account_id, apns_token, tier, env FROM devices WHERE notify_key=?",
            (nkey,)) as cur:
        row = await cur.fetchone()
    if row is None:
        # Не бан: устройство просто не на этом релее (валидный failover связки).
        return web.json_response({"ok": True, "sent": False, "reason": "unregistered"})
    acc, apns_token, tier, env = row
    # §quota: АТОМАРНО резервируем слот ДО отправки (устраняет гонку + ограничивает
    # обращения к APNs, не только успехи). remaining=None → лимит исчерпан.
    res = await _reserve(db, acc, tier)
    if res is None:
        return _quota_resp(await _reset_at(db, acc), now, sent=False)
    remaining, slot_rowid = res

    payload = {"aps": {"alert": {"title": title or "Hedgehog", "body": body},
                       "sound": "default"}}
    if chat_id:
        payload["chatId"] = chat_id
        payload["aps"]["thread-id"] = chat_id   # группировка пушей по чату
    host = APNS_HOST.get(env, APNS_HOST[DEFAULT_ENV])
    headers = {
        "authorization": f"bearer {request.app['jwt'].token()}",
        "apns-topic": TOPIC,
        "apns-push-type": "alert",
        "apns-priority": "10",
        "apns-expiration": str(_now() + EXPIRATION_SECS),
        "content-type": "application/json",
    }
    if chat_id:
        headers["apns-collapse-id"] = chat_id[:64]  # схлопывание повторов по чату
    try:
        resp = await request.app["http"].post(
            f"{host}/3/device/{apns_token}",
            headers=headers, content=json.dumps(payload), timeout=10)
    except Exception as e:
        await _refund(db, slot_rowid, acc)            # до Apple не дошли → вернём точный слот
        log.warning("apns unreachable: %s", e)       # детали — в лог, не клиенту
        return web.json_response({"ok": True, "sent": False, "reason": "apns_error"})
    if resp.status_code == 200:
        if remaining <= 0:
            # Последний разрешённый пуш — сообщаем reset_at (информационно).
            return _quota_resp(await _reset_at(db, acc), now, sent=True)
        return web.json_response({"ok": True, "sent": True})
    reason = ""
    try:
        reason = resp.json().get("reason", "")
    except Exception:
        reason = ""
    # Unregistered (410) — Apple предписывает удалить токен (мёртвое устройство).
    # BadDeviceToken (400) НЕ удаляем: частая причина — рассинхрон env, снесёт живое.
    if resp.status_code == 410 or reason == "Unregistered":
        await db.execute("DELETE FROM devices WHERE notify_key=?", (nkey,))
        await db.commit()
    # Клиенту отдаём apns_status (нужен для failover-логики связки: 410=мёртвый
    # токен), но НЕ сырой текст Apple (минимизируем рекон для хостильного Ёžika).
    return web.json_response(
        {"ok": True, "sent": False, "reason": "apns", "apns_status": resp.status_code})


async def handle_health(_: web.Request) -> web.Response:
    return web.json_response({"ok": True, "topic": TOPIC, "env": DEFAULT_ENV})


async def on_startup(app: web.Application):
    with open(KEY_PATH) as f:
        app["jwt"] = Jwt(f.read())          # fail-fast при отсутствии .p8
    app["http"] = httpx.AsyncClient(http2=True)
    app["db"] = await aiosqlite.connect(DB_PATH)
    await init_db(app["db"])
    app["sweeper"] = asyncio.create_task(_sweeper(app))   # чистка bans/hits


async def on_cleanup(app: web.Application):
    sweeper = app.get("sweeper")
    if sweeper is not None:
        sweeper.cancel()
    await app["http"].aclose()
    await app["db"].close()


def make_app() -> web.Application:
    # client_max_size = MAX_BODY: тело больше → aiohttp 413 → guard банит IP.
    app = web.Application(client_max_size=MAX_BODY, middlewares=[guard])
    # §contract state (in-memory на релее): баны и рейт-хиты (чистятся _sweeper).
    app["bans"] = {}
    app["hits"] = {}
    app.add_routes([
        web.post("/v1/register", handle_register),
        web.post("/v1/notify", handle_notify),
        web.get("/v1/health", handle_health),
    ])
    app.on_startup.append(on_startup)
    app.on_cleanup.append(on_cleanup)
    return app


if __name__ == "__main__":
    web.run_app(make_app(), host="0.0.0.0", port=PORT)
