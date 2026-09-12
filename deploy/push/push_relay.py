#!/usr/bin/env python3
"""§push: релей APNs для Ёžika (push.ecorp.red).

Единственное место, где живёт Apple-ключ .p8. Клиент регистрирует device-token,
Ёžik при агентском уведомлении и оффлайн-клиенте просит релей отправить пуш.

Раздельные секреты (радиус компрометации сервера ограничен):
  • accountId — знает ТОЛЬКО клиент; нужен для /register. Серверам НЕ выдаётся.
  • notifyKey — клиент выдаёт своим Ёžik-серверам; нужен для /notify.
Скомпрометированный сервер знает лишь notifyKey → максимум спам в пределах
квоты; НЕ может перерегистрировать/перехватить токен (нужен accountId).

Endpoints (за TLS Caddy, домен push.ecorp.red, штатный LE-серт — CA-валидация):
  POST /v1/register  {accountId, notifyKey, apnsToken, tier, env}
  POST /v1/notify    {notifyKey, title, body, chatId?}
  GET  /v1/health

APNs: HTTP/2, ES256-JWT (kid=Key ID, iss=Team ID), apns-topic=bundle id.
Хранилище: SQLite (WAL). Секрет — только .p8.
"""
from __future__ import annotations

import json
import os
import time

import aiosqlite
import httpx
import jwt  # PyJWT
from aiohttp import web

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
TIER_DAILY = {"free": 5, "lite": 30, "full": 200}
DEFAULT_DAILY = 5

EXPIRATION_SECS = 6 * 3600   # apns-expiration: протухший пуш не прилетит сутки спустя
MAX_TEXT = 512               # защитная обрезка (payload APNs ≤ 4KB)


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


async def handle_register(request: web.Request) -> web.Response:
    try:
        d = await request.json()
    except Exception:
        return _bad("bad json")
    acc = (d.get("accountId") or "").strip()
    nkey = (d.get("notifyKey") or "").strip()
    tok = (d.get("apnsToken") or "").strip()
    tier = (d.get("tier") or "free").strip().lower()
    env = (d.get("env") or DEFAULT_ENV).strip().lower()
    if not acc or not nkey or not tok:
        return _bad("accountId, notifyKey and apnsToken required")
    if env not in APNS_HOST:
        env = DEFAULT_ENV
    if tier not in TIER_DAILY:
        tier = "free"
    db = request.app["db"]
    # accountId — ключ владельца; notifyKey привязан к нему (UNIQUE). Перезапись
    # возможна только знающим accountId (клиентом), не сервером.
    await db.execute(
        """INSERT INTO devices(account_id, notify_key, apns_token, tier, env, updated)
           VALUES(?,?,?,?,?,?)
           ON CONFLICT(account_id) DO UPDATE SET
             notify_key=excluded.notify_key, apns_token=excluded.apns_token,
             tier=excluded.tier, env=excluded.env, updated=excluded.updated""",
        (acc, nkey, tok, tier, env, _now()))
    await db.commit()
    return web.json_response({"ok": True})


async def _quota_left(db: aiosqlite.Connection, acc: str, tier: str) -> int:
    limit = TIER_DAILY.get(tier, DEFAULT_DAILY)
    since = _now() - 86400
    # Оппортунистическая чистка старых записей этого accountId (лог не растёт).
    await db.execute("DELETE FROM pushes WHERE account_id=? AND ts<?", (acc, since))
    async with db.execute(
            "SELECT COUNT(*) FROM pushes WHERE account_id=? AND ts>=?",
            (acc, since)) as cur:
        (used,) = await cur.fetchone()
    return max(0, limit - used)


async def handle_notify(request: web.Request) -> web.Response:
    try:
        d = await request.json()
    except Exception:
        return _bad("bad json")
    nkey = (d.get("notifyKey") or "").strip()
    title = (d.get("title") or "").strip()[:MAX_TEXT]
    body = (d.get("body") or "").strip()[:MAX_TEXT]
    if not nkey:
        return _bad("notifyKey required")
    db = request.app["db"]
    async with db.execute(
            "SELECT account_id, apns_token, tier, env FROM devices WHERE notify_key=?",
            (nkey,)) as cur:
        row = await cur.fetchone()
    if row is None:
        return web.json_response({"ok": True, "sent": False, "reason": "unregistered"})
    acc, apns_token, tier, env = row
    if await _quota_left(db, acc, tier) <= 0:
        return web.json_response({"ok": True, "sent": False, "reason": "quota"})

    payload = {"aps": {"alert": {"title": title or "Hedgehog", "body": body},
                       "sound": "default"}}
    chat_id = (d.get("chatId") or "").strip()
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
        return _bad(f"apns unreachable: {e}", 502)
    if resp.status_code == 200:
        await db.execute("INSERT INTO pushes(account_id, ts) VALUES(?,?)", (acc, _now()))
        await db.commit()
        return web.json_response({"ok": True, "sent": True})
    reason = ""
    try:
        reason = resp.json().get("reason", "")
    except Exception:
        reason = resp.text[:120]
    # Unregistered (410) — Apple предписывает удалить токен (мёртвое устройство).
    # BadDeviceToken (400) НЕ удаляем: частая причина — рассинхрон env, снесёт живое.
    if resp.status_code == 410 or reason == "Unregistered":
        await db.execute("DELETE FROM devices WHERE notify_key=?", (nkey,))
        await db.commit()
    return web.json_response(
        {"ok": True, "sent": False, "reason": reason, "apns_status": resp.status_code})


async def handle_health(_: web.Request) -> web.Response:
    return web.json_response({"ok": True, "topic": TOPIC, "env": DEFAULT_ENV})


async def on_startup(app: web.Application):
    with open(KEY_PATH) as f:
        app["jwt"] = Jwt(f.read())          # fail-fast при отсутствии .p8
    app["http"] = httpx.AsyncClient(http2=True)
    app["db"] = await aiosqlite.connect(DB_PATH)
    await init_db(app["db"])


async def on_cleanup(app: web.Application):
    await app["http"].aclose()
    await app["db"].close()


def make_app() -> web.Application:
    app = web.Application()
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
