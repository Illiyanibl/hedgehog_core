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
  POST /v1/register    {accountId, notifyKey, apnsToken, tier, env}            — легаси v1
  POST /v1/register    {deviceToken, accountId, notifyKey, apnsToken, tier, env} — v2 (SIWA)
  POST /v1/auth/apple  {identityToken, deviceId} → {deviceToken}
  POST /v1/devices     {deviceToken} → список устройств аккаунта
  POST /v1/revoke      {deviceToken, deviceId?} — отзыв устройства (без id — своего)
  POST /v1/notify      {notifyKey, title, body, chatId?}
  GET  /v1/health

§siwa (Sign in with Apple, roadmap п.5): identity token Apple (RS256 JWT)
проверяется ЛОКАЛЬНО по публичным JWKS Apple (кэш; сеть — только при неизвестном
kid/протухшем кэше). Верифицированный `sub` → users; устройству выдаётся
deviceToken (256 бит, в БД ТОЛЬКО SHA-256). Регистрация v2 идёт под deviceToken:
deviceId берётся из строки авторизации, НЕ от клиента — это и есть привязка
deviceId↔notifyKey. Квота v2 — per-user (`u:<id>`): все устройства аккаунта
делят суточный лимит. Легаси v1 (анонимная пара accountId/notifyKey) полностью
сохраняется — старые сборки клиента работают без изменений.
Принято для MVP (задокументировано, ревью Fable):
  • notify_key в БД открытым текстом (как в легаси: компрометация БД ≈
    компрометация хоста ≈ утечка .p8 — хэширование ключа радиус не меняет);
  • replay identityToken ТРЕТЬИМИ лицами закрыт TLS; при этом клиент шлёт ОДИН
    identityToken на все 3 релея → скомпрометированный релей в 10-мин окне
    может реплеить его соседям и угнать пуш-слоты учётки на связке. Принято:
    релеи — наша инфраструктура, компрометация релея = утечка .p8 (хуже);
  • revoke снимается повторным входом через Apple (proof-of-identity);
  • квота per-user считается на КАЖДОМ релее отдельно (своя БД) → злой Ёžik,
    шлющий notify во все 3 (а не failover'ом), получает до 3× лимита — тот же
    класс, что легаси-M2;
  • revoke по связке best-effort: недоступный в момент signOut релей останется
    с активной привязкой до TTL (полное решение — с per-Ёžik ключами, п. M6);
  • 410-окно (R1): пока v2-строка держит apns_token=NULL, знающий nk Ёžik может
    занять ключ легаси-регистрацией (эквивалент легаси, где 410 удалял строку
    и освобождал nk); жертва при следующем v2-register получит 409 до TTL
    строки атакующего. Ещё один аргумент за per-Ёžik ключи (M6);
  • :8080 обязан быть достижим ТОЛЬКО для Caddy (docker-сеть) — доверие
    X-Real-IP держится на этом.

APNs: HTTP/2, ES256-JWT (kid=Key ID, iss=Team ID), apns-topic=bundle id.
Хранилище: SQLite (WAL). Секрет — только .p8.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import secrets
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
_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,200}$")   # accountId/notifyKey/deviceId
_TOKEN_RE = re.compile(r"^[a-fA-F0-9]{64}$")       # apnsToken — ровно 64 hex
# §siwa: структурная форма JWT (3 сегмента base64url). Identity token Apple
# ~1КБ; кап 4КБ — запас (MAX_BODY всё равно режет тело целиком).
_JWT_RE = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")
MAX_JWT = 4096

# §siwa: параметры проверки identity token Apple.
APPLE_ISS = "https://appleid.apple.com"
APPLE_JWKS_URL = os.environ.get("APPLE_JWKS_URL", "https://appleid.apple.com/auth/keys")
JWKS_TTL = 6 * 3600     # плановая свежесть кэша ключей Apple
JWKS_MIN_GAP = 60       # анти-DoS: битые/неизвестные kid не заставят дёргать Apple чаще
# Потолок устройств на учётку: режет флуд user_devices произвольными deviceId
# под одним Apple ID. Обычные строки чистит DEVICE_TTL; revoked-маркеры живут
# REVOKED_TTL (сильно дольше: короткий TTL истекал бы revoke даунгрейдом на v1,
# бессмертие делало бы MAX_DEVICES пожизненным потолком — Fable Ф3/R4).
MAX_DEVICES = 20
REVOKED_TTL = 730 * 86400
# Ручки, куда ходит ТЕЛЕФОН (может быть за CGNAT) — мягкий рейт-лимит register.
_PHONE_PATHS = {"/v1/register", "/v1/auth/apple", "/v1/devices", "/v1/revoke"}


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
            if app.get("db") is not None:
                await _prune_db(app, now)
        except Exception as e:  # noqa: BLE001 — чистка не должна ронять релей
            log.warning("sweep db prune failed: %s", e)


async def _prune_db(app: web.Application, now: int) -> None:
    """Чистка БД (вынесена из sweeper-цикла — тестируется напрямую)."""
    db = app["db"]
    async with app["wlock"]:
        await db.execute("DELETE FROM devices WHERE updated < ?",
                         (now - DEVICE_TTL,))
        # §siwa: revoked-строки живут REVOKED_TTL, а не DEVICE_TTL (Fable Ф3):
        # короткий TTL стирал бы маркер отзыва (register 401 вместо 403 →
        # честный клиент «мягко» воскрешает пуши через v1). Но не вечно (R4):
        # иначе MAX_DEVICES стал бы пожизненным потолком учётки.
        await db.execute(
            "DELETE FROM user_devices WHERE updated < ? AND revoked=0",
            (now - DEVICE_TTL,))
        await db.execute(
            "DELETE FROM user_devices WHERE updated < ? AND revoked=1",
            (now - REVOKED_TTL,))
        # Учётка без устройств — мусор (все строки протухли).
        await db.execute("DELETE FROM users WHERE NOT EXISTS("
                         "SELECT 1 FROM user_devices d WHERE d.user_id=users.id)")
        await db.execute("DELETE FROM pushes WHERE ts < ?", (now - 86400,))
        await db.commit()


def _now() -> int:
    return int(time.time())


def _sha256(s: str) -> str:
    """Хэш deviceToken: в БД сам токен не храним (утечка БД ≠ утечка токенов)."""
    return hashlib.sha256(s.encode()).hexdigest()


class AppleKeys:
    """§siwa: кэш публичных ключей Apple (JWKS). Подпись identity token
    проверяется локально; сеть — только при неизвестном kid или протухшем кэше,
    и не чаще JWKS_MIN_GAP (иначе поток запросов с выдуманными kid превращается
    во внешний DoS на appleid.apple.com и на нас). Ключи заменяются атомарно
    ЦЕЛИКОМ и только при непустом ответе — сбойная выборка не сносит рабочий кэш."""

    def __init__(self, http: httpx.AsyncClient):
        self._http = http
        self._keys: dict[str, object] = {}
        self._fetched = 0.0     # время последней УСПЕШНОЙ выборки
        self._attempt = 0.0     # время последней ПОПЫТКИ (для MIN_GAP)
        self._lock = asyncio.Lock()

    async def key(self, kid: str):
        now = _now()
        if kid in self._keys and now - self._fetched < JWKS_TTL:
            return self._keys[kid]
        async with self._lock:
            now = _now()
            if kid in self._keys and now - self._fetched < JWKS_TTL:
                return self._keys[kid]     # соседний запрос уже обновил
            if now - self._attempt < JWKS_MIN_GAP:
                return self._keys.get(kid)  # свежая попытка была — не дёргаем Apple
            self._attempt = now
            try:
                resp = await self._http.get(APPLE_JWKS_URL, timeout=10)
                fresh: dict[str, object] = {}
                for k in resp.json().get("keys", []):
                    try:
                        fresh[str(k.get("kid") or "")] = \
                            jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(k))
                    except Exception:      # noqa: BLE001 — битый ключ пропускаем
                        continue
                if fresh:
                    self._keys = fresh
                    self._fetched = now
            except Exception as e:  # noqa: BLE001 — сеть/JSON: живём на старом кэше
                log.warning("apple jwks fetch failed: %s", e)
            return self._keys.get(kid)


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
    # §siwa: учётки Apple. AUTOINCREMENT — id НЕ переиспользуются после чистки
    # (иначе новый юзер унаследовал бы квоту-скоуп `u:<id>` удалённого).
    await db.execute("""CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        apple_sub TEXT NOT NULL UNIQUE,
        created INTEGER NOT NULL)""")
    # §siwa: устройства под учёткой. token_hash — SHA-256 deviceToken (256-бит
    # случайные токены — коллизии исключены, UNIQUE не нужен). notify_key
    # UNIQUE — чужой ключ не занять. revoked=1 сохраняет token_hash (register
    # различает 403 «отозван» vs 401 «протух»), но гасит все операции.
    await db.execute("""CREATE TABLE IF NOT EXISTS user_devices(
        user_id INTEGER NOT NULL,
        device_id TEXT NOT NULL,
        token_hash TEXT NOT NULL,
        notify_key TEXT UNIQUE,
        apns_token TEXT,
        tier TEXT NOT NULL DEFAULT 'free',
        env TEXT NOT NULL DEFAULT 'sandbox',
        revoked INTEGER NOT NULL DEFAULT 0,
        updated INTEGER NOT NULL,
        PRIMARY KEY(user_id, device_id))""")
    await db.execute(
        "CREATE INDEX IF NOT EXISTS ix_ud_token ON user_devices(token_hash)")
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
    limit = REQ_LIMIT_REGISTER if request.path in _PHONE_PATHS else REQ_LIMIT_NOTIFY
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
    nkey = str(d.get("notifyKey") or "").strip()     # coerce: не-строки не роняют
    tok = str(d.get("apnsToken") or "").strip()
    tier = str(d.get("tier") or "free").strip().lower()
    env = str(d.get("env") or DEFAULT_ENV).strip().lower()
    dtok = str(d.get("deviceToken") or "").strip()
    # §contract: битые/нестандартные id — нарушение → бан. apnsToken строго 64 hex
    # (defense-in-depth: сужает разнообразие мусора и «чужой токен под своим acc»).
    if not (_ID_RE.match(nkey) and _TOKEN_RE.match(tok)):
        _ban(request.app, ip, now, "bad_ids")
        return _drop(request)
    if env not in APNS_HOST:
        env = DEFAULT_ENV
    if tier not in TIER_DAILY:
        tier = "free"
    db = request.app["db"]
    acc = str(d.get("accountId") or "").strip()
    if dtok:
        # §siwa: регистрация v2 — под deviceToken, выданным /v1/auth/apple.
        # deviceId берём из СТРОКИ АВТОРИЗАЦИИ, не из запроса — привязка
        # deviceId↔notifyKey enforced сервером. accountId клиент шлёт и здесь:
        # это proof-of-ownership для миграции легаси-строки (Fable Ф1).
        if not _ID_RE.match(dtok) or (acc and not _ID_RE.match(acc)):
            _ban(request.app, ip, now, "bad_ids")
            return _drop(request)
        async with request.app["wlock"]:
            async with db.execute(
                    "SELECT user_id, device_id, revoked FROM user_devices "
                    "WHERE token_hash=?", (_sha256(dtok),)) as cur:
                row = await cur.fetchone()
            if row is None:
                # НЕ бан: токен протух (TTL-чистка) — клиент откатится на легаси
                # v1 (пуш продолжает жить) и предложит повторный вход.
                return _bad("unauthorized", 401)
            if row[2]:
                # Устройство ОТОЗВАНО владельцем: 403 — честный клиент НЕ должен
                # откатываться на v1 (иначе revoke обходится даунгрейдом);
                # оживление только новым входом через Apple. token_hash при
                # revoke СОХРАНЯЕТСЯ именно ради различимости 403 vs 401.
                return _bad("revoked", 403)
            uid, device_id, _ = row
            # §siwa (Fable Ф1): захват ЛЕГАСИ-ключа через v2 — злой Ёžik знает
            # notifyKey жертвы и мог бы, войдя под СВОИМ Apple ID, увести ключ
            # (UNIQUE в user_devices легаси-таблицу не покрывает). Миграция —
            # только с доказательством владения: accountId легаси-строки.
            async with db.execute(
                    "SELECT account_id FROM devices WHERE notify_key=?",
                    (nkey,)) as cur:
                legacy = await cur.fetchone()
            if legacy is not None and (not acc or legacy[0] != acc):
                return web.json_response(
                    {"ok": False, "error": "conflict"}, status=409)
            try:
                # revoked=0 перепроверяется В транзакции (Fable Ф9: TOCTOU с
                # конкурентным revoke — иначе UPDATE реанимировал бы ключ).
                cur = await db.execute(
                    """UPDATE user_devices SET notify_key=?, apns_token=?, tier=?,
                       env=?, updated=? WHERE user_id=? AND device_id=? AND revoked=0""",
                    (nkey, tok, tier, env, _now(), uid, device_id))
                if cur.rowcount == 0:
                    await db.rollback()
                    return _bad("revoked", 403)
                # Миграция: своя легаси-строка больше не нужна — v2 теперь
                # источник истины для ключа (скоуп по account_id — см. выше).
                await db.execute(
                    "DELETE FROM devices WHERE notify_key=? AND account_id=?",
                    (nkey, acc))
                await db.commit()
            except aiosqlite.IntegrityError:
                # notifyKey занят ДРУГОЙ строкой user_devices (чужой 256-битный
                # ключ угадать нельзя — попытка захвата) — отказ без 500.
                await db.rollback()
                return web.json_response({"ok": False, "error": "conflict"}, status=409)
        return web.json_response({"ok": True})
    if not _ID_RE.match(acc):
        _ban(request.app, ip, now, "bad_ids")
        return _drop(request)
    # Легаси v1: accountId — ключ владельца; notifyKey привязан к нему (UNIQUE).
    # Перезапись возможна только знающим accountId (клиентом), не сервером.
    async with request.app["wlock"]:
        # §siwa: ключ, занятый ЖИВОЙ v2-строкой (apns_token есть), в легаси
        # занять НЕЛЬЗЯ — иначе «закладка»: v1-строка с чужим nk дождалась бы
        # фоллбэка notify и увела пуши. v2-строка с NULL apns_token (после 410 /
        # осиротевшая) ключ НЕ держит: легаси-регистрация освобождает его
        # (UPDATE ниже) — эквивалент легаси-поведения, где 410 удалял строку и
        # nk становился свободен. Честный клиент с живой v2 сюда не попадает
        # (регистрируется по v2).
        async with db.execute(
                "SELECT 1 FROM user_devices WHERE notify_key=? "
                "AND apns_token IS NOT NULL", (nkey,)) as cur:
            shadow = await cur.fetchone()
        if shadow is not None:
            return web.json_response({"ok": False, "error": "conflict"}, status=409)
        try:
            await db.execute(
                """INSERT INTO devices(account_id, notify_key, apns_token, tier, env, updated)
                   VALUES(?,?,?,?,?,?)
                   ON CONFLICT(account_id) DO UPDATE SET
                     notify_key=excluded.notify_key, apns_token=excluded.apns_token,
                     tier=excluded.tier, env=excluded.env, updated=excluded.updated""",
                (acc, nkey, tok, tier, env, _now()))
            # Освободить ключ у мёртвой v2-строки: авторизация (token_hash)
            # остаётся, ключ вернётся при следующей v2-регистрации после входа.
            await db.execute(
                "UPDATE user_devices SET notify_key=NULL WHERE notify_key=? "
                "AND apns_token IS NULL", (nkey,))
            await db.commit()
        except aiosqlite.IntegrityError:
            # notifyKey уже привязан к ДРУГОМу accountId (UNIQUE) — попытка
            # занять чужой notifyKey. Split-secret держит (нужен и accountId),
            # просто отказываем без 500.
            await db.rollback()
            return web.json_response({"ok": False, "error": "conflict"}, status=409)
    return web.json_response({"ok": True})


async def _reserve(app: web.Application, acc: str, tier: str) -> tuple[int, int] | None:
    """§quota: АТОМАРНО занять слот суточной квоты — единым INSERT…SELECT WHERE
    count<limit (одно SQL-выражение → нет гонки read-then-insert между count и
    insert, даже при конкурентных notify). Возвращает (остаток слотов, rowid
    вставленной строки), или None если лимит исчерпан. Резерв ДО отправки в APNs
    → квота ограничивает число обращений к Apple (а не только успехи).
    Под wlock: commit не должен публиковать чужую полу-транзакцию."""
    db = app["db"]
    limit = TIER_DAILY.get(tier, DEFAULT_DAILY)
    since = _now() - 86400
    async with app["wlock"]:
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


async def _refund(app: web.Application, rowid: int, acc: str) -> None:
    """Вернуть слот по ТОЧНОМУ rowid (не MAX — иначе при конкуренции того же
    аккаунта можно снять чужую свежую бронь). Скоуп по account_id — belt-and-
    suspenders: даже при баге логики нельзя удалить строку чужого аккаунта.
    Только если до APNs не дошли."""
    async with app["wlock"]:
        await app["db"].execute(
            "DELETE FROM pushes WHERE rowid=? AND account_id=?", (rowid, acc))
        await app["db"].commit()


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
    # §siwa: сначала v2 (устройство под учёткой Apple), затем легаси. Квота v2 —
    # per-user `u:<id>` (все устройства аккаунта делят суточный лимит); у легаси
    # скоуп-ключи — произвольные id клиента, но с `u:` пересечься не могут:
    # легаси-скоуп равен accountId, а _ID_RE не пропускает двоеточие.
    v2_device: tuple[int, str] | None = None    # (user_id, device_id) — для 410
    async with db.execute(
            "SELECT user_id, device_id, apns_token, tier, env FROM user_devices "
            "WHERE notify_key=? AND revoked=0", (nkey,)) as cur:
        row = await cur.fetchone()
    if row is not None and row[2]:
        uid, dev_id, apns_token, tier, env = row
        v2_device = (uid, dev_id)
        acc = f"u:{uid}"
    else:
        # v2-строка без apns_token (после 410 / осиротевшая после localSignOut)
        # НЕ хоронит легаси (Fable Ф5): клиент мог честно перерегистрироваться
        # по v1 (токена авторизации у него уже нет — починить v2 нечем).
        # Закладку это не открывает: занять ключ активной v2-строки в легаси
        # register не даёт (shadow-проверка).
        async with db.execute(
                "SELECT account_id, apns_token, tier, env FROM devices "
                "WHERE notify_key=?", (nkey,)) as cur:
            row = await cur.fetchone()
        if row is None:
            # Не бан: устройство просто не на этом релее (валидный failover связки).
            return web.json_response(
                {"ok": True, "sent": False, "reason": "unregistered"})
        acc, apns_token, tier, env = row
    # §quota: АТОМАРНО резервируем слот ДО отправки (устраняет гонку + ограничивает
    # обращения к APNs, не только успехи). remaining=None → лимит исчерпан.
    res = await _reserve(request.app, acc, tier)
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
        await _refund(request.app, slot_rowid, acc)   # до Apple не дошли → вернём точный слот
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
        async with request.app["wlock"]:
            if v2_device is not None:
                # v2: строку НЕ удаляем (в ней deviceToken-авторизация) — снимаем
                # только apns_token; клиент перерегистрирует при следующем запуске.
                await db.execute(
                    "UPDATE user_devices SET apns_token=NULL WHERE user_id=? AND device_id=?",
                    v2_device)
            else:
                await db.execute("DELETE FROM devices WHERE notify_key=?", (nkey,))
            await db.commit()
    # Клиенту отдаём apns_status (нужен для failover-логики связки: 410=мёртвый
    # токен), но НЕ сырой текст Apple (минимизируем рекон для хостильного Ёžika).
    return web.json_response(
        {"ok": True, "sent": False, "reason": "apns", "apns_status": resp.status_code})


async def _parse_dict(request: web.Request) -> dict | None:
    """Общий парс тела для §siwa-ручек: JSON-объект или None (вызвавший банит).
    413 пробрасывается в guard (там бан за размер)."""
    try:
        d = await request.json()
    except web.HTTPException:
        raise
    except Exception:
        return None
    return d if isinstance(d, dict) else None


async def _device_by_token(db: aiosqlite.Connection, dtok: str):
    """Строка user_devices по deviceToken (или None). Отозванные не проходят."""
    async with db.execute(
            "SELECT user_id, device_id FROM user_devices "
            "WHERE token_hash=? AND revoked=0", (_sha256(dtok),)) as cur:
        return await cur.fetchone()


async def handle_auth_apple(request: web.Request) -> web.Response:
    """§siwa: identity token Apple → deviceToken релея. Подпись проверяется по
    JWKS Apple локально. Мусор (не-JWT, битый deviceId) — структурное нарушение
    → бан; корректный по форме, но невалидный токен (протух/чужой aud) — 401 БЕЗ
    бана: у легитимного клиента бывает протухший токен (ретрай после сна)."""
    ip = _client_ip(request)
    now = _now()
    d = await _parse_dict(request)
    if d is None:
        _ban(request.app, ip, now, "bad_json")
        return _drop(request)
    ident = str(d.get("identityToken") or "").strip()
    device_id = str(d.get("deviceId") or "").strip()
    if not _ID_RE.match(device_id) or len(ident) > MAX_JWT or not _JWT_RE.match(ident):
        _ban(request.app, ip, now, "bad_auth_ids")
        return _drop(request)
    try:
        header = jwt.get_unverified_header(ident)
    except Exception:
        _ban(request.app, ip, now, "bad_jwt")
        return _drop(request)
    key = await request.app["apple_keys"].key(str(header.get("kid") or ""))
    if key is None:
        # Ключа нет: неизвестный kid (ротация у Apple) или JWKS недоступен.
        # НЕ бан и НЕ 401 — клиенту имеет смысл повторить позже.
        return _bad("auth_unavailable", 503)
    try:
        claims = jwt.decode(
            ident, key=key, algorithms=["RS256"], audience=TOPIC,
            issuer=APPLE_ISS,
            # exp обязателен (иначе токен без exp жил бы вечно — PyJWT проверяет
            # только присутствующие claims); sub — наш ключ учётки.
            options={"require": ["exp", "sub", "iat"]})
    except Exception:
        return _bad("invalid_token", 401)
    sub = str(claims.get("sub") or "")
    if not sub:
        return _bad("invalid_token", 401)
    db = request.app["db"]
    token = secrets.token_urlsafe(32)
    async with request.app["wlock"]:
        await db.execute(
            "INSERT INTO users(apple_sub, created) VALUES(?,?) "
            "ON CONFLICT(apple_sub) DO NOTHING", (sub, now))
        async with db.execute("SELECT id FROM users WHERE apple_sub=?", (sub,)) as cur:
            (uid,) = await cur.fetchone()
        # Потолок устройств на учётку (флуд произвольными deviceId под одним
        # Apple ID; revoked-строки живут вечно — потолок ограничивает и их).
        async with db.execute(
                "SELECT COUNT(*), MAX(CASE WHEN device_id=? THEN 1 ELSE 0 END) "
                "FROM user_devices WHERE user_id=?", (device_id, uid)) as cur:
            cnt, exists = await cur.fetchone()
        if not exists and (cnt or 0) >= MAX_DEVICES:
            await db.commit()            # users-строка безвредна — фиксируем
            return _bad("too_many_devices", 409)
        # Повторный вход перезаписывает token_hash (старый deviceToken умирает)
        # и снимает revoked: живой вход через Apple = proof-of-identity.
        await db.execute(
            """INSERT INTO user_devices(user_id, device_id, token_hash, updated)
               VALUES(?,?,?,?)
               ON CONFLICT(user_id, device_id) DO UPDATE SET
                 token_hash=excluded.token_hash, revoked=0, updated=excluded.updated""",
            (uid, device_id, _sha256(token), now))
        await db.commit()
    return web.json_response({"ok": True, "deviceToken": token})


async def handle_devices(request: web.Request) -> web.Response:
    """§siwa: список устройств учётки (для UI «мои устройства»/отзыва)."""
    ip = _client_ip(request)
    now = _now()
    d = await _parse_dict(request)
    if d is None:
        _ban(request.app, ip, now, "bad_json")
        return _drop(request)
    dtok = str(d.get("deviceToken") or "").strip()
    if not _ID_RE.match(dtok):
        _ban(request.app, ip, now, "bad_ids")
        return _drop(request)
    db = request.app["db"]
    me = await _device_by_token(db, dtok)
    if me is None:
        return _bad("unauthorized", 401)
    uid, my_dev = me
    out = []
    async with db.execute(
            "SELECT device_id, apns_token IS NOT NULL, revoked, updated "
            "FROM user_devices WHERE user_id=?", (uid,)) as cur:
        async for dev_id, has_tok, revoked, updated in cur:
            out.append({"deviceId": dev_id, "registered": bool(has_tok),
                        "revoked": bool(revoked), "updated": _iso(updated),
                        "self": dev_id == my_dev})
    return web.json_response({"ok": True, "devices": out})


async def handle_revoke(request: web.Request) -> web.Response:
    """§siwa: отзыв устройства учётки — его notifyKey/apnsToken/deviceToken
    перестают действовать (лечит утёкший ключ у отдельного устройства). Без
    deviceId отзывается СВОЁ устройство (выход из аккаунта). Снимается только
    новым входом через Apple на том устройстве."""
    ip = _client_ip(request)
    now = _now()
    d = await _parse_dict(request)
    if d is None:
        _ban(request.app, ip, now, "bad_json")
        return _drop(request)
    dtok = str(d.get("deviceToken") or "").strip()
    target = str(d.get("deviceId") or "").strip()
    if not _ID_RE.match(dtok) or (target and not _ID_RE.match(target)):
        _ban(request.app, ip, now, "bad_ids")
        return _drop(request)
    db = request.app["db"]
    me = await _device_by_token(db, dtok)
    if me is None:
        return _bad("unauthorized", 401)
    uid, my_dev = me
    target = target or my_dev
    # token_hash НЕ стираем: по нему register v2 отличает «отозван» (403, без
    # отката на v1) от «протух» (401, мягкий откат). Для всех операций токен
    # мёртв — _device_by_token фильтрует revoked=0.
    async with request.app["wlock"]:
        cur = await db.execute(
            "UPDATE user_devices SET revoked=1, notify_key=NULL, apns_token=NULL, "
            "updated=? WHERE user_id=? AND device_id=?",
            (now, uid, target))
        await db.commit()
    if cur.rowcount == 0:
        return _bad("not_found", 404)
    return web.json_response({"ok": True, "revoked": target})


async def handle_health(_: web.Request) -> web.Response:
    return web.json_response({"ok": True, "topic": TOPIC, "env": DEFAULT_ENV})


async def on_startup(app: web.Application):
    with open(KEY_PATH) as f:
        app["jwt"] = Jwt(f.read())          # fail-fast при отсутствии .p8
    app["http"] = httpx.AsyncClient(http2=True)
    app["apple_keys"] = AppleKeys(app["http"])   # §siwa: кэш JWKS Apple
    app["db"] = await aiosqlite.connect(DB_PATH)
    # §wlock: ОДНА aiosqlite-коннекция на всех + неявные транзакции → без лока
    # rollback() одного хендлера откатывал бы незакоммиченные записи другого
    # (Fable Ф2: индуцируемая 409-ами потеря конкурентного revoke). Каждая
    # write-транзакция (execute…commit/rollback) — единый критический участок.
    app["wlock"] = asyncio.Lock()
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
        web.post("/v1/auth/apple", handle_auth_apple),   # §siwa
        web.post("/v1/devices", handle_devices),         # §siwa
        web.post("/v1/revoke", handle_revoke),           # §siwa
        web.get("/v1/health", handle_health),
    ])
    app.on_startup.append(on_startup)
    app.on_cleanup.append(on_cleanup)
    return app


if __name__ == "__main__":
    web.run_app(make_app(), host="0.0.0.0", port=PORT)
