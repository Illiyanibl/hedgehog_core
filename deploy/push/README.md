# §push — релей APNs (push.ecorp.red)

Единственное место, где живёт Apple-ключ `.p8`. Ёžik сам в APNs не ходит —
шлёт запрос сюда по TLS (штатная CA-валидация LE-серта, **не** пиннинг —
у релея настоящий публичный сертификат домена, ротируется ~90 дней).

## Раздельные секреты (радиус компрометации сервера ограничен)

- **`accountId`** — знает ТОЛЬКО клиент; нужен для `/register`. Серверам НЕ выдаётся.
- **`notifyKey`** — клиент выдаёт своим Ёžik-серверам; нужен для `/notify`.

Скомпрометированный/недоверенный сервер знает лишь `notifyKey` → максимум спам
в пределах суточной квоты; НЕ может перерегистрировать/перехватить device-token
(для этого нужен `accountId`, которого у сервера нет). Оба секрета —
высокоэнтропийные, ходят только по TLS. Позже `accountId`/`notifyKey` лягут на
Sign in with Apple.

## Поток

1. Клиент → `POST /v1/register {accountId, notifyKey, apnsToken, tier, env}`.
2. Ёžik при агентском `notify` и **оффлайн-клиенте** → `POST /v1/notify {notifyKey, title, body, chatId?}`.
3. Релей: `notifyKey → устройство`, проверка суточной квоты по тиру, ES256-JWT
   (Key ID + Team ID), APNs HTTP/2 (topic = bundle id). На `Unregistered`(410)
   устройство удаляется.

## Конфиг (env)

| env | дефолт | назначение |
|-----|--------|------------|
| `APNS_KEY_PATH` | `/secrets/AuthKey.p8` | путь к .p8 (том, chmod 600) |
| `APNS_KEY_ID` | `3D9RXCJ6FJ` | Key ID |
| `APNS_TEAM_ID` | `RW4MGD4RTB` | Team ID (iss JWT) |
| `APNS_TOPIC` | `red.ecorp.DevolutionHedgehog` | bundle id (apns-topic) |
| `APNS_DEFAULT_ENV` | `sandbox` | окружение (sandbox/production) |
| `PUSH_DB_PATH` | `/data/push.db` | SQLite (WAL) |
| `PUSH_PORT` | `8080` | порт внутри контейнера (наружу НЕ публикуется) |

Идентификаторы (Key ID/Team ID/topic) НЕ секретны — секрет только `.p8`.

## Квота (MVP)

Тир сообщает клиент (реальную верификацию у Apple подключим с платежами).
Суточный лимит пушей: free=5, lite=30, full=200 (`TIER_DAILY` в push_relay.py).
Лог `pushes` чистится оппортунистически (записи старше 24ч).

## Развёртывание (на хосте push.ecorp.red)

```
# .p8 положить в /opt/hedgehog-push/secrets/AuthKey.p8 (chmod 600), НЕ в git
docker network create hedgehog-edge 2>/dev/null || true
docker build -t hedgehog-push /opt/hedgehog-src/deploy/push
docker run -d --name hedgehog-push --restart unless-stopped \
  --network hedgehog-edge \
  -e APNS_DEFAULT_ENV=sandbox \
  -v /opt/hedgehog-push/secrets/AuthKey.p8:/secrets/AuthKey.p8:ro \
  -v hedgehog-push-data:/data \
  hedgehog-push
# ВАЖНО: без -p — наружу порт НЕ публикуем, доступ только через Caddy.
# Caddy (hedgehog-mirror) должен быть в сети hedgehog-edge и проксировать
# push.ecorp.red → hedgehog-push:8080 (см. deploy/mirror/Caddyfile).
```

## Окружение APNs (sandbox/production)

Dev-сборки (Xcode Run) выдают **sandbox** device-token, TestFlight/AppStore —
**production**. Клиент сообщает `env` при регистрации; релей шлёт в нужный хост.
`BadDeviceToken`(400) обычно = рассинхрон env (sandbox-токен на production-хост);
устройство НЕ удаляется, только лог.
