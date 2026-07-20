#!/usr/bin/env bash
# Ёжик — установка на сервер. Идемпотентно.
#
# Обычно запускается так (клиент «Добавить сервер» делает это по SSH):
#   apt-get install -y git
#   git clone --depth 1 https://github.com/Illiyanibl/hedgehog_core /opt/hedgehog
#   bash /opt/hedgehog/deploy/bootstrap.sh
#
# Что делает:
#   1) apt update + базовые пакеты
#   2) ставит Docker Engine + compose plugin (если ещё нет)
#   3) firewall (ufw): SSH + WS/FILE порты + 8000-8099 (приложения) + Caddy
#   4) генерит bearer-токен, определяет публичный IP → deploy/.env
#   5) docker compose up -d --build (Ёжик + socket-proxy + Caddy)
#   6) печатает JSON коннекта (host/порты/токен/TLS-отпечаток)
#
# Порты хоста переопределяются переменными окружения (для теста, чтобы не
# конфликтовать с уже занятыми портами):
#   HEDGEHOG_WS_PORT (8765) HEDGEHOG_FILE_PORT (8767)
#   CADDY_HTTP_PORT (80) CADDY_HTTPS_PORT (443)
set -euo pipefail

[ "$(id -u)" = 0 ] || { echo "нужен root (sudo)"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
[ -f "$SCRIPT_DIR/docker-compose.yml" ] || { echo "не найден docker-compose.yml рядом со скриптом"; exit 1; }
# Работаем из deploy/: compose сам подхватит ./.env и относительные пути
# (context: .. → корень репо, ./caddy/Caddyfile).
cd "$SCRIPT_DIR"

WS_PORT="${HEDGEHOG_WS_PORT:-8765}"
FILE_PORT="${HEDGEHOG_FILE_PORT:-8767}"
CADDY_HTTP="${CADDY_HTTP_PORT:-80}"
CADDY_HTTPS="${CADDY_HTTPS_PORT:-443}"
APP_MIN="${APP_PORT_MIN:-8000}"
APP_MAX="${APP_PORT_MAX:-8099}"

log(){ echo "[bootstrap] $*"; }

# 1) apt --------------------------------------------------------------------
log "apt update + базовые пакеты"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq ca-certificates curl git ufw openssl >/dev/null

# 2) docker -----------------------------------------------------------------
if ! command -v docker >/dev/null 2>&1; then
  log "установка Docker Engine"
  curl -fsSL https://get.docker.com | sh >/dev/null
else
  log "Docker уже установлен: $(docker --version)"
fi
if ! docker compose version >/dev/null 2>&1; then
  log "установка docker compose plugin"
  apt-get install -y -qq docker-compose-plugin >/dev/null 2>&1 || true
fi
docker compose version >/dev/null 2>&1 || { echo "docker compose недоступен"; exit 1; }

# 3) firewall ---------------------------------------------------------------
# Важно: SSH (22) разрешаем ПЕРЕД включением ufw, иначе можно отрезать доступ.
if command -v ufw >/dev/null 2>&1; then
  log "firewall (ufw): 22, $WS_PORT, $FILE_PORT, $APP_MIN:$APP_MAX, $CADDY_HTTP, $CADDY_HTTPS"
  ufw allow 22/tcp >/dev/null 2>&1 || true
  ufw allow "${WS_PORT}/tcp"   >/dev/null 2>&1 || true
  ufw allow "${FILE_PORT}/tcp" >/dev/null 2>&1 || true
  ufw allow "${APP_MIN}:${APP_MAX}/tcp" >/dev/null 2>&1 || true
  ufw allow "${CADDY_HTTP}/tcp"  >/dev/null 2>&1 || true
  ufw allow "${CADDY_HTTPS}/tcp" >/dev/null 2>&1 || true
  ufw --force enable >/dev/null 2>&1 || true
else
  log "ufw нет — firewall пропущен (настрой вручную)"
fi

# 4) .env: IP + токен + TLS + порты -----------------------------------------
PUBLIC_IP="${SERVER_IP:-$(curl -fsS https://api.ipify.org 2>/dev/null || true)}"
[ -n "$PUBLIC_IP" ] || PUBLIC_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
TOKEN="${HEDGEHOG_TOKEN:-$(openssl rand -hex 32)}"
umask 077
cat > "$SCRIPT_DIR/.env" <<EOF
SERVER_IP=$PUBLIC_IP
HEDGEHOG_TOKEN=$TOKEN
HEDGEHOG_TLS=1
HEDGEHOG_WS_PORT=$WS_PORT
HEDGEHOG_FILE_PORT=$FILE_PORT
CADDY_HTTP_PORT=$CADDY_HTTP
CADDY_HTTPS_PORT=$CADDY_HTTPS
EOF
log "IP=$PUBLIC_IP, WS=$WS_PORT FILE=$FILE_PORT, токен сгенерирован, TLS файл-сервера включён"

# 5) up ---------------------------------------------------------------------
log "сборка и запуск стека (docker compose up -d --build)"
docker compose up -d --build

# 6) ждём Ёжика и считаем TLS-отпечаток -------------------------------------
# Отпечаток берём детерминированно из самого Ёжика (tls.fingerprint), а не
# парсингом лога.
log "ждём старт Ёжика…"
FP=""
for _ in $(seq 1 40); do
  if docker compose exec -T hedgehog test -f /data/tls/cert.pem 2>/dev/null; then
    FP="$(docker compose exec -T hedgehog python -c \
          'from hedgehog import tls; from hedgehog.config import Config; print(tls.fingerprint(Config().tls_cert_file))' \
          2>/dev/null | tr -d '\r\n')"
    [ -n "$FP" ] && break
  fi
  sleep 2
done
[ -n "$FP" ] || log "предупреждение: TLS-отпечаток не получен (проверь логи Ёжика)"

# 7) JSON коннекта ----------------------------------------------------------
echo "===HEDGEHOG_CONNECT_BEGIN==="
echo "{\"host\":\"$PUBLIC_IP\",\"ws_port\":$WS_PORT,\"file_port\":$FILE_PORT,\"token\":\"$TOKEN\",\"tls\":true,\"file_fingerprint\":\"$FP\"}"
echo "===HEDGEHOG_CONNECT_END==="
log "готово. Клиент подключается по данным выше (WS ws://$PUBLIC_IP:$WS_PORT)."
