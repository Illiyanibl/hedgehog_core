#!/usr/bin/env bash
# Ёжик — установка на сервер. Идемпотентно. Обычный docker (без compose):
# работает и со старым docker.io 20.10 из Debian-репо, где нет compose v2.
#
# Обычно запускается так (клиент «Добавить сервер» делает это по SSH):
#   apt-get install -y git
#   git clone --depth 1 https://github.com/Illiyanibl/hedgehog_core /opt/hedgehog
#   bash /opt/hedgehog/deploy/bootstrap.sh
#
# Порты хоста переопределяются env (для теста / занятых портов):
#   HEDGEHOG_WS_PORT (8765) HEDGEHOG_FILE_PORT (8767)
#   CADDY_HTTP_PORT (80) CADDY_HTTPS_PORT (443)
set -euo pipefail

[ "$(id -u)" = 0 ] || { echo "нужен root (sudo)"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
[ -f "$SCRIPT_DIR/caddy/Caddyfile" ] || { echo "не найден caddy/Caddyfile рядом со скриптом"; exit 1; }

WS_PORT="${HEDGEHOG_WS_PORT:-8765}"
FILE_PORT="${HEDGEHOG_FILE_PORT:-8767}"
CADDY_HTTP="${CADDY_HTTP_PORT:-80}"
CADDY_HTTPS="${CADDY_HTTPS_PORT:-443}"
APP_MIN="${APP_PORT_MIN:-8000}"
APP_MAX="${APP_PORT_MAX:-8099}"

NET=hedgehog-net
# Готовый образ из реестра (собирается в GitHub Actions) — на сервере не
# билдим, только pull. Переопределяется env HEDGEHOG_IMAGE (напр. для форка).
IMAGE="${HEDGEHOG_IMAGE:-ghcr.io/illiyanibl/hedgehog:latest}"

log(){ echo "[bootstrap] $*"; }

# 1) apt --------------------------------------------------------------------
log "apt update + базовые пакеты"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq ca-certificates curl git ufw openssl >/dev/null

# 2) docker (движок) --------------------------------------------------------
if ! command -v docker >/dev/null 2>&1; then
  log "установка Docker Engine (get.docker.com)"
  curl -fsSL https://get.docker.com | sh >/dev/null
else
  log "Docker уже установлен: $(docker --version)"
fi
# Демон может быть не запущен (свежий docker.io) — поднимаем.
systemctl enable --now docker >/dev/null 2>&1 || service docker start >/dev/null 2>&1 || true
docker info >/dev/null 2>&1 || { echo "docker демон недоступен"; exit 1; }

# 3) firewall ---------------------------------------------------------------
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

# 4) IP + токен -------------------------------------------------------------
PUBLIC_IP="${SERVER_IP:-$(curl -fsS https://api.ipify.org 2>/dev/null || true)}"
[ -n "$PUBLIC_IP" ] || PUBLIC_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
TOKEN="${HEDGEHOG_TOKEN:-$(openssl rand -hex 32)}"
log "IP=$PUBLIC_IP, WS=$WS_PORT FILE=$FILE_PORT, токен сгенерирован"

# 5) сеть + тома ------------------------------------------------------------
docker network create "$NET" >/dev/null 2>&1 || true
for v in hedgehog-data hedgehog-apps hedgehog-caddy-data hedgehog-caddy-config; do
  docker volume create "$v" >/dev/null 2>&1 || true
done

# 6) получение образа Ёжика (готовый из реестра, без сборки) ----------------
log "получение образа: $IMAGE"
docker pull "$IMAGE"

# 7) контейнеры (пересоздаём идемпотентно) ----------------------------------
log "запуск контейнеров"
docker rm -f hedgehog hedgehog-socket-proxy hedgehog-caddy >/dev/null 2>&1 || true

# socket-proxy: whitelist Docker API, сокет смонтирован ro. Порт наружу НЕ
# публикуется — доступен только контейнерам сети hedgehog-net.
docker run -d --name hedgehog-socket-proxy --restart unless-stopped \
  --network "$NET" \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -e INFO=1 -e VERSION=1 -e EVENTS=1 -e PING=1 \
  -e CONTAINERS=1 -e IMAGES=1 -e NETWORKS=1 -e VOLUMES=1 \
  -e POST=1 -e BUILD=1 -e EXEC=1 \
  tecnativa/docker-socket-proxy:0.3.0 >/dev/null

# Ёжик: WS/файлы наружу, docker — через прокси, тома данных и приложений.
docker run -d --name hedgehog --restart unless-stopped \
  --network "$NET" \
  -e DOCKER_HOST=tcp://hedgehog-socket-proxy:2375 \
  -e HEDGEHOG_HOST=0.0.0.0 -e HEDGEHOG_DEFAULT_CWD=/apps \
  -e HEDGEHOG_TOKEN="$TOKEN" -e HEDGEHOG_TLS=1 \
  -e APP_PORT_MIN="$APP_MIN" -e APP_PORT_MAX="$APP_MAX" \
  -e SERVER_IP="$PUBLIC_IP" -e APPS_VOLUME=hedgehog-apps \
  -p "${WS_PORT}:8765" -p "${FILE_PORT}:8767" \
  -v hedgehog-data:/data -v hedgehog-apps:/apps \
  "$IMAGE" >/dev/null

# Caddy: ingress :80/:443 (on-demand TLS, простаивает без домена).
docker run -d --name hedgehog-caddy --restart unless-stopped \
  --network "$NET" \
  -p "${CADDY_HTTP}:80" -p "${CADDY_HTTPS}:443" \
  -v "$SCRIPT_DIR/caddy/Caddyfile":/etc/caddy/Caddyfile:ro \
  -v hedgehog-caddy-data:/data -v hedgehog-caddy-config:/config \
  caddy:2.8 >/dev/null

# 8) ждём Ёжика и считаем TLS-отпечаток -------------------------------------
log "ждём старт Ёжика…"
FP=""
for _ in $(seq 1 40); do
  if docker exec hedgehog test -f /data/tls/cert.pem 2>/dev/null; then
    FP="$(docker exec hedgehog python -c \
          'from hedgehog import tls; from hedgehog.config import Config; print(tls.fingerprint(Config().tls_cert_file))' \
          2>/dev/null | tr -d '\r\n')"
    [ -n "$FP" ] && break
  fi
  sleep 2
done
[ -n "$FP" ] || log "предупреждение: TLS-отпечаток не получен (проверь: docker logs hedgehog)"

# 9) JSON коннекта ----------------------------------------------------------
echo "===HEDGEHOG_CONNECT_BEGIN==="
echo "{\"host\":\"$PUBLIC_IP\",\"ws_port\":$WS_PORT,\"file_port\":$FILE_PORT,\"token\":\"$TOKEN\",\"tls\":true,\"file_fingerprint\":\"$FP\"}"
echo "===HEDGEHOG_CONNECT_END==="
log "готово. Клиент подключается по данным выше (WS ws://$PUBLIC_IP:$WS_PORT)."
