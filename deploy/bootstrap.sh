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

# --- прогресс установки (§install-progress) --------------------------------
# Пишем ход в файлы, чтобы клиент опрашивал установку даже после разрыва SSH.
# Каталог состояния задаёт loader через HEDGEHOG_INSTALL_STATE:
#   progress  — строки STEP:<key>:<begin|ok|fail>
#   log       — полный stdout/stderr (перенаправляет loader)
#   status    — running|ok|fail
#   result.json — JSON коннекта (на успехе)
STATE="${HEDGEHOG_INSTALL_STATE:-}"
CURSTEP=""
mark(){ CURSTEP="$1"; [ -n "$STATE" ] && echo "STEP:$1:$2" >> "$STATE/progress" 2>/dev/null || true; }
on_err(){
  [ -n "$STATE" ] && { echo "STEP:${CURSTEP}:fail" >> "$STATE/progress" 2>/dev/null; echo fail > "$STATE/status" 2>/dev/null; }
  log "ошибка на шаге '${CURSTEP}'"
  return 0
}
trap on_err ERR

# 0) DNS (§install-dns) ------------------------------------------------------
# Явные резолверы Google + Cloudflare: часть VPS приезжает со сломанным DNS,
# из-за чего падают apt/git/docker pull. Правим хост И docker-демон.
mark dns begin
log "DNS: 8.8.8.8, 8.8.4.4, 1.1.1.1 (хост + docker)"
for ns in 8.8.8.8 8.8.4.4 1.1.1.1; do
  grep -q "$ns" /etc/resolv.conf 2>/dev/null || echo "nameserver $ns" >> /etc/resolv.conf 2>/dev/null || true
done
if systemctl is-active systemd-resolved >/dev/null 2>&1; then
  mkdir -p /etc/systemd/resolved.conf.d
  printf '[Resolve]\nDNS=8.8.8.8 1.1.1.1 8.8.4.4\nFallbackDNS=8.8.4.4\n' \
    > /etc/systemd/resolved.conf.d/hedgehog.conf
  systemctl restart systemd-resolved >/dev/null 2>&1 || true
fi
mkdir -p /etc/docker
if [ ! -f /etc/docker/daemon.json ]; then
  printf '{\n  "dns": ["8.8.8.8", "1.1.1.1", "8.8.4.4"]\n}\n' > /etc/docker/daemon.json
  # docker уже запущен (идемпотентный повтор) — применяем dns рестартом.
  { command -v docker >/dev/null 2>&1 && systemctl restart docker >/dev/null 2>&1; } || true
else
  grep -q '"dns"' /etc/docker/daemon.json || log "daemon.json без dns — не трогаю чужой конфиг"
fi
mark dns ok

# 1) apt --------------------------------------------------------------------
mark packages begin
log "apt update + базовые пакеты"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq ca-certificates curl git ufw openssl fail2ban >/dev/null
mark packages ok

# 2) docker (движок) --------------------------------------------------------
mark docker begin
if ! command -v docker >/dev/null 2>&1; then
  log "установка Docker Engine (get.docker.com)"
  curl -fsSL https://get.docker.com | sh >/dev/null
else
  log "Docker уже установлен: $(docker --version)"
fi
# Демон может быть не запущен (свежий docker.io) — поднимаем.
systemctl enable --now docker >/dev/null 2>&1 || service docker start >/dev/null 2>&1 || true
docker info >/dev/null 2>&1 || { echo "docker демон недоступен"; exit 1; }
mark docker ok

# 3) firewall ---------------------------------------------------------------
mark firewall begin
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
mark firewall ok

# 4) IP + токен -------------------------------------------------------------
PUBLIC_IP="${SERVER_IP:-$(curl -fsS https://api.ipify.org 2>/dev/null || true)}"
[ -n "$PUBLIC_IP" ] || PUBLIC_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
TOKEN="${HEDGEHOG_TOKEN:-$(openssl rand -hex 32)}"
log "IP=$PUBLIC_IP, WS=$WS_PORT FILE=$FILE_PORT, токен сгенерирован"

# 5) сеть + тома ------------------------------------------------------------
mark network begin
docker network create "$NET" >/dev/null 2>&1 || true
for v in hedgehog-data hedgehog-apps hedgehog-caddy-data hedgehog-caddy-config; do
  docker volume create "$v" >/dev/null 2>&1 || true
done
mark network ok

# 6) получение образа Ёжика (готовый из реестра, без сборки) ----------------
mark image begin
log "получение образа: $IMAGE"
docker pull "$IMAGE"
mark image ok

# 7) контейнеры (пересоздаём идемпотентно) ----------------------------------
mark containers begin
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
mark containers ok

# 7.5) fail2ban -------------------------------------------------------------
mark fail2ban begin
# Баним перебор: SSH (парольный вход) + токен Ёжика. Реальный IP атакующего
# Ёжик берёт из TCP-пира и пишет в auth_failures.log (том hedgehog-data → виден
# с хоста). ВАЖНО: порты Ёжика публикует Docker, трафик идёт через FORWARD, а не
# INPUT — поэтому bans для Ёжика вставляем в цепочку DOCKER-USER (иначе не
# сработают). SSH банится штатно в INPUT.
if command -v fail2ban-server >/dev/null 2>&1; then
  log "fail2ban: filter + jail (sshd + hedgehog → DOCKER-USER)"
  AUTHLOG=/var/lib/docker/volumes/hedgehog-data/_data/auth_failures.log
  mkdir -p "$(dirname "$AUTHLOG")" 2>/dev/null || true
  touch "$AUTHLOG" 2>/dev/null || true
  cat > /etc/fail2ban/filter.d/hedgehog.conf <<'FILTER'
# Матчит строки auth_failures.log Ёжика: "<iso> auth-failed ip=<IP> svc=ws|file …"
[Definition]
failregex = ^.*\bauth-failed ip=<HOST> svc=(ws|file)\b
ignoreregex =
FILTER
  cat > /etc/fail2ban/jail.d/hedgehog.conf <<JAIL
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 6

# SSH — классический бан перебора пароля (в INPUT, штатно).
[sshd]
enabled = true

# Порты Ёжика (WS/файлы) — бан в DOCKER-USER, т.к. трафик к контейнеру идёт
# мимо INPUT. iptables-allports блокирует IP целиком.
[hedgehog]
enabled  = true
filter   = hedgehog
logpath  = $AUTHLOG
port     = ${WS_PORT},${FILE_PORT}
maxretry = 8
findtime = 5m
bantime  = 1h
action   = iptables-allports[name=hedgehog, chain="DOCKER-USER"]
JAIL
  systemctl enable fail2ban >/dev/null 2>&1 || true
  { systemctl restart fail2ban || service fail2ban restart; } >/dev/null 2>&1 || \
    log "предупреждение: не удалось перезапустить fail2ban (проверь вручную)"
else
  log "fail2ban не установлен — бан перебора пропущен"
fi
mark fail2ban ok

# 8) ждём Ёжика и считаем TLS-отпечаток -------------------------------------
mark tls begin
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
mark tls ok

# 9) JSON коннекта ----------------------------------------------------------
CONNECT_JSON="{\"host\":\"$PUBLIC_IP\",\"ws_port\":$WS_PORT,\"file_port\":$FILE_PORT,\"token\":\"$TOKEN\",\"tls\":true,\"file_fingerprint\":\"$FP\"}"
# §install-progress: результат + финальный статус для опроса клиентом.
if [ -n "$STATE" ]; then
  printf '%s\n' "$CONNECT_JSON" > "$STATE/result.json" 2>/dev/null || true
  echo ok > "$STATE/status" 2>/dev/null || true
fi
# Старые маркеры оставляем (обратная совместимость / ручная отладка по SSH).
echo "===HEDGEHOG_CONNECT_BEGIN==="
echo "$CONNECT_JSON"
echo "===HEDGEHOG_CONNECT_END==="
log "готово. Клиент подключается по данным выше (WS ws://$PUBLIC_IP:$WS_PORT)."
