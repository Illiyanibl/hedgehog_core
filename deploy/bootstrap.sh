#!/usr/bin/env bash
# Ёжик — установка на новый сервер (Фаза 2). Идемпотентно.
#
#   sudo bash deploy/bootstrap.sh
#
# Что делает:
#   1) apt update + базовые пакеты
#   2) ставит Docker Engine + compose plugin (если ещё нет)
#   3) firewall (ufw): SSH + 8765/8767 (Ёжик) + 8000-8099 (приложения) + 80/443
#   4) генерит bearer-токен, определяет публичный IP → deploy/.env
#   5) docker compose up -d --build (Ёжик + socket-proxy + Caddy)
#   6) печатает JSON коннекта для клиента (host/порты/токен/TLS-отпечаток)
#
# Запускается ИЗ доставленного дерева репозитория (клиент «Добавить сервер»
# заливает его по SSH, Фаза 3). Скрипт сам находит deploy/docker-compose.yml.
set -euo pipefail

[ "$(id -u)" = 0 ] || { echo "нужен root (sudo)"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
COMPOSE="$SCRIPT_DIR/docker-compose.yml"
[ -f "$COMPOSE" ] || { echo "не найден $COMPOSE"; exit 1; }
# Работаем из deploy/: compose сам подхватит ./.env и относительные пути
# (context: .. → корень репо, ./caddy/Caddyfile).
cd "$SCRIPT_DIR"

WS_PORT="${WS_PORT:-8765}"
FILE_PORT="${FILE_PORT:-8767}"
APP_MIN="${APP_PORT_MIN:-8000}"
APP_MAX="${APP_PORT_MAX:-8099}"

log(){ echo "[bootstrap] $*"; }

# 1) apt --------------------------------------------------------------------
log "apt update + базовые пакеты"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq ca-certificates curl git ufw openssl fail2ban >/dev/null

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
# Важно: SSH (22) разрешаем ПЕРЕД включением ufw, иначе можно отрезать себе доступ.
if command -v ufw >/dev/null 2>&1; then
  log "firewall (ufw): 22, $WS_PORT, $FILE_PORT, $APP_MIN:$APP_MAX, 80, 443"
  ufw allow 22/tcp >/dev/null 2>&1 || true
  ufw allow "${WS_PORT}/tcp"  >/dev/null 2>&1 || true
  ufw allow "${FILE_PORT}/tcp" >/dev/null 2>&1 || true
  ufw allow "${APP_MIN}:${APP_MAX}/tcp" >/dev/null 2>&1 || true
  ufw allow 80/tcp  >/dev/null 2>&1 || true
  ufw allow 443/tcp >/dev/null 2>&1 || true
  ufw --force enable >/dev/null 2>&1 || true
else
  log "ufw нет — firewall пропущен (настрой вручную)"
fi

# 4) .env: IP + токен + TLS -------------------------------------------------
PUBLIC_IP="${SERVER_IP:-$(curl -fsS https://api.ipify.org 2>/dev/null || true)}"
[ -n "$PUBLIC_IP" ] || PUBLIC_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
TOKEN="${HEDGEHOG_TOKEN:-$(openssl rand -hex 32)}"
umask 077
cat > "$SCRIPT_DIR/.env" <<EOF
SERVER_IP=$PUBLIC_IP
HEDGEHOG_TOKEN=$TOKEN
HEDGEHOG_TLS=1
EOF
log "IP=$PUBLIC_IP, токен сгенерирован, TLS файл-сервера включён"

# 5) up ---------------------------------------------------------------------
log "сборка и запуск стека (docker compose up -d --build)"
docker compose up -d --build

# 5.5) fail2ban -------------------------------------------------------------
# Баним перебор: SSH (парольный вход) + токен Ёжика. Реальный IP атакующего
# Ёжик берёт из TCP-пира и пишет в auth_failures.log (том /data → виден с
# хоста). ВАЖНО: порты Ёжика публикует Docker, трафик идёт через FORWARD, а не
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

# 6) ждём Ёжика и считаем TLS-отпечаток -------------------------------------
# Отпечаток берём детерминированно из самого Ёжика (tls.fingerprint), а не
# парсингом лога — формат лога может меняться.
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
