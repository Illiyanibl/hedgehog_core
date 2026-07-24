#!/usr/bin/env bash
# Ёжик ПРЯМО в готовый контейнер — процессом, БЕЗ docker внутри.
# (Режим «В контейнер»: у пользователя уже есть контейнер, порты он
# пробрасывает сам. Приложения соседними контейнерами тут недоступны —
# нет docker; это осознанное ограничение режима.)
#
# Запускается по SSH внутрь контейнера:
#   apt-get update && apt-get install -y git
#   git clone --depth 1 https://github.com/Illiyanibl/hedgehog_core /opt/hedgehog-src
#   bash /opt/hedgehog-src/deploy/install-in-container.sh
#
# Порты (Ёжик слушает их ВНУТРИ контейнера; наружу пробрасывает пользователь):
#   HEDGEHOG_WS_PORT (8765) HEDGEHOG_FILE_PORT (8767)
set -euo pipefail

WS_PORT="${HEDGEHOG_WS_PORT:-8765}"
FILE_PORT="${HEDGEHOG_FILE_PORT:-8767}"
DATA_DIR="${HEDGEHOG_DATA_DIR:-/opt/hedgehog-data}"
SRC_DIR="$(cd "$(dirname "$0")/.." && pwd)"   # корень клонированного репо

log(){ echo "[install] $*"; }

# 1) зависимости --------------------------------------------------------------
export DEBIAN_FRONTEND=noninteractive
log "apt: python3, git, curl, openssl"
apt-get update -qq
apt-get install -y -qq python3 python3-venv python3-pip git curl ca-certificates openssl >/dev/null

# 2) claude CLI ---------------------------------------------------------------
if ! command -v claude >/dev/null 2>&1; then
  log "установка claude CLI"
  curl -fsSL https://claude.ai/install.sh | bash >/dev/null
  ln -sf "$HOME/.local/bin/claude" /usr/local/bin/claude 2>/dev/null || true
fi

# 3) venv + зависимости Ёжика -------------------------------------------------
log "venv + pip"
python3 -m venv "$SRC_DIR/.venv"
"$SRC_DIR/.venv/bin/pip" install -q -r "$SRC_DIR/requirements.txt"

# 4) IP + токен ---------------------------------------------------------------
mkdir -p "$DATA_DIR"
PUBLIC_IP="${SERVER_IP:-$(curl -fsS https://api.ipify.org 2>/dev/null || true)}"
[ -n "$PUBLIC_IP" ] || PUBLIC_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
TOKEN="${HEDGEHOG_TOKEN:-$(openssl rand -hex 32)}"

# 5) supervisor-loop (respawn процесса) --------------------------------------
# Нет systemd в контейнере — держим Ёжика простым while-loop через nohup.
# ВНИМАНИЕ: при РЕСТАРТЕ контейнера процесс не поднимется сам (нет init) —
# тогда переустанови или добавь запуск run-loop.sh в entrypoint контейнера.
cat > "$SRC_DIR/run-loop.sh" <<EOF
#!/usr/bin/env bash
export HEDGEHOG_HOST=0.0.0.0
export HEDGEHOG_PORT=$WS_PORT
export HEDGEHOG_FILE_PORT=$FILE_PORT
export HEDGEHOG_DATA_DIR=$DATA_DIR
export HEDGEHOG_TOKEN=$TOKEN
export HEDGEHOG_TLS=1
cd "$SRC_DIR"
while true; do
  .venv/bin/python -m hedgehog.main >> "$DATA_DIR/hedgehog.log" 2>&1 || true
  sleep 3
done
EOF
chmod +x "$SRC_DIR/run-loop.sh"

log "запуск Ёжика (WS=$WS_PORT FILE=$FILE_PORT)"
pkill -f "hedgehog.main" 2>/dev/null || true
pkill -f "run-loop.sh"   2>/dev/null || true
sleep 1
setsid nohup "$SRC_DIR/run-loop.sh" >/dev/null 2>&1 &
sleep 4

# 6) ждём старт и считаем TLS-отпечаток ---------------------------------------
FP=""
for _ in $(seq 1 30); do
  if [ -f "$DATA_DIR/tls/cert.pem" ]; then
    FP="$(HEDGEHOG_DATA_DIR="$DATA_DIR" "$SRC_DIR/.venv/bin/python" -c \
          'from hedgehog import tls; from hedgehog.config import Config; print(tls.fingerprint(Config().tls_cert_file))' \
          2>/dev/null | tr -d '\r\n')"
    [ -n "$FP" ] && break
  fi
  sleep 2
done
[ -n "$FP" ] || log "предупреждение: TLS-отпечаток не получен (см. $DATA_DIR/hedgehog.log)"

# 7) JSON коннекта ------------------------------------------------------------
echo "===HEDGEHOG_CONNECT_BEGIN==="
echo "{\"host\":\"$PUBLIC_IP\",\"ws_port\":$WS_PORT,\"file_port\":$FILE_PORT,\"token\":\"$TOKEN\",\"tls\":true,\"file_fingerprint\":\"$FP\"}"
echo "===HEDGEHOG_CONNECT_END==="
log "готово. Проброс портов $WS_PORT/$FILE_PORT наружу — на твоей стороне."
