# shellcheck shell=bash
# §deploy: общее ядро deploy-скриптов Ёžika (процесс-режим, без docker).
# Только функции — вызывающий сам делает `set -euo pipefail`. Не дублировать
# установку/запуск: source-ится из selfsetup.sh. (install-in-container.sh пока
# самостоятелен — переход на этот lib оставлен отдельным тех-долгом, чтобы не
# трогать рабочий app-driven путь.)

hh_log(){ echo "[$1] $2"; }

# apt-зависимости для процесс-режима (без docker).
hh_install_deps(){
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq python3 python3-venv python3-pip git curl ca-certificates openssl >/dev/null
}

# claude CLI (идемпотентно).
hh_install_claude(){
  if ! command -v claude >/dev/null 2>&1; then
    curl -fsSL https://claude.ai/install.sh | bash >/dev/null
    ln -sf "$HOME/.local/bin/claude" /usr/local/bin/claude 2>/dev/null || true
  fi
}

# venv + зависимости Ёžika.
hh_make_venv(){ # <src_dir>
  local src="$1"
  python3 -m venv "$src/.venv"
  "$src/.venv/bin/pip" install -q -r "$src/requirements.txt"
}

# Пишет run-loop.sh (supervisor-loop) с env и правами 600 — ВНУТРИ Bearer-токен,
# поэтому не 755 (иначе токен читаем другими пользователями машины).
hh_write_runloop(){ # <src> <data_dir> <ws> <file_port> <tls01> <token> [extra_env]
  local src="$1" data="$2" ws="$3" fport="$4" tls="$5" tok="$6" extra="${7:-}"
  cat > "$src/run-loop.sh" <<EOF
#!/usr/bin/env bash
export HEDGEHOG_HOST=0.0.0.0
export HEDGEHOG_PORT=$ws
export HEDGEHOG_FILE_PORT=$fport
export HEDGEHOG_DATA_DIR="$data"
export HEDGEHOG_TOKEN="$tok"
export HEDGEHOG_TLS=$tls$extra
cd "$src"
while true; do
  .venv/bin/python -m hedgehog.main >> "$data/hedgehog.log" 2>&1 || true
  sleep 3
done
EOF
  chmod 600 "$src/run-loop.sh"
}

# Перезапуск supervisor-loop (нет init в контейнере — держим через setsid nohup).
hh_start_supervised(){ # <src_dir>
  local src="$1"
  pkill -f "hedgehog.main" 2>/dev/null || true
  pkill -f "run-loop.sh"   2>/dev/null || true
  sleep 1
  setsid nohup "$src/run-loop.sh" >/dev/null 2>&1 &
  sleep 4
}

# Ждёт серт и печатает SHA-256 отпечаток (stdout). Пусто, если не дождались.
# Отпечаток берём штатной утилитой adminctl (ensure_cert идемпотентно, тот же
# серт, что слушают 8765/8767).
hh_wait_fingerprint(){ # <src_dir> <data_dir>
  local src="$1" data="$2" fp="" i
  for i in $(seq 1 30); do
    if [ -f "$data/tls/cert.pem" ]; then
      fp="$(cd "$src" && HEDGEHOG_DATA_DIR="$data" \
            .venv/bin/python -m hedgehog.adminctl fingerprint 2>/dev/null | tr -d '\r\n')"
      [ -n "$fp" ] && break
    fi
    sleep 2
  done
  printf '%s' "$fp"
}

# Публичный адрес Ёžika (без явного host в настройках): SERVER_IP → ipify →
# hostname -I (последнее почти всегда внутренний адрес — крайний фолбэк).
hh_detect_host(){
  local h="${SERVER_IP:-}"
  [ -n "$h" ] || h="$(curl -fsS https://api.ipify.org 2>/dev/null || true)"
  [ -n "$h" ] || h="$(hostname -I 2>/dev/null | awk '{print $1}')"
  printf '%s' "$h"
}
