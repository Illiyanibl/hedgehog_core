# shellcheck shell=bash
# §deploy: общее ядро deploy-скриптов Ёžika (процесс-режим, без docker).
# Только функции — вызывающий сам делает `set -euo pipefail`. Не дублировать
# установку/запуск: source-ится из selfsetup.sh. (install-in-container.sh пока
# самостоятелен — переход на этот lib оставлен отдельным тех-долгом, чтобы не
# трогать рабочий app-driven путь.)

hh_log(){ echo "[$1] $2"; }

# D1: single-quote + escape для безопасной подстановки значения в генерируемый
# shell-скрипт. Значения конфига (data_dir/token/browse_root/…) могут содержать
# $(...)/$VAR — без этого они исполнились бы при запуске run-loop.sh (вторичная
# shell-инъекция «конфиг = код»). `a'b` → `'a'\''b'`.
hh_shq(){ local s=$1; s=${s//\'/\'\\\'\'}; printf "'%s'" "$s"; }

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
  # D1: все значения — через hh_shq (одиночные кавычки + экранирование), чтобы
  # `$(...)`/`$VAR` в data_dir/token и т.п. НЕ исполнялись при запуске run-loop.sh.
  # $extra (блок export'ов) формирует вызывающий — он тоже обязан экранировать
  # значения (см. selfsetup.sh). Порты/tls тоже квотим — дёшево и безопасно.
  local q_src q_data q_tok q_ws q_fp q_tls
  q_src=$(hh_shq "$src"); q_data=$(hh_shq "$data"); q_tok=$(hh_shq "$tok")
  q_ws=$(hh_shq "$ws"); q_fp=$(hh_shq "$fport"); q_tls=$(hh_shq "$tls")
  cat > "$src/run-loop.sh" <<EOF
#!/usr/bin/env bash
export HEDGEHOG_HOST=0.0.0.0
export HEDGEHOG_PORT=$q_ws
export HEDGEHOG_FILE_PORT=$q_fp
export HEDGEHOG_DATA_DIR=$q_data
export HEDGEHOG_TOKEN=$q_tok
export HEDGEHOG_TLS=$q_tls$extra
cd $q_src
while true; do
  .venv/bin/python -m hedgehog.main >> $q_data/hedgehog.log 2>&1 || true
  sleep 3
done
EOF
  chmod 600 "$src/run-loop.sh"
}

# Перезапуск supervisor-loop (нет init в контейнере — держим через setsid nohup).
# D1: запускаем через `bash <файл>`, а НЕ напрямую — run-loop.sh лежит с правами
# 600 (внутри Bearer-токен), прямой execve без x-бита дал бы EACCES даже под root
# и установка «молча» падала. Возврат 1, если supervisor не поднялся (health-gate;
# pgrep недоступен в чистом контейнере — проверяем живость по PID через kill -0).
# ВАЖНО: звать только из скрипта (не из интерактивного шелла) — иначе фоновая job
# станет лидером группы, setsid форкнет и $! укажет на мёртвую обёртку.
hh_start_supervised(){ # <src_dir>
  local src="$1"
  pkill -f "hedgehog.main" 2>/dev/null || true
  pkill -f "run-loop.sh"   2>/dev/null || true
  sleep 1
  setsid nohup bash "$src/run-loop.sh" >/dev/null 2>&1 &
  local pid=$!
  sleep 4
  if ! kill -0 "$pid" 2>/dev/null; then
    echo "run-loop.sh не поднялся (pid $pid мёртв)" >&2
    return 1
  fi
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
