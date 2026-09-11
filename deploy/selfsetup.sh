#!/usr/bin/env bash
# §selfsetup: автономная установка Ёžika ВНУТРИ уже готового контейнера + выгрузка
# файла-конфига РОВНО в формате импорта iOS-клиента (кнопка «Загрузить конфигурацию»).
#
# Сценарий: клонируешь открытый репозиторий, запускаешь этот скрипт внутри своего
# контейнера, забираешь итоговый файл (по scp/sftp) и открываешь его в приложении.
# Docker и SSH-параметры НЕ нужны — скрипт уже в целевом контейнере.
#
#   apt-get update && apt-get install -y git
#   git clone --depth 1 https://github.com/Illiyanibl/hedgehog_core /opt/hedgehog-src
#   bash /opt/hedgehog-src/deploy/selfsetup.sh            # настройки: deploy/selfsetup.json
#   bash /opt/hedgehog-src/deploy/selfsetup.sh my.json    # своя копия настроек
set -euo pipefail

SRC_DIR="$(cd "$(dirname "$0")/.." && pwd)"          # корень клонированного репо
SETTINGS="${1:-$SRC_DIR/deploy/selfsetup.json}"
# shellcheck source=lib/core.sh
. "$SRC_DIR/deploy/lib/core.sh"

log(){ hh_log selfsetup "$*"; }

[ -f "$SETTINGS" ] || { echo "нет файла настроек: $SETTINGS"; exit 1; }

# 1) python3 — нужен для парса настроек (ставим первым, apt быстрый) ---------
log "apt: python3/venv/pip/git/curl/openssl"
hh_install_deps

# 2) читаем настройки СРАЗУ после python3 — ДО медленных claude/venv: fail-fast
#    на битом JSON. Присваивание в переменную (не прямой eval) пробрасывает
#    статус python в set -e; значения санитайзятся shlex.quote.
PARSED="$(python3 - "$SETTINGS" <<'PY'
import json, sys, shlex
try:
    c = json.load(open(sys.argv[1]))
except Exception as e:
    print(f"selfsetup: не читается JSON настроек: {e}", file=sys.stderr)
    sys.exit(2)
if c.get("kind") != "devolution-hedgehog-setup":
    print("selfsetup: не файл настроек (ожидался kind=devolution-hedgehog-setup)",
          file=sys.stderr)
    sys.exit(2)
p = c.get("ports") or {}
def d(k, dflt):
    v = c.get(k)
    return dflt if v is None else v
out = {
    "HH_HOST":    c.get("host") or "",
    "HH_DOMAIN":  c.get("domain") or "",
    "HH_TLS":     "1" if c.get("tls", True) else "0",
    "HH_TOKEN_SET": c.get("token") or "",
    "HH_DATA":    d("data_dir", "/opt/hedgehog-data"),
    "HH_BROWSE":  d("browse_root", "/"),
    "HH_DEFCWD":  c.get("default_cwd") or "",
    "HH_OUT":     c.get("out_file") or "",
    "HH_WS":      str(p.get("hedgehog") or 8765),
    "HH_FILE":    str(p.get("file") or 8767),
}
for k, v in out.items():
    print(f"{k}={shlex.quote(str(v))}")
PY
)" || { echo "битые настройки: $SETTINGS"; exit 1; }
eval "$PARSED"

# 3) медленное: claude CLI + venv -------------------------------------------
log "claude CLI"
hh_install_claude
log "venv + зависимости Ёžika"
hh_make_venv "$SRC_DIR"

# 4) токен (из настроек или сгенерировать) ----------------------------------
HH_TOKEN="${HH_TOKEN_SET:-$(openssl rand -hex 32)}"

# 5) каталог данных 700 + run-loop.sh (600, токен внутри) + запуск ----------
mkdir -p "$HH_DATA"
chmod 700 "$HH_DATA" 2>/dev/null || true
EXTRA=""
[ -n "$HH_BROWSE" ] && EXTRA="$EXTRA"$'\n'"export HEDGEHOG_BROWSE_ROOT=\"$HH_BROWSE\""
[ -n "$HH_DEFCWD" ] && EXTRA="$EXTRA"$'\n'"export HEDGEHOG_DEFAULT_CWD=\"$HH_DEFCWD\""
log "run-loop.sh (TLS=$HH_TLS, WS=$HH_WS FILE=$HH_FILE)"
hh_write_runloop "$SRC_DIR" "$HH_DATA" "$HH_WS" "$HH_FILE" "$HH_TLS" "$HH_TOKEN" "$EXTRA"
log "запуск Ёžika"
hh_start_supervised "$SRC_DIR"

# 6) отпечаток TLS (сквозной флаг: только при tls) --------------------------
FP=""
if [ "$HH_TLS" = "1" ]; then
  log "жду серт, снимаю отпечаток…"
  FP="$(hh_wait_fingerprint "$SRC_DIR" "$HH_DATA")"
  [ -n "$FP" ] || log "ПРЕДУПРЕЖДЕНИЕ: отпечаток не получен (см. $HH_DATA/hedgehog.log)"
fi

# 7) публичный host (host из настроек предпочтителен) -----------------------
if [ -n "$HH_HOST" ]; then
  HOST="$HH_HOST"; HOST_AUTO=0
else
  HOST="$(hh_detect_host)"; HOST_AUTO=1
fi
[ -n "$HOST" ] || { echo "не удалось определить host — впиши host в $SETTINGS"; exit 1; }

# 8) клиентский файл РОВНО в формате ServerConfigFile (json.dumps: числовые
#    порты, bool tls, корректное экранирование) ------------------------------
OUT="$HH_OUT"
if [ -z "$OUT" ]; then
  SAFE="$(printf '%s' "$HOST" | sed 's/[^A-Za-z0-9._-]/_/g')"
  OUT="$HH_DATA/hedgehog-$SAFE.json"
fi
python3 - "$OUT" "$HOST" "$HH_WS" "$HH_FILE" "$HH_TLS" "$FP" "$HH_DOMAIN" "$HH_TOKEN" <<'PY'
import json, sys
out, host, ws, fport, tls, fp, domain, token = sys.argv[1:9]
cfg = {
    "kind": "devolution-hedgehog-server",
    "version": 1,
    "host": host,
    "hedgehogPort": int(ws),
    "filePort": int(fport),
    "tls": tls == "1",
    "token": token,
}
if tls == "1" and fp:
    cfg["tlsFingerprint"] = fp
if domain:
    cfg["domain"] = domain
with open(out, "w") as f:
    json.dump(cfg, f, indent=2, ensure_ascii=False)
PY
chmod 600 "$OUT"

# 9) итог -------------------------------------------------------------------
echo
echo "============================================================"
echo "  Ёžik установлен и запущен."
echo "  Файл-конфиг для клиента (кнопка «Загрузить конфигурацию»):"
echo "    $OUT"
echo
if [ "$HH_TLS" = "1" ]; then
  echo "  TLS: wss + пиннинг; SHA-256 отпечаток серта внутри файла."
  [ -n "$FP" ] || echo "  ⚠ отпечаток пуст — сервер не поднялся? см. $HH_DATA/hedgehog.log"
else
  echo "  TLS: ВЫКЛЮЧЕН (plaintext ws:// — только за доверенным SSH-туннелем)."
fi
if [ "$HOST_AUTO" = "1" ]; then
  echo "  ⚠ host определён автоматически: $HOST"
  echo "    Проверь, что он достижим с телефона; при NAT/прокси впиши host в $SETTINGS."
fi
echo
echo "  Файл содержит Bearer-токен + отпечаток = ПОЛНЫЙ доступ к серверу."
echo "  Переноси только по защищённому каналу (scp/sftp), НЕ по открытому FTP."
echo "============================================================"
