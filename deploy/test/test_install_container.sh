#!/usr/bin/env bash
# Интеграционный тест установки «В контейнер» (§install-progress).
#
# Поднимает чистый debian-контейнер и прогоняет install-in-container.sh ровно
# тем же контрактом, что и iOS-клиент (BootstrapService): отсоединённый запуск
# через setsid + pid-файл, опрос состояния (status/pid-liveness/progress/
# result.json/log). Проверяет:
#   • маркеры шагов STEP:<key>:<begin|ok> в правильном порядке;
#   • liveness через `kill -0 pid` (без procps/pgrep) — HH_ALIVE=1 во время работы;
#   • финальный status=ok + валидный result.json (host/порты/токен/fingerprint);
#   • файл-сервер реально слушает и презентует серт с тем же fingerprint.
#
# Использование:  deploy/test/test_install_container.sh
# Требует: docker + сеть (apt/pip/claude CLI ставятся внутри контейнера).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
IMAGE="${TEST_IMAGE:-debian:12}"
CNAME="hh-install-test-$$"
STATE=/opt/hedgehog-install
WS_PORT=8765
FILE_PORT=8767
TIMEOUT_S="${TEST_TIMEOUT:-600}"
EXPECTED_STEPS="prepare dns packages claude venv hedgehog tls"

pass(){ echo "  ✅ $*"; }
fail(){ echo "  ❌ $*"; FAILED=1; }
FAILED=0

command -v docker >/dev/null 2>&1 || { echo "SKIP: docker недоступен"; exit 0; }

cleanup(){ docker rm -f "$CNAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "== 1. Контейнер $IMAGE =="
docker run -d --name "$CNAME" "$IMAGE" sleep infinity >/dev/null
# Пред-apt НЕ делаем: весь apt — внутри run.sh (как у клиентского loader), иначе
# гонка за apt-lock. Egress проверит сам run.sh (prepare: apt-get update).
docker cp "$REPO_ROOT" "$CNAME:/opt/hedgehog-src" >/dev/null
echo "  репозиторий скопирован в /opt/hedgehog-src"

echo "== 2. Запуск установки (detached + pid, как клиент) =="
# run.sh мирит клиентский loader: pid-файл + prepare + локальный install-скрипт
# (клонирование пропускаем — тестируем рабочее дерево, а не origin). Генерируем
# во временный файл и docker cp — надёжнее вложенного heredoc через docker exec.
# Heredoc UNquoted: $STATE/$WS_PORT/$FILE_PORT подставляются тут; \$\$ и \$1 —
# остаются литералами для рантайма.
RUNSH="$(mktemp)"
cat > "$RUNSH" <<RUNEOF
#!/usr/bin/env bash
set +e
STATE=$STATE
echo \$\$ > "\$STATE/pid"
step(){ echo "STEP:\$1:\$2" >> "\$STATE/progress"; }
fail(){ step "\$1" fail; echo fail > "\$STATE/status"; exit 1; }
export DEBIAN_FRONTEND=noninteractive
step prepare begin
apt-get update -qq || fail prepare
apt-get install -y -qq git || fail prepare
step prepare ok
HEDGEHOG_INSTALL_STATE="\$STATE" HEDGEHOG_WS_PORT=$WS_PORT HEDGEHOG_FILE_PORT=$FILE_PORT bash /opt/hedgehog-src/deploy/install-in-container.sh
RUNEOF
docker exec "$CNAME" mkdir -p "$STATE"
docker cp "$RUNSH" "$CNAME:$STATE/run.sh" >/dev/null
rm -f "$RUNSH"
docker exec "$CNAME" bash -c "
: > $STATE/log; : > $STATE/progress; rm -f $STATE/result.json $STATE/pid
echo running > $STATE/status
chmod +x $STATE/run.sh
if command -v setsid >/dev/null 2>&1; then setsid bash $STATE/run.sh </dev/null >>$STATE/log 2>&1 &
else nohup bash $STATE/run.sh </dev/null >>$STATE/log 2>&1 & fi
" >/dev/null

echo "== 3. Опрос состояния (liveness = kill -0 pid) =="
alive_seen=0
st=running
elapsed=0
while [ "$elapsed" -lt "$TIMEOUT_S" ]; do
  st=$(docker exec "$CNAME" cat "$STATE/status" 2>/dev/null || echo "?")
  alive=$(docker exec "$CNAME" bash -c "kill -0 \"\$(cat $STATE/pid 2>/dev/null)\" 2>/dev/null && echo 1 || echo 0")
  [ "$alive" = "1" ] && alive_seen=1
  printf "  [%03ds] status=%s alive=%s\n" "$elapsed" "$st" "$alive"
  [ "$st" = "ok" ] || [ "$st" = "fail" ] && break
  sleep 5; elapsed=$((elapsed+5))
done

progress=$(docker exec "$CNAME" cat "$STATE/progress" 2>/dev/null || true)
result=$(docker exec "$CNAME" cat "$STATE/result.json" 2>/dev/null || true)

echo "== 4. Проверки =="
# liveness работал без procps
[ "$alive_seen" = "1" ] && pass "liveness (kill -0 pid) наблюдался во время установки" \
  || fail "liveness ни разу не был 1 (pid-файл/kill -0 сломаны)"

# статус ok
[ "$st" = "ok" ] && pass "status=ok" || fail "status=$st (ожидался ok)"

# все шаги дошли до ok в правильном порядке
order_ok=1; prev=-1
for key in $EXPECTED_STEPS; do
  echo "$progress" | grep -q "STEP:$key:ok" || { fail "нет STEP:$key:ok"; order_ok=0; }
done
# порядок: индексы :ok идут по возрастанию
seq_line=$(echo "$progress" | grep ':ok$' | sed 's/STEP:\([a-z0-9]*\):ok/\1/')
expected_seq=$(echo "$EXPECTED_STEPS" | tr ' ' '\n')
[ "$seq_line" = "$expected_seq" ] && pass "порядок шагов: $(echo $EXPECTED_STEPS)" \
  || { fail "порядок шагов не совпал"; echo "    got: $(echo $seq_line)"; }

# result.json валиден и содержит поля
echo "$result" | python3 -c '
import sys,json
d=json.load(sys.stdin)
for k in ("host","ws_port","file_port","token","tls","file_fingerprint"):
    assert k in d and d[k] not in ("",None), f"missing {k}"
assert len(d["token"])>=32, "token too short"
assert d["ws_port"]=='"$WS_PORT"' and d["file_port"]=='"$FILE_PORT"', "ports mismatch"
print("  fields:", ",".join(d.keys()))
' && pass "result.json валиден (все поля, порты совпали)" || fail "result.json невалиден: $result"

# файл-сервер слушает и презентует серт с тем же fingerprint
fp_expect=$(echo "$result" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("file_fingerprint",""))' 2>/dev/null || true)
fp_live=$(docker exec "$CNAME" bash -c "echo | openssl s_client -connect 127.0.0.1:$FILE_PORT 2>/dev/null | openssl x509 -noout -fingerprint -sha256 2>/dev/null | sed 's/.*=//; s/://g' | tr A-Z a-z")
[ -n "$fp_expect" ] && [ "$fp_live" = "$fp_expect" ] \
  && pass "файл-сервер :$FILE_PORT слушает, fingerprint совпал" \
  || fail "fingerprint файл-сервера не совпал (live=$fp_live expect=$fp_expect)"

echo "== Итог =="
if [ "$FAILED" = "0" ]; then echo "PASS ✅"; exit 0; else echo "FAIL ❌"; exit 1; fi
