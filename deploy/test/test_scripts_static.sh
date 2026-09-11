#!/usr/bin/env bash
# Быстрые статические проверки deploy-скриптов (§install-progress) — без docker
# и сети. Прогоняются мгновенно, годятся для CI как первый барьер.
#   • bash -n (синтаксис);
#   • наличие контракта прогресса: маркеры шагов, DNS, result.json+status, trap ERR.
set -uo pipefail

DIR="$(cd "$(dirname "$0")/.." && pwd)"
BOOT="$DIR/bootstrap.sh"
CONT="$DIR/install-in-container.sh"
SELF="$DIR/selfsetup.sh"
LIB="$DIR/lib/core.sh"
FAILED=0

check(){ # <файл> <regex> <описание>
  if grep -Eq "$2" "$1"; then echo "  ✅ $(basename "$1"): $3";
  else echo "  ❌ $(basename "$1"): НЕТ — $3"; FAILED=1; fi
}

echo "== bash -n (синтаксис) =="
for f in "$BOOT" "$CONT" "$SELF" "$LIB"; do
  if bash -n "$f"; then echo "  ✅ $(basename "$f") синтаксис ок";
  else echo "  ❌ $(basename "$f") синтаксическая ошибка"; FAILED=1; fi
done

echo "== bootstrap.sh (Чистый сервер) =="
check "$BOOT" 'trap on_err ERR' "trap ERR → fail"
check "$BOOT" 'HEDGEHOG_INSTALL_STATE' "читает STATE каталог"
for s in dns packages docker firewall network image containers fail2ban tls; do
  check "$BOOT" "mark $s begin" "шаг $s (begin)"
  check "$BOOT" "mark $s ok" "шаг $s (ok)"
done
check "$BOOT" '/etc/docker/daemon.json' "DNS для docker-демона"
check "$BOOT" '8\.8\.8\.8' "публичные резолверы"
check "$BOOT" 'result\.json' "пишет result.json"
check "$BOOT" 'echo ok > "\$STATE/status"' "финальный status=ok"

echo "== install-in-container.sh (В контейнер) =="
check "$CONT" 'trap on_err ERR' "trap ERR → fail"
check "$CONT" 'HEDGEHOG_INSTALL_STATE' "читает STATE каталог"
for s in dns packages claude venv hedgehog tls; do
  check "$CONT" "mark $s begin" "шаг $s (begin)"
  check "$CONT" "mark $s ok" "шаг $s (ok)"
done
check "$CONT" '8\.8\.8\.8' "публичные резолверы"
check "$CONT" 'result\.json' "пишет result.json"
check "$CONT" 'echo ok > "\$STATE/status"' "финальный status=ok"

echo "== selfsetup.sh (self-setup + файл-конфиг клиента) =="
# У self-setup НЕТ прогресс-контракта (STATE/result.json) — не проверяем его.
check "$SELF" 'lib/core\.sh' "source общего ядра"
check "$SELF" 'devolution-hedgehog-server' "эмитит kind формата импорта клиента"
check "$SELF" 'json\.dump' "JSON собирается python-ом (числа/bool/экранирование)"
check "$SELF" 'chmod 600 "\$OUT"' "файл-конфиг 600 (Bearer+отпечаток)"
check "$SELF" 'HH_TLS" = "1"' "tls — сквозной флаг (отпечаток только при tls)"
check "$LIB"  'chmod 600 "\$src/run-loop.sh"' "run-loop.sh 600 (токен внутри)"

echo "== Итог =="
if [ "$FAILED" = "0" ]; then echo "PASS ✅"; exit 0; else echo "FAIL ❌"; exit 1; fi
