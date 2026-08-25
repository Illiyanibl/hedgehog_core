# Тесты установки (§install-progress)

Проверяют deploy-скрипты и контракт прогресса установки, который опрашивает
iOS-клиент (`BootstrapService`): маркеры шагов `STEP:<key>:<begin|ok|fail>`,
DNS-настройку, `result.json` + `status`, отсоединённый запуск и pid-liveness.

## `test_scripts_static.sh` — быстро, без docker
`bash -n` + проверка наличия контракта в `bootstrap.sh` и
`install-in-container.sh`. Мгновенно, годится первым барьером в CI.

```bash
deploy/test/test_scripts_static.sh
```

## `test_install_container.sh` — интеграционный (docker + сеть)
Поднимает чистый `debian:12`, прогоняет `install-in-container.sh` тем же
контрактом, что и клиент (setsid + pid-файл + опрос), и проверяет:
маркеры/порядок шагов, `kill -0` liveness (без procps), `status=ok`, валидный
`result.json`, реально слушающий файл-сервер с совпавшим TLS-fingerprint.

```bash
deploy/test/test_install_container.sh
# переменные: TEST_IMAGE (debian:12), TEST_TIMEOUT (600)
```

Требует исходящую сеть в контейнере (apt/pip/claude CLI). ~1–2 мин.

---
Живой прогон 2026-08-25 (debian:12): установка «В контейнер» — PASS. Шаги
prepare→dns→packages→claude→venv→hedgehog→tls, status=ok за ~75с, файл-сервер
слушает, TLS-fingerprint совпал. Тест вскрыл баг клиента (pgrep→pid liveness).
