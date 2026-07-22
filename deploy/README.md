# Развёртывание Ёжика (контейнер + деплой приложений)

Ёжик едет в контейнере на базе **Debian 12**. Образ собирается один раз в
GitHub Actions и публикуется в `ghcr.io/illiyanibl/hedgehog:latest` — на
сервере он **только скачивается** (`docker pull`), без сборки. Агент внутри
поднимает приложения (FastAPI, сайты) **соседними контейнерами** через
socket-proxy; наружу они торчат по `IP:port`, а при наличии домена — по
HTTPS через Caddy.

```
Хост
├─ firewall: WS/FILE (8765/8767) + 8000–8099 (приложения) + 80/443 (Caddy)
├─ [socket-proxy] ── whitelist ──▶ /var/run/docker.sock
├─ [hedgehog]  Debian 12, DOCKER_HOST=tcp://hedgehog-socket-proxy:2375
│              тома: hedgehog-data (/data), hedgehog-apps (/apps)
├─ [caddy]     :80/:443   on-demand TLS (простаивает без домена)
└─ [app-контейнеры]  создаёт агент:  -p 80XX:PORT  →  http://SERVER_IP:80XX
```

## Установка (обычно делает клиент по SSH)

```bash
apt-get update && apt-get install -y git
git clone --depth 1 https://github.com/Illiyanibl/hedgehog_core /opt/hedgehog
bash /opt/hedgehog/deploy/bootstrap.sh
```

`bootstrap.sh` идемпотентен и работает на любом docker (включая старый
`docker.io` 20.10, где нет compose): ставит Docker (если нет), открывает
firewall, **тянет готовый образ** (`docker pull`), поднимает три контейнера
обычным `docker run` (socket-proxy + hedgehog + caddy), генерит bearer-токен
и печатает JSON коннекта для клиента.

Переопределяется env-переменными:
`HEDGEHOG_WS_PORT`, `HEDGEHOG_FILE_PORT`, `CADDY_HTTP_PORT`, `CADDY_HTTPS_PORT`,
`HEDGEHOG_IMAGE` (напр. свой образ из форка).

> Требования к серверу: диск **20+ ГБ** (образ ~1 ГБ + место под образы
> приложений, которые поднимает агент), root-доступ, интернет.

## Как агент разворачивает приложение

Код кладётся в общий том `hedgehog-apps` (`/apps/<name>/`), приложение
поднимается отдельным контейнером с монтированием того же тома по имени:

```bash
docker run -d --name hh-app-<name> -p 8001:8000 \
  -v hedgehog-apps:/apps -w /apps/<name> \
  python:3.12-slim \
  sh -c "pip install -r requirements.txt && uvicorn app:app --host 0.0.0.0 --port 8000"
```

Доступно на `http://SERVER_IP:8001`. Рестарт Ёжика приложение не трогает.

## Образ

Собирается автоматически (`.github/workflows/docker-publish.yml`) при
изменении кода Ёжика / Dockerfile и пушится в
`ghcr.io/illiyanibl/hedgehog:latest` (пакет публичный — pull без логина).
Локально: `docker build -f deploy/Dockerfile -t hedgehog:local .`

## Безопасность

`POST=1` на socket-proxy даёт агенту create/build/exec — технически позволяет
создать контейнер с произвольным bind-mount и выйти на root хоста. Осознанный
компромисс ради «делать сайты»; сужение до собственного deploy-API —
следующий виток. Сокет смонтирован ro, whitelist ресурсов точечный.
