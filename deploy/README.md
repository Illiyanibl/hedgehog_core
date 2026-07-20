# Развёртывание Ёжика (контейнер + деплой приложений)

Ёжик едет в контейнере на базе **Debian 12** — полноценная среда, где агент
может доставлять софт (apt) и поднимать приложения (FastAPI, сайты)
**соседними контейнерами** через socket-proxy. Наружу они торчат по `IP:port`,
а при наличии домена — по HTTPS через Caddy.

```
Хост
├─ firewall: WS/FILE порты (8765/8767) + 8000–8099 (приложения) + 80/443 (Caddy)
├─ [socket-proxy] ── whitelist ──▶ /var/run/docker.sock
├─ [hedgehog]  Debian 12, DOCKER_HOST=tcp://socket-proxy:2375
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

`bootstrap.sh` идемпотентен: ставит Docker, открывает firewall, генерит
bearer-токен, поднимает стек и печатает JSON коннекта для клиента.

Порты хоста переопределяются env-переменными (напр. если 8765 занят):
`HEDGEHOG_WS_PORT`, `HEDGEHOG_FILE_PORT`, `CADDY_HTTP_PORT`, `CADDY_HTTPS_PORT`.

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

## Безопасность

`POST=1` на socket-proxy даёт агенту create/build/exec — технически позволяет
создать контейнер с произвольным bind-mount и выйти на root хоста. Осознанный
компромисс ради «делать сайты»; сужение до собственного deploy-API —
следующий виток. Сокет смонтирован ro, whitelist ресурсов точечный.
