# Ёжик — контейнерный образ. База Debian 12 (bookworm): полноценная среда,
# где агент может доставлять «остальное ПО» через apt. Ставим Python-рантайм
# Ёжика + claude CLI (auth §13 + SDK-бэкенд) + docker CLI (агент рулит
# соседними контейнерами через socket-proxy).
#
# Контекст сборки — корень репозитория (hedgehog_core/), т.к. нужны hedgehog/
# и requirements.txt:
#   docker build -f deploy/Dockerfile -t hedgehog:local .
FROM debian:12-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    HOME=/root \
    PATH=/opt/venv/bin:$PATH

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-venv python3-pip \
        git curl ca-certificates tini \
    && rm -rf /var/lib/apt/lists/*

# docker CLI (статический бинарь) — только клиент. Агент ходит в socket-proxy
# (DOCKER_HOST=tcp://socket-proxy:2375) и поднимает приложения соседними
# контейнерами.
ARG DOCKER_CLI_VERSION=27.5.1
RUN curl -fsSL "https://download.docker.com/linux/static/stable/x86_64/docker-${DOCKER_CLI_VERSION}.tgz" \
        -o /tmp/docker.tgz \
    && tar -xzf /tmp/docker.tgz -C /tmp \
    && mv /tmp/docker/docker /usr/local/bin/docker \
    && rm -rf /tmp/docker /tmp/docker.tgz \
    && docker --version

# claude CLI — standalone-установщик. Нужен для auth-флоу §13 (setup-token в
# PTY) и как бэкенд claude-agent-sdk.
RUN curl -fsSL https://claude.ai/install.sh | bash \
    && ln -sf /root/.local/bin/claude /usr/local/bin/claude \
    && claude --version

# venv + зависимости Ёжика. Пакет hedgehog кладём в /app и запускаем как модуль
# (python -m hedgehog.main) — не устанавливаем как dist, чтобы правки видны сразу.
RUN python3 -m venv /opt/venv
WORKDIR /app
COPY requirements.txt ./requirements.txt
RUN pip install -r requirements.txt
COPY hedgehog/ ./hedgehog/
COPY pyproject.toml ./pyproject.toml

ENV HEDGEHOG_HOST=0.0.0.0 \
    HEDGEHOG_PORT=8765 \
    HEDGEHOG_FILE_PORT=8767 \
    HEDGEHOG_DATA_DIR=/data \
    HEDGEHOG_DEFAULT_CWD=/apps

EXPOSE 8765 8767
VOLUME ["/data", "/apps"]

ENTRYPOINT ["tini", "--"]
CMD ["python", "-m", "hedgehog.main"]
