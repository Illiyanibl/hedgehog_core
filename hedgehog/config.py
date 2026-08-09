"""Runtime configuration for Ёжик.

Everything comes from environment variables with sane defaults for the
Phase 1a test bench (plain ws:// behind an SSH tunnel, data dir next to
the process). The bearer token is generated on first start and persisted
under the data dir so restarts keep the credential stable.
"""

from __future__ import annotations

import json
import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Config:
    host: str = field(default_factory=lambda: os.environ.get("HEDGEHOG_HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: int(os.environ.get("HEDGEHOG_PORT", "8765")))
    # §7 Файлы — ОТДЕЛЬНЫЙ aiohttp-порт (WS-чаты не трогаем). Общий токен+серт.
    file_port: int = field(default_factory=lambda: int(
        os.environ.get("HEDGEHOG_FILE_PORT", "8767")))
    # TLS для файл-сервера (в бою без туннеля обязателен). Локально за
    # туннелем можно оставить выключенным (plain http). HEDGEHOG_TLS=1 → on.
    tls_enabled: bool = field(default_factory=lambda: os.environ.get(
        "HEDGEHOG_TLS", "").lower() in ("1", "true", "yes", "on"))
    # Лимит размера одной загрузки.
    max_upload_bytes: int = 512 * 1024 * 1024  # 512 МБ
    data_dir: Path = field(default_factory=lambda: Path(
        os.environ.get("HEDGEHOG_DATA_DIR", "./data")).resolve())
    # Дефолтный рабочий каталог новых чатов (если create_chat.cwd = null).
    # None → каждый чат в своём /data/chats/<id>/ (изоляция). Если задан
    # (напр. /root/projects) — все чаты работают там, видят реальные проекты.
    default_cwd: str | None = field(default_factory=lambda: os.environ.get(
        "HEDGEHOG_DEFAULT_CWD") or None)
    # §16 Files: потолок обзора файл-браузера. По умолчанию "/" — корень
    # контейнера (проект изолирован в Docker, вся его ФС доступна владельцу).
    # На голом сервере можно ужать (напр. /root/projects). Пути выше потолка
    # сервер отдаёт 403. Родитель проектов (projects_root) клиент красит
    # красным как «вышел из своих проектов» — но обзор не блокирует.
    browse_root: str = field(default_factory=lambda: os.environ.get(
        "HEDGEHOG_BROWSE_ROOT", "/"))

    # §17 Neko-браузер — общий Chromium в контейнере, стрим по WebRTC, доступ
    # по TLS-пиннингу (тем же сертом, что файл-сервер), без SSH. Ставится Ёжиком
    # через docker CLI + socket-proxy. Один общий инстанс на сервер, opt-in.
    neko_image: str = field(default_factory=lambda: os.environ.get(
        "HEDGEHOG_NEKO_IMAGE", "ghcr.io/illiyanibl/devolution-neko:latest"))
    # Порт HTTPS/WSS-сигналинга neko (TLS терминирует сам neko нашим сертом).
    neko_https_port: int = field(default_factory=lambda: int(
        os.environ.get("HEDGEHOG_NEKO_PORT", "8766")))
    # WebRTC одним портом: udp-mux (медиа) + tcp-mux (fallback на строгих сетях).
    neko_udpmux_port: int = field(default_factory=lambda: int(
        os.environ.get("HEDGEHOG_NEKO_UDPMUX", "59000")))
    neko_tcpmux_port: int = field(default_factory=lambda: int(
        os.environ.get("HEDGEHOG_NEKO_TCPMUX", "59000")))
    # §AI-control: порт MCP-плейна @playwright/mcp внутри контейнера neko. НЕ
    # публикуется наружу (-p) — доступен только агенту по ВЫДЕЛЕННОЙ docker-сети
    # hedgehog↔neko (см. neko._ensure_network). Агент ходит на
    # http://hedgehog-neko:<port>/mcp.
    neko_mcp_port: int = field(default_factory=lambda: int(
        os.environ.get("HEDGEHOG_NEKO_MCP_PORT", "9250")))
    # §AI-control: swap на ХОСТЕ под neko (браузер память-тяжёлый; без swap на
    # слабых серверах OOM убивает chrome). Ставится Ёжиком через привилегированный
    # one-shot контейнер (host-ресурс — контейнер сам не создаст). 0 = выключить.
    neko_swap_mb: int = field(default_factory=lambda: int(
        os.environ.get("HEDGEHOG_NEKO_SWAP_MB", "1024")))
    neko_screen: str = field(default_factory=lambda: os.environ.get(
        "HEDGEHOG_NEKO_SCREEN", "1280x800@30"))
    # Публичный IP сервера — для NEKO_NAT1TO1 (ICE-кандидат WebRTC). В контейнере
    # bootstrap выставляет SERVER_IP; иначе neko сам заберёт через ipfetch.
    server_ip: str | None = field(default_factory=lambda: os.environ.get(
        "SERVER_IP") or None)

    server_version: str = "0.1.0"
    protocol_versions: tuple[int, ...] = (1,)
    capabilities: tuple[str, ...] = ("claude", "broker_shell", "picker")

    # screen_snapshot aggregation window, seconds (broker overflow pattern)
    snapshot_interval: float = 0.08
    # user has this long to answer permission_request / picker_request
    permission_timeout: float = 300.0
    # user has this long to open the OAuth link and paste the code back (§13)
    auth_timeout: float = 600.0

    # Лог приложения-клиента (§14 client_log): накопительный файл, лимит.
    client_log_cap: int = 512 * 1024 * 1024  # 512 МБ

    @property
    def chats_dir(self) -> Path:
        return self.data_dir / "chats"

    @property
    def projects_root(self) -> Path:
        """«Домашняя» зона файл-браузера — родитель рабочих папок проектов.
        Если задан HEDGEHOG_DEFAULT_CWD (все чаты работают там) — это он;
        иначе изоляция: /data/chats. Внутри — «свои проекты», снаружи (но
        в пределах browse_root) клиент красит путь красным."""
        base = self.default_cwd or self.chats_dir
        return Path(base).resolve()

    @property
    def client_log_file(self) -> Path:
        return self.data_dir / "client.log"

    @property
    def oauth_token_file(self) -> Path:
        """Долгоживущий OAuth-токен из auth-флоу (§13); подкладывается
        SDK-сессиям через env CLAUDE_CODE_OAUTH_TOKEN."""
        return self.data_dir / "oauth_token"

    def load_oauth_token(self) -> str | None:
        try:
            token = self.oauth_token_file.read_text().strip()
        except OSError:
            return None
        return token or None

    # --- альтернативная авторизация Claude (§altauth): API-ключ / OmniRoute ---
    # Выбранный способ и его секреты хранятся в data/auth.json. Активный режим
    # ЗАМЕНЯЕТ прошлый (запись перезаписывает файл целиком → «стирая прошлые
    # настройки»). Пустой/битый файл или mode=oauth → поведение как раньше
    # (подписка через OAuth-токен).
    @property
    def auth_config_file(self) -> Path:
        return self.data_dir / "auth.json"

    def load_auth_config(self) -> dict:
        """Конфиг альт-авторизации. {} если файла нет/битый (⇒ режим oauth)."""
        try:
            data = json.loads(self.auth_config_file.read_text())
        except (OSError, ValueError):
            return {}
        return data if isinstance(data, dict) else {}

    def save_auth_config(self, data: dict) -> None:
        """Записать выбранный способ (перезаписывая прошлый). chmod 600 — секрет."""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        tmp = self.auth_config_file.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False))
        tmp.chmod(0o600)
        tmp.replace(self.auth_config_file)

    def clear_auth_config(self) -> None:
        """Сбросить альт-авторизацию (logout) → возврат к OAuth."""
        try:
            self.auth_config_file.unlink(missing_ok=True)
        except OSError:
            pass

    @property
    def token_file(self) -> Path:
        return self.data_dir / "auth_token"

    @property
    def auth_log_file(self) -> Path:
        """Стабильный лог неудачных авторизаций для fail2ban (§security).
        В контейнере виден с хоста через том /data."""
        return self.data_dir / "auth_failures.log"

    # §7 TLS: self-signed серт/ключ Ёжика (Ёжик — единый авторитет). Клиент
    # пинит SHA-256 отпечаток, провижининг — по bootstrap-SSH.
    @property
    def tls_dir(self) -> Path:
        return self.data_dir / "tls"

    @property
    def tls_cert_file(self) -> Path:
        return self.tls_dir / "cert.pem"

    @property
    def tls_key_file(self) -> Path:
        return self.tls_dir / "key.pem"

    def load_token(self) -> str:
        """Explicit env override, else persisted file, else generate+persist."""
        env_token = os.environ.get("HEDGEHOG_TOKEN")
        if env_token:
            return env_token
        if self.token_file.exists():
            token = self.token_file.read_text().strip()
            if token:
                return token
        token = secrets.token_urlsafe(32)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.token_file.write_text(token + "\n")
        self.token_file.chmod(0o600)
        return token
