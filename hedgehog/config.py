"""Runtime configuration for Ёжик.

Everything comes from environment variables with sane defaults for the
Phase 1a test bench (plain ws:// behind an SSH tunnel, data dir next to
the process). The bearer token is generated on first start and persisted
under the data dir so restarts keep the credential stable.
"""

from __future__ import annotations

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

    @property
    def token_file(self) -> Path:
        return self.data_dir / "auth_token"

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
