"""§17 Neko-браузер: провижининг общего Chromium-контейнера, доступного по
TLS-пиннингу (тем же сертом, что файл-сервер) без SSH.

Neko = настоящий Chromium в контейнере, картинка по WebRTC, ввод обратно.
Ставится Ёжиком через docker CLI (в образе есть) → socket-proxy — тот же путь,
что деплой приложений агента. Один общий инстанс на сервер (дорогой ресурс),
opt-in.

Отличия от devolution (который ходил SSH-тоннелем):
  - TLS терминирует сам neko нашим сертом (NEKO_SERVER_CERT/KEY) → WKWebView
    пинит ТОТ ЖЕ SHA-256, что у файл-сервера. Тоннель не нужен.
  - WebRTC одним портом: udp-mux (медиа) + tcp-mux (fallback), а не EPR-диапазон.
  - NAT1TO1 = SERVER_IP (или neko сам заберёт через ipfetch).

Идемпотентность: rename→run→(успех)rm-old / (провал)rename-back+start — НЕ
безусловный `rm -f` (баг devolution: offline → остались без браузера).
"""
from __future__ import annotations

import json
import secrets
import socket
import subprocess
from dataclasses import dataclass, asdict
from pathlib import Path

import structlog

from .config import Config

log = structlog.get_logger("neko")

CONTAINER = "hedgehog-neko"
PROFILE_VOLUME = "hedgehog-neko-profile"
TLS_VOLUME = "hedgehog-neko-tls"


@dataclass
class NekoResult:
    ok: bool
    status: str = "absent"        # running | absent | error
    message: str = ""
    https_port: int = 0
    user_password: str = ""       # для авто-логина клиента (?pwd=)
    server_ip: str = ""           # публичный адрес для WKWebView


# ---------- docker helpers ----------

def _run(args: list[str], timeout: int = 600,
         input_bytes: bytes | None = None) -> tuple[int, str]:
    try:
        proc = subprocess.run(
            args, capture_output=True, timeout=timeout, input=input_bytes)
    except (OSError, subprocess.SubprocessError) as e:
        return 1, f"{type(e).__name__}: {e}"
    out = (proc.stdout or b"") + (proc.stderr or b"")
    return proc.returncode, out.decode("utf-8", "replace").strip()


def _docker_ok() -> bool:
    code, _ = _run(["docker", "info"], timeout=20)
    return code == 0


def _own_network() -> str | None:
    """Сеть, в которой сам Ёжик — чтобы neko был в ней же (для Playwright-агента
    в Фазе 3 + единообразия). hostname контейнера = его id."""
    host = socket.gethostname()
    code, out = _run(["docker", "inspect", host, "--format",
                      "{{range $k,$_ := .NetworkSettings.Networks}}{{$k}} {{end}}"],
                     timeout=20)
    if code != 0 or not out.strip():
        return None
    # первая не-bridge сеть (bridge — дефолтная, не наша)
    nets = [n for n in out.split() if n and n != "bridge"]
    return nets[0] if nets else None


def _container_status(name: str) -> str:
    """running | stopped | absent"""
    code, out = _run(["docker", "inspect", "-f", "{{.State.Status}}", name],
                     timeout=20)
    if code != 0:
        return "absent"
    return "running" if out.strip() == "running" else "stopped"


# ---------- пароли (персистятся в /data, переживают пересоздание) ----------

def _passwords(config: Config) -> tuple[str, str]:
    """(user, admin). Генерим один раз, храним в data/neko_auth.json —
    пересоздание контейнера не меняет пароль (клиент не теряет доступ)."""
    p = config.data_dir / "neko_auth.json"
    try:
        d = json.loads(p.read_text())
        if d.get("user") and d.get("admin"):
            return d["user"], d["admin"]
    except (OSError, ValueError):
        pass
    user, admin = secrets.token_hex(16), secrets.token_hex(16)
    config.data_dir.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({"user": user, "admin": admin}))
    p.chmod(0o600)
    return user, admin


def _seed_tls_volume(config: Config) -> bool:
    """Скопировать наш серт/ключ в отдельный том neko (ro-монтируется в neko).
    Не монтируем весь /data (там токен/oauth) — только cert/key."""
    try:
        cert = config.tls_cert_file.read_bytes()
        key = config.tls_key_file.read_bytes()
    except OSError as e:
        log.error("neko.tls.read_failed", error=str(e))
        return False
    _run(["docker", "volume", "create", TLS_VOLUME], timeout=30)
    # пишем оба файла в том через helper-alpine (stdin → файл)
    for name, data in (("cert.pem", cert), ("key.pem", key)):
        code, out = _run(
            ["docker", "run", "--rm", "-i", "-v", f"{TLS_VOLUME}:/tls",
             "alpine", "sh", "-c", f"cat > /tls/{name}"],
            timeout=60, input_bytes=data)
        if code != 0:
            log.error("neko.tls.seed_failed", file=name, out=out[-200:])
            return False
    return True


# ---------- сборка docker run (чистая функция — юнит-тестируемо) ----------

def build_run_cmd(config: Config, user_pw: str, admin_pw: str,
                  network: str | None, nat_ip: str | None) -> list[str]:
    screen = config.neko_screen
    args = [
        "docker", "run", "-d", "--name", CONTAINER,
        "--shm-size=2gb", "--cap-add=SYS_ADMIN", "--restart", "unless-stopped",
        # сигналинг HTTPS/WSS (TLS терминирует neko нашим сертом)
        "-p", f"{config.neko_https_port}:8080/tcp",
        # WebRTC одним портом: udp-mux (медиа) + tcp-mux (fallback)
        "-p", f"{config.neko_udpmux_port}:{config.neko_udpmux_port}/udp",
        "-p", f"{config.neko_tcpmux_port}:{config.neko_tcpmux_port}/tcp",
        "-e", "NEKO_SERVER_BIND=:8080",
        "-e", "NEKO_SERVER_CERT=/tls/cert.pem",
        "-e", "NEKO_SERVER_KEY=/tls/key.pem",
        "-e", f"NEKO_SCREEN={screen}",
        "-e", f"NEKO_DESKTOP_SCREEN={screen}",
        "-e", f"NEKO_PASSWORD={user_pw}",
        "-e", f"NEKO_PASSWORD_ADMIN={admin_pw}",
        "-e", f"NEKO_WEBRTC_UDPMUX={config.neko_udpmux_port}",
        "-e", f"NEKO_WEBRTC_TCPMUX={config.neko_tcpmux_port}",
        "-e", "NEKO_CAPTURE_AUDIO_CODEC=opus",
        "-v", f"{TLS_VOLUME}:/tls:ro",
        "-v", f"{PROFILE_VOLUME}:/home/neko/.config/chromium",
    ]
    if nat_ip:
        args += ["-e", f"NEKO_NAT1TO1={nat_ip}"]
    else:
        # без явного IP — neko сам заберёт публичный адрес
        args += ["-e", "NEKO_IPFETCH=https://api.ipify.org"]
    if network:
        args += ["--network", network]
    args.append(config.neko_image)
    return args


# ---------- публичное API ----------

def status(config: Config) -> NekoResult:
    if not _docker_ok():
        return NekoResult(ok=False, status="error",
                          message="docker недоступен (нет socket-proxy?)")
    st = _container_status(CONTAINER)
    if st == "running":
        user, _ = _passwords(config)
        return NekoResult(ok=True, status="running",
                          https_port=config.neko_https_port,
                          user_password=user, server_ip=config.server_ip or "")
    return NekoResult(ok=True, status="absent" if st == "absent" else "error",
                      message="" if st == "absent" else "контейнер остановлен")


def provision(config: Config) -> NekoResult:
    """Идемпотентно поднять neko. Блокирующая — звать через asyncio.to_thread."""
    if not _docker_ok():
        return NekoResult(ok=False, status="error",
                          message="docker недоступен (нужен socket-proxy)")
    user_pw, admin_pw = _passwords(config)
    if not _seed_tls_volume(config):
        return NekoResult(ok=False, status="error",
                          message="не удалось подготовить TLS-серт для neko")

    network = _own_network()
    nat_ip = config.server_ip

    # pull образа (не критично при offline, если локально есть)
    _run(["docker", "pull", config.neko_image], timeout=600)

    existing = _container_status(CONTAINER)
    recreate = existing != "absent"
    if recreate:
        _run(["docker", "rm", "-f", f"{CONTAINER}-old"], timeout=60)
        code, out = _run(["docker", "rename", CONTAINER, f"{CONTAINER}-old"], timeout=60)
        if code != 0:
            return NekoResult(ok=False, status="error",
                              message=f"docker rename: {out[-200:]}")
        _run(["docker", "stop", "-t", "5", f"{CONTAINER}-old"], timeout=30)

    # чистим Singleton-lock профиля (иначе chromium в FATAL после пересоздания)
    _run(["docker", "run", "--rm", "-v", f"{PROFILE_VOLUME}:/p",
          config.neko_image, "sh", "-c", "rm -f /p/Singleton*"], timeout=60)

    cmd = build_run_cmd(config, user_pw, admin_pw, network, nat_ip)
    code, out = _run(cmd, timeout=120)
    if code != 0:
        if recreate:
            # откат на рабочий старый
            _run(["docker", "rename", f"{CONTAINER}-old", CONTAINER], timeout=60)
            _run(["docker", "start", CONTAINER], timeout=60)
            return NekoResult(ok=False, status="error",
                              message=f"docker run упал, откат на старый: {out[-200:]}")
        return NekoResult(ok=False, status="error", message=f"docker run: {out[-200:]}")

    if recreate:
        _run(["docker", "rm", "-f", f"{CONTAINER}-old"], timeout=60)

    log.info("neko.provisioned", port=config.neko_https_port, network=network,
             nat=nat_ip or "ipfetch")
    return NekoResult(ok=True, status="running",
                      https_port=config.neko_https_port,
                      user_password=user_pw, server_ip=config.server_ip or "")


def teardown(config: Config) -> NekoResult:
    _run(["docker", "rm", "-f", CONTAINER], timeout=60)
    return NekoResult(ok=True, status="absent", message="neko удалён")
