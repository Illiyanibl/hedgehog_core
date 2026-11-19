"""§multi-cli: реестр типов CLI-агентов, которые умеет обслуживать Ёжик.

Единственный источник правды о том, какие `cliType` существуют и что каждый из
них умеет (`cliCapabilities`, protocol/messages.md §18.3). Фабрики сессий живут
в wss-слое (им нужны store/hub/config); здесь — только описание типов, без
зависимостей от остального ядра (импортируется отовсюду, циклов нет).
"""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from pathlib import Path

DEFAULT_CLI_TYPE = "claude"

# §18.3: гейт совместимости — сервер объявляет в hello.capabilities, клиент §18
# присылает в client_hello.clientCapabilities. Фреймы §18 — только таким
# соединениям; остальные видят протокол как до фичи.
MULTI_CLI_CAP = "multi_cli"
# Типы серверных фреймов, которые видят ТОЛЬКО соединения с multi_cli.
MULTI_CLI_ONLY_TYPES = frozenset({"cli_switched", "cli_status"})

# Словарь возможностей (§18.3). Набор открытый: клиент игнорирует незнакомые.
CAP_MODELS = "models"                    # list_models
CAP_SET_MODEL = "set_model"              # set_model
CAP_LIMITS = "limits"                    # get_limits отдаёт реальные лимиты
CAP_PERMISSION_MODES = "permission_modes"  # set_mode
CAP_MCP = "mcp"                          # реестр MCP-серверов
CAP_CLEAR_SESSION = "clear_session"
CAP_INTERRUPT = "interrupt"
CAP_RESUME = "resume"
CAP_SKILLS = "skills"                    # скиллы (§3.7a-skills)
# Ёжик может перехватить ПРАВКИ файлов и спросить (acceptEdits/default). У
# Antigravity по ACP правки идут без запроса (проверено на agy 1.5.0) — §18.8;
# у Grok и Codex запрос на правки приходит.
CAP_EDIT_GATE = "edit_gate"


# Способы входа (cliStatus.authMethods[].id), docs/cli-auth-methods.md
AUTH_LINK_CODE = "link_code"        # подписка: ссылка + вставка кода обратно
AUTH_DEVICE_CODE = "device_code"    # подписка: код устройства (подтверждение на сайте)
AUTH_TOKEN = "token"                # готовый долгоживущий токен подписки (вставка)
AUTH_API_KEY = "api_key"            # API-ключ (оплата по API)
AUTH_GATEWAY = "gateway"            # шлюз / свой endpoint: base_url + ключ + модели


def _field(name: str, secret: bool = False, required: bool = True) -> dict:
    return {"name": name, "secret": secret, "required": required}


@dataclass(frozen=True)
class AuthMethod:
    id: str
    fields: tuple[dict, ...] = ()
    # gateway: какой API должен говорить шлюз (anthropic | openai | gemini | …)
    protocol: str | None = None

    def public(self) -> dict:
        out: dict = {"id": self.id, "fields": [dict(f) for f in self.fields]}
        if self.protocol:
            out["protocol"] = self.protocol
        return out


_KEY_FIELDS = (_field("api_key", secret=True), _field("base_url", required=False))
_GW_FIELDS = (_field("base_url"), _field("api_key", secret=True),
              _field("models", required=False), _field("active_id", required=False))
_GW_FIELDS_BACKEND = _GW_FIELDS + (_field("api_backend", required=False),)


@dataclass(frozen=True)
class CliSpec:
    cli_type: str
    title: str
    capabilities: tuple[str, ...]
    binary: str | None = None            # исполняемый файл для проверки present
    # bundled: CLI поставляется вместе с Ёжиком (Claude — через Agent SDK),
    # отдельная проверка наличия не нужна.
    bundled: bool = False
    # legacy_visible: показывать ли тип в hello.cliTypes (его видят и клиенты без
    # multi_cli, которые могли бы предложить его пользователю).
    legacy_visible: bool = True
    # experimental: CLI/протокол помечены поставщиком как экспериментальные —
    # клиент может показать пометку (hello.cliStatus[...].experimental).
    experimental: bool = False
    # реально реализованные на сервере способы входа (клиент строит UI по ним)
    auth_methods: tuple[AuthMethod, ...] = ()
    # вид проверки ключа (core/key_probe.py): xai | openai | gemini
    key_probe: str | None = None
    # шлюз выбирает модели (Claude/Grok/Codex); у Antigravity модели фиксированы
    gateway_models: bool = True


CLI_SPECS: dict[str, CliSpec] = {
    "claude": CliSpec(
        cli_type="claude",
        title="Claude Code",
        capabilities=(CAP_MODELS, CAP_SET_MODEL, CAP_LIMITS,
                      CAP_PERMISSION_MODES, CAP_MCP, CAP_CLEAR_SESSION,
                      CAP_INTERRUPT, CAP_RESUME, CAP_SKILLS, CAP_EDIT_GATE),
        binary="claude",
        bundled=True,
        auth_methods=(AuthMethod(AUTH_LINK_CODE),
                      AuthMethod(AUTH_TOKEN, (_field("token", secret=True),)),
                      AuthMethod(AUTH_API_KEY, _KEY_FIELDS),
                      AuthMethod(AUTH_GATEWAY, _GW_FIELDS, "anthropic")),
    ),
    "antigravity": CliSpec(
        cli_type="antigravity",
        title="Antigravity CLI",
        capabilities=(CAP_MODELS, CAP_SET_MODEL, CAP_PERMISSION_MODES, CAP_MCP,
                      CAP_CLEAR_SESSION, CAP_INTERRUPT, CAP_RESUME),
        binary="agy",
        legacy_visible=False,
        auth_methods=(AuthMethod(AUTH_LINK_CODE),
                      AuthMethod(AUTH_API_KEY, _KEY_FIELDS),
                      # свой endpoint обязан говорить по Gemini API
                      AuthMethod(AUTH_GATEWAY, (_field("base_url"),
                                                _field("api_key", secret=True)), "gemini")),
        key_probe="gemini",
        gateway_models=False,
    ),
    "codex": CliSpec(
        cli_type="codex",
        title="OpenAI Codex",
        capabilities=(CAP_MODELS, CAP_SET_MODEL, CAP_LIMITS,
                      CAP_PERMISSION_MODES, CAP_MCP, CAP_CLEAR_SESSION,
                      CAP_INTERRUPT, CAP_RESUME, CAP_EDIT_GATE),
        binary="codex",
        legacy_visible=False,
        experimental=True,        # codex app-server у OpenAI — experimental
        auth_methods=(AuthMethod(AUTH_DEVICE_CODE),
                      AuthMethod(AUTH_API_KEY, _KEY_FIELDS),
                      # Codex говорит только по Responses API
                      AuthMethod(AUTH_GATEWAY, _GW_FIELDS, "openai_responses")),
        key_probe="openai",
    ),
    "grok": CliSpec(
        cli_type="grok",
        title="Grok Build",
        # лимитов через ACP нет (`grok usage` — только в TUI) → без CAP_LIMITS
        capabilities=(CAP_MODELS, CAP_SET_MODEL, CAP_PERMISSION_MODES, CAP_MCP,
                      CAP_CLEAR_SESSION, CAP_INTERRUPT, CAP_RESUME,
                      CAP_EDIT_GATE),
        binary="grok",
        legacy_visible=False,
        experimental=True,        # новый CLI xAI, промо-доступ, ACP может меняться
        auth_methods=(AuthMethod(AUTH_DEVICE_CODE),
                      AuthMethod(AUTH_API_KEY, _KEY_FIELDS),
                      AuthMethod(AUTH_GATEWAY, _GW_FIELDS_BACKEND, "openai")),
        key_probe="xai",
    ),
}


# Окружение дочерних CLI — БЕЛЫЙ СПИСОК, а не os.environ целиком: в окружении
# сервера могут лежать секреты (HEDGEHOG_TOKEN, ключи push/TLS), а read-only
# команды агента (`env`, `cat /proc/self/environ`) CLI разрешают без запроса.
_ENV_BASE = frozenset({
    "HOME", "USER", "LOGNAME", "SHELL", "LANG", "LANGUAGE", "TERM", "TZ",
    "TMPDIR", "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE",
    "NODE_EXTRA_CA_CERTS", "NODE_OPTIONS", "HTTP_PROXY", "HTTPS_PROXY",
    "NO_PROXY", "ALL_PROXY"})
_ENV_BASE_PREFIX = ("LC_", "XDG_")
# имена и префиксы, нужные конкретному CLI (ключи API, домашние каталоги, флаги)
_ENV_CLI: dict[str, tuple[frozenset, tuple]] = {
    "grok": (frozenset({"XAI_API_KEY", "RUST_LOG"}), ("GROK_",)),
    "codex": (frozenset({"OPENAI_API_KEY", "OPENAI_BASE_URL", "RUST_LOG"}), ("CODEX_",)),
    "antigravity": (frozenset(), ("AGY_", "GOOGLE_", "GEMINI_")),
    "claude": (frozenset({"ANTHROPIC_API_KEY", "ANTHROPIC_BASE_URL"}),
               ("CLAUDE_", "ANTHROPIC_")),
}


# §cli-pins: политика версий CLI. HEDGEHOG_CLI_AUTO_UPDATE=1 (по умолчанию) —
# встроенное самообновление CLI не трогаем, пины compat.json — МИНИМУМ;
# =0 — пины ТОЧНЫЕ, самообновление CLI выключаем (env/конфиг ниже).
_AUTO_UPDATE_ENV = "HEDGEHOG_CLI_AUTO_UPDATE"
# env, которым CLI отключают своё самообновление (только при политике «точно»)
_NO_SELF_UPDATE_ENV: dict[str, dict[str, str]] = {
    "antigravity": {"AGY_CLI_DISABLE_AUTO_UPDATE": "1"},
    "grok": {"GROK_DISABLE_AUTOUPDATER": "1"},
}


def cli_auto_update() -> bool:
    """True — самообновление CLI разрешено и пины работают как минимум."""
    raw = os.environ.get(_AUTO_UPDATE_ENV, "1").strip().lower()
    return raw not in ("0", "false", "no", "off")


def no_self_update_env(cli_type: str) -> dict[str, str]:
    """env-флаги выключения самообновления CLI — только при политике «точно»."""
    if cli_auto_update():
        return {}
    return dict(_NO_SELF_UPDATE_ENV.get(cli_type, {}))


# §cli-pins: управляемый каталог установки CLI (чистая установка Ёжиком):
# HEDGEHOG_CLI_DIR, иначе <data_dir>/cli-bin (задаёт сервер через configure_cli_dir).
_cli_dir: Path | None = None


def configure_cli_dir(path: Path | str | None) -> None:
    global _cli_dir
    _cli_dir = Path(path) if path else None


def managed_cli_dir() -> Path | None:
    env = os.environ.get("HEDGEHOG_CLI_DIR", "").strip()
    if env:
        return Path(env).expanduser()
    return _cli_dir


class CliUnavailable(RuntimeError):
    """Бинарь CLI не найден к моменту запуска процесса (→ CLI_UNAVAILABLE)."""


def spawn_env(cli_type: str, binary: str | None = None,
              extra: dict[str, str] | None = None) -> dict[str, str]:
    """env для запуска CLI: белый список из окружения сервера (+ HEDGEHOG_<CLI>_ENV_PASS
    — запасной люк «A,B»), каталог бинаря в PATH (npm-шим `#!/usr/bin/env node`
    требует node рядом), флаги выключения самообновления (политика «точно»,
    HEDGEHOG_CLI_AUTO_UPDATE=0), затем `extra` (перекрывает)."""
    names, prefixes = _ENV_CLI.get(cli_type, (frozenset(), ()))
    passthrough = {x.strip() for x in os.environ.get(
        f"HEDGEHOG_{cli_type.upper()}_ENV_PASS", "").split(",") if x.strip()}
    base_lower = {b.lower() for b in _ENV_BASE}
    env = {k: v for k, v in os.environ.items()
           if k in _ENV_BASE or k.lower() in base_lower or k in names
           or k in passthrough or k.startswith(_ENV_BASE_PREFIX + prefixes)}
    path = os.environ.get("PATH", "")
    if binary:
        bindir = str(os.path.dirname(binary))
        if bindir not in path.split(os.pathsep):
            path = f"{bindir}{os.pathsep}{path}"
    env["PATH"] = path
    env.update(no_self_update_env(cli_type))
    env.update(extra or {})
    return env


def find_binary(cli_type: str) -> str | None:
    """Путь к исполняемому файлу CLI: env HEDGEHOG_<TYPE>_BIN, управляемый
    каталог Ёжика (HEDGEHOG_CLI_DIR / <data_dir>/cli-bin), PATH, типовые
    каталоги установки (~/.local/bin, /opt/agy). None — не найден."""
    spec = CLI_SPECS.get(cli_type)
    if spec is None or not spec.binary:
        return None
    override = os.environ.get(f"HEDGEHOG_{cli_type.upper()}_BIN")
    if override and os.access(override, os.X_OK):
        return override
    managed = managed_cli_dir()
    if managed is not None:
        cand = managed / spec.binary
        if cand.is_file() and os.access(cand, os.X_OK):
            return str(cand)
    found = shutil.which(spec.binary)
    if found:
        return found
    for d in (Path.home() / ".local" / "bin", Path("/opt/agy"),
              Path("/opt/node/bin"), Path("/usr/local/bin"),
              Path("/opt/grok/bin"), Path.home() / ".grok" / "bin"):
        cand = d / spec.binary
        if cand.is_file() and os.access(cand, os.X_OK):
            return str(cand)
    return None


def legacy_visible_cli_types() -> tuple[str, ...]:
    return tuple(t for t, sp in CLI_SPECS.items() if sp.legacy_visible)


def known_cli_types() -> tuple[str, ...]:
    return tuple(CLI_SPECS)


def spec_for(cli_type: str) -> CliSpec | None:
    return CLI_SPECS.get(cli_type)


def capabilities_for(cli_type: str) -> tuple[str, ...]:
    spec = CLI_SPECS.get(cli_type)
    return spec.capabilities if spec else ()


def supports(cli_type: str, capability: str) -> bool:
    return capability in capabilities_for(cli_type)
