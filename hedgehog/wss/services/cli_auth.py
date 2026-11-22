"""CliAuthService: вход/выход и смена способа авторизации CLI.

Вынесено из HedgehogServer (wss/server.py) без изменения поведения и протокола:
менеджеры входа (Claude OAuth, Antigravity, Codex, Grok), замки смены способа
по CLI, MED-1-пометка «токен отвергнут», активация API-ключа/шлюза.

Хост (сервер, см. services/base.AuthHost) передаётся в конструктор. Его методы
зовём как ``self.host._x(...)`` в момент вызова (bound-методы не захватываем);
config/hub/store — property-прокси на хост. wss.server не импортируем.
"""

from __future__ import annotations

import asyncio
import copy
import functools
import hashlib
import json
import time
from typing import Any

import structlog

from ...config import write_secret_file
from ...core.auth import AuthManager
from ...core import models
from ...core.gateways import omniroute as omniroute_gw
from ...core import (agy_auth, auth_store, cli_registry, codex_auth,
                     grok_auth, key_probe, secrets_redact)
from ...core.agy_auth import AgyAuthManager
from ...core.codex_auth import CodexAuthManager
from ...core.grok_auth import GrokAuthManager
from ...protocol import AuthOmniRoutePayload, Err, make_error, make_frame
from ... import i18n
from .base import AuthHost

log = structlog.get_logger("wss")

# CLI, у которых вход — отдельный менеджер (device/OAuth), и модуль-«хранилище»
# (is_logged_in/logout/apply_alt — побочные эффекты режима API-ключа/шлюза).
LOGIN_MODULES = {"antigravity": agy_auth, "codex": codex_auth,
                 "grok": grok_auth}
# LOW-1: CLI, у которых вход поверх живого токена безвреден (`agy --login`
# токен не стирает) — на 401 стартуем вход как раньше, без проверки токена.
_AUTOLOGIN_OVER_TOKEN = frozenset({"antigravity"})


class CliAuthService:
    def __init__(self, host: AuthHost):
        self.host = host
        config = host.config
        self.auth = AuthManager(config, self._auth_broadcast)
        # §multi-cli: вход Antigravity (Google OAuth через `agy acp --login`).
        self.agy_auth = AgyAuthManager(
            config, functools.partial(self._cli_auth_broadcast, "antigravity"))
        # §20: вход OpenAI Codex (device code через `codex login --device-auth`).
        self.codex_auth = CodexAuthManager(
            config, functools.partial(self._cli_auth_broadcast, "codex"))
        host._configure_grok_home()
        codex_auth.configure(config)
        agy_auth.configure(config)
        # §cli-pins: управляемый каталог CLI (чистая установка Ёжиком) — его
        # find_binary смотрит первым после HEDGEHOG_<CLI>_BIN.
        cli_registry.configure_cli_dir(config.data_dir / "cli-bin")
        secrets_redact.clear_sources()
        secrets_redact.add_source(lambda: auth_store.all_api_secrets(config))
        # §21: вход Grok Build (device code через `grok login --device-auth`).
        self.grok_auth = GrokAuthManager(
            config, functools.partial(self._cli_auth_broadcast, "grok"))
        # §auth: замок на CLI — сериализует активацию/выход/старт входа и создание сессий
        self._auth_locks: dict[str, asyncio.Lock] = {}
        # MED-1: CLI ответил 401 при живом токене подписки — cli_status/hello
        # отдают AUTH_REQUIRED (кэш моделей хранит OK последней удачной пробы),
        # пока не будет удачной пробы, реального входа или смены способа.
        self._cli_token_rejected: set[str] = set()
        # §netwait: текущая login-операция (single-flight): {op_id,conn_id,phase,
        # slow_task,hard_task}. Логин глобальный → таймеры отдельно от _ops.
        self._login_op: dict[str, Any] | None = None
        # §omni: кэш каталога шлюза по base_url ({base: (ts, data)}), TTL ниже.
        self._omni_catalog_cache: dict[str, tuple[float, dict]] = {}

    _OMNI_CATALOG_TTL = 300      # §omni: кэш каталога шлюза (5 мин)
    _OMNI_CATALOG_MAX = 32       # L: потолок записей кэша (не растёт бесконечно)

    # Прокси на хост: перенесённый код обращается к self.config/hub/store как раньше.
    @property
    def config(self):
        return self.host.config

    @property
    def hub(self):
        return self.host.hub

    @property
    def store(self):
        return self.host.store

    async def shutdown(self) -> None:
        # §netwait H3/L4: login-таймеры гасим первыми (часть HedgehogServer.shutdown).
        self._cancel_login_timers()
        self._login_op = None
        await self.auth.stop()
        await self.agy_auth.stop()
        await self.codex_auth.stop()
        await self.grok_auth.stop()

    def _auth_lock(self, cli: str) -> asyncio.Lock:
        lock = self._auth_locks.get(cli)
        if lock is None:
            lock = self._auth_locks[cli] = asyncio.Lock()
        return lock

    # ---------- хендлеры фреймов входа/выхода (_SYS_ROUTES → cli_auth.*) ----------

    async def _h_auth_start(self, conn_id, frame, p):
        cli = p.cliType or models.DEFAULT_CLI_TYPE
        if cli != models.DEFAULT_CLI_TYPE:       # §multi-cli (§18.7)
            return await self._cli_auth_start(conn_id, frame, cli)
        # §netwait: single-flight — если флоу уже идёт, auth.start() лишь
        # пере-шлёт ссылку; новые таймеры ставим ТОЛЬКО на реально новый флоу.
        was_running = self.auth.running
        await self.auth.start()
        if not was_running and self.auth.running:
            self._start_login_timers(frame.id, conn_id, "start")
        return

    async def _h_auth_code(self, conn_id, frame, p):
        if p.cliType != models.DEFAULT_CLI_TYPE:  # §multi-cli (§18.7)
            return await self._cli_auth_code(conn_id, p)
        if not await self.auth.submit_code(p.code):
            # Единый путь у клиента: неуспех — тоже auth_result.
            await self.hub.send_global(conn_id, make_frame(
                "auth_result",
                {"ok": False, "error": "no auth flow in progress"}))
            return
        # §netwait: ждём auth_result по коду (обмен кода на токен — сеть).
        self._start_login_timers(frame.id, conn_id, "code")
        return

    async def _auth_alt_precheck(self, conn_id, frame, cli: str, method: str,
                                 base_url: str | None) -> str | None:
        """Общая проверка auth_apikey/auth_gateway: CLI известен и умеет способ,
        base_url допустим. Нормализованный base_url (или "") либо None, если
        клиенту уже отправлена ошибка."""
        spec = cli_registry.spec_for(cli)
        if spec is None:
            await self._cli_auth_err(conn_id, frame, Err.CLI_UNKNOWN,
                                     f"unknown cliType {cli!r}")
            return None
        if method not in {m.id for m in spec.auth_methods}:
            await self._cli_auth_err(conn_id, frame, Err.AUTH_METHOD_UNSUPPORTED,
                                     i18n.Msg("auth.method_unsupported"))
            return None
        if not base_url:
            return ""
        try:
            return auth_store.validate_base_url(base_url)
        except ValueError as e:
            await self._cli_auth_err(conn_id, frame, Err.BAD_BASE_URL,
                                     i18n.Msg(str(e)))
            return None

    async def _h_auth_apikey(self, conn_id, frame, p):
        # §altauth: активировать прямой API-ключ (заголовок x-api-key).
        cli = p.cliType or models.DEFAULT_CLI_TYPE
        base = await self._auth_alt_precheck(
            conn_id, frame, cli, cli_registry.AUTH_API_KEY, p.base_url)
        if base is None:
            return
        if cli != models.DEFAULT_CLI_TYPE:
            async def _op_cli_key():
                return "auth_result", await self._activate_cli_alt(
                    cli, auth_store.API_KEY, p.api_key, base or None, frame.id)
            self.host._spawn_tracked(conn_id, frame.id, "auth_apikey", _op_cli_key())
            return
        p = p.model_copy(update={"base_url": base or None})

        async def _op_apikey():
            ok, err = await self._activate_apikey(
                p.api_key, p.base_url, frame.id)
            return "auth_result", {"ok": ok, "error": err}
        self.host._spawn_tracked(
            conn_id, frame.id, "auth_apikey", _op_apikey())
        return

    async def _h_auth_token(self, conn_id, frame, p):
        # §auth: вставленный долгоживущий токен подписки (Claude, способ 4)
        cli = p.cliType or models.DEFAULT_CLI_TYPE
        if await self._auth_alt_precheck(conn_id, frame, cli, cli_registry.AUTH_TOKEN,
                                         None) is None:
            return
        token = p.token.strip()
        if not token.isprintable() or any(c.isspace() for c in token):
            return await self._cli_auth_err(conn_id, frame, Err.BAD_FRAME,
                                            i18n.Msg("auth.token_invalid"))

        async def _op_token():
            from ... import usage
            res = await usage.fetch_limits(self.config, token=token)
            self.host._mark_committing(frame.id)
            if res.get("error") == "auth" or res.get("error") == "http":
                return "auth_result", {"ok": False, "cliType": cli, "method": "token",
                                       "error": i18n.Msg("probe.key_rejected",
                                                         status=401)}
            if res.get("error"):
                return "auth_result", {"ok": False, "cliType": cli, "method": "token",
                                       "error": i18n.Msg("probe.check_failed",
                                                         detail=str(res.get("message")))}
            write_secret_file(self.config.oauth_token_file, token)
            await self._quiet_stop_login()
            log.info("auth.token_activated")
            # как успех OAuth: стирает альт-режим, сбрасывает модели, пересоздаёт сессии
            await self._claude_login_succeeded()
            return "auth_result", {"ok": True, "cliType": cli, "method": "token",
                                   "error": None}
        self.host._spawn_tracked(conn_id, frame.id, "auth_token", _op_token())
        return

    async def _h_auth_gateway(self, conn_id, frame, p):
        # §auth: шлюз для любого CLI; у Claude это тот же omniroute-флоу.
        base = await self._auth_alt_precheck(
            conn_id, frame, p.cliType or models.DEFAULT_CLI_TYPE,
            cli_registry.AUTH_GATEWAY, p.base_url)
        if base is None:
            return
        cli = p.cliType or models.DEFAULT_CLI_TYPE
        if cli != models.DEFAULT_CLI_TYPE:
            async def _op_cli_gw():
                return "auth_result", await self._activate_cli_alt(
                    cli, auth_store.GATEWAY, p.api_key, base, frame.id,
                    models_sel=[{"id": m.id, "name": m.name} for m in p.models],
                    active_id=p.active_id, api_backend=p.api_backend)
            self.host._spawn_tracked(conn_id, frame.id, "auth_gateway", _op_cli_gw())
            return
        omni = AuthOmniRoutePayload(
            api_key=p.api_key, base_url=base, models=p.models,
            active_id=p.active_id, small_fast_id=p.small_fast_id)
        return await self._h_auth_omniroute(conn_id, frame, omni)

    async def _h_auth_omniroute(self, conn_id, frame, p):
        # §altauth: активировать шлюз (ключ + base_url + выбранные модели).
        base = await self._auth_alt_precheck(
            conn_id, frame, models.DEFAULT_CLI_TYPE, cli_registry.AUTH_GATEWAY,
            p.base_url)
        if base is None:
            return
        p = p.model_copy(update={"base_url": base})

        async def _op_omni():
            ok, err = await self._activate_omniroute(p, frame.id)
            return "auth_result", {"ok": ok, "error": err}
        self.host._spawn_tracked(
            conn_id, frame.id, "omni_activate", _op_omni())
        return

    async def _h_omniroute_probe_models(self, conn_id, frame, p):
        # §omni шаг 1: каталог моделей шлюза. Ключ пуст → берём сохранённый
        # (редактирование без ввода ключа), но ТОЛЬКО на сохранённый base_url:
        # не отправляем секрет на произвольный клиентский URL (Fable SF1).
        if cli_registry.spec_for(p.cliType) is None:
            # до любого чтения auth_store: cliType идёт в имя файла
            await self.hub.send_global(conn_id, make_frame(
                "omniroute_catalog",
                {"ok": False, "error": f"unknown cliType {p.cliType!r}"[:80],
                 "code": Err.CLI_UNKNOWN, "providers": [],
                 "cliType": p.cliType, "related": frame.id}))
            return
        base = (p.base_url or "").strip()
        key = (p.api_key or "").strip()
        if base:
            try:                       # тот же контроль URL, что при активации
                base = auth_store.validate_base_url(base)
            except ValueError as e:
                await self.hub.send_global(conn_id, make_frame(
                    "omniroute_catalog",
                    {"ok": False, "error": i18n.Msg(str(e)), "providers": [],
                     "cliType": p.cliType, "related": frame.id}))
                return
        if not key:
            auth = self.config.load_auth_config() if p.cliType == "claude" \
                else auth_store.load(self.config, p.cliType)
            if auth.get("mode") == "omniroute" or auth.get("method") == "gateway":
                stored_base = auth.get("base_url", "")
                if not base or base == stored_base:
                    base = base or stored_base
                    key = auth.get("api_key", "")
        if not base or not key:
            # §netwait L2: мгновенный отказ — op не регистрируем.
            await self.hub.send_global(conn_id, make_frame(
                "omniroute_catalog",
                {"ok": False, "error": i18n.Msg("omni.no_base_or_key"),
                 "providers": [], "cliType": p.cliType,
                 "related": frame.id}))
            return
        cli = p.cliType

        async def _op_probe():
            data = await self._omniroute_catalog(base, key)
            data["cliType"] = cli
            return "omniroute_catalog", data
        self.host._spawn_tracked(
            conn_id, frame.id, "omni_probe", _op_probe())
        return

    async def _h_omniroute_set_key(self, conn_id, frame, p):
        # §omni: сменить только ключ активного omniroute (модели сохраняются).
        async def _op_setkey():
            ok, err = await self._set_omniroute_key(p.api_key, frame.id)
            return "omniroute_set_result", {"ok": ok, "error": err}
        self.host._spawn_tracked(
            conn_id, frame.id, "omni_setkey", _op_setkey())
        return

    async def _h_omniroute_set_models(self, conn_id, frame, p):
        # §omni шаг 1: сохранить выбор моделей (без тир-лимита — режет клиент).
        ok, err = self._save_omniroute_models(p)
        if ok:
            await self.host._reset_all_chat_models()   # выбор мог протухнуть (§models L2)
            await self.host._restart_cli_sessions(models.DEFAULT_CLI_TYPE)
            self.host._invalidate_models_cache()
            await self.host._broadcast_cli_status(models.DEFAULT_CLI_TYPE)
        await self.hub.send_global(conn_id, make_frame(
            "omniroute_set_result", {"ok": ok, "error": err}))
        return

    async def _h_logout(self, conn_id, frame, p):
        cli = p.cliType or models.DEFAULT_CLI_TYPE
        if cli != models.DEFAULT_CLI_TYPE:       # §multi-cli (§18.7)
            return await self._cli_logout(conn_id, cli)
        # §13: разлогин. /logout в SDK не работает (интерактивная
        # команда), поэтому удаляем сохранённый OAuth-токен и пересоздаём
        # claude-сессии. Следующий user_msg → AUTH_REQUIRED → auth-флоу.
        # M: если прямо сейчас идёт OAuth-флоу — гасим его ДО unlink, иначе он
        # дожуёт код и запишет токен уже ПОСЛЕ разлогина (broadcast ok). stop()
        # отменяет задачу флоу до удаления файла → сохранения после нет.
        if self.auth.running or self._login_op is not None:
            await self._abort_login("logged out")
        # Слоистый выход (только multi_cli-клиенты): при активном ключе/шлюзе снимаем
        # ТОЛЬКО его — OAuth-токен подписки не трогаем (как у остальных CLI, §22.2).
        # Старые клиенты — прежний полный разлогин.
        layered = (self.hub.conn_has_cap(conn_id, cli_registry.MULTI_CLI_CAP)
                   and auth_store.active_method(self.config, cli)
                   != auth_store.SUBSCRIPTION)
        if not layered:
            try:
                self.config.oauth_token_file.unlink(missing_ok=True)
            except OSError as e:
                log.warning("auth.logout_unlink_failed", err=str(e))
        # §altauth: разлогин сбрасывает и альт-способ (API-ключ/OmniRoute).
        self.config.clear_auth_config()
        await self.host._reset_all_chat_models()    # §models L2: выбор мог протухнуть
        await self.host._restart_cli_sessions(models.DEFAULT_CLI_TYPE)
        self.host._invalidate_models_cache()   # §models: сбросить/переобновить
        await self.host._broadcast_cli_status(models.DEFAULT_CLI_TYPE)
        log.info("auth.logout")
        return

    # ---------- авторизация Claude (§13) ----------

    async def _auth_broadcast(self, ftype: str, payload: dict):
        """auth_link / auth_result — глобально всем соединениям, без журнала."""
        self._login_broadcast_hook(ftype)   # §netwait: гасим login-таймеры по шагам
        await self.hub.broadcast_global(make_frame(ftype, payload))
        if ftype == "auth_result" and payload.get("ok"):
            await self._claude_login_succeeded()

    async def _claude_login_succeeded(self) -> None:
        """Вход Claude по подписке состоялся (OAuth-флоу или вставленный токен)."""
        # §omni: OAuth-успех = вход по подписке → СТИРАЕМ альт-авторизацию
        # (auth.json), иначе остался бы mode=omniroute и build_auth_env/
        # list_models продолжили бы отдавать модели шлюза (баг: после входа
        # по подписке в CLI-view висели omniroute-модели). apikey/omniroute шлют
        # auth_result напрямую.
        self.config.clear_auth_config()
        await self.host._reset_all_chat_models()      # per-chat выбор мог быть omniroute-id
        # Новый OAuth-токен: пересоздаём claude-сессии, чтобы SDK
        # подхватил env CLAUDE_CODE_OAUTH_TOKEN на следующем user_msg.
        await self.host._restart_cli_sessions(models.DEFAULT_CLI_TYPE)
        self.host._invalidate_models_cache()   # §models: список мог смениться
        await self.host._broadcast_cli_status(models.DEFAULT_CLI_TYPE)

    # -- login single-flight: таймеры на сетевые под-ожидания (M2) --

    def _start_login_timers(self, op_id: str, conn_id: int, phase: str):
        """phase='start' (auth_start→auth_link) или 'code' (auth_code→auth_result).
        Один набор одновременно (single-flight)."""
        self._cancel_login_timers()
        slow = asyncio.create_task(
            self.host._emit_op_slow(op_id, "login", conn_id, True))   # broadcast
        hard = asyncio.create_task(self._login_hard_timeout(op_id))
        self._login_op = {"op_id": op_id, "conn_id": conn_id, "phase": phase,
                          "slow_task": slow, "hard_task": hard}

    def _cancel_login_timers(self):
        lop = self._login_op
        if lop is not None:
            lop["slow_task"].cancel()
            lop["hard_task"].cancel()

    async def _login_hard_timeout(self, op_id: str):
        try:
            await asyncio.sleep(self.config.op_hard_timeout)
        except asyncio.CancelledError:
            return
        lop = self._login_op
        if lop is not None and lop["op_id"] == op_id:
            log.warning("netwait.login_timeout", op=op_id)
            # H2: снимаем состояние САМИ до broadcast (не через хук — иначе
            # _cancel_login_timers отменил бы ЭТУ задачу на suspension внутри
            # broadcast_global и терминальный auth_result потерялся бы). hard_task
            # (это мы) не трогаем; гасим только slow.
            self._login_op = None
            lop["slow_task"].cancel()
            await self.auth.stop()
            await self._auth_broadcast(
                "auth_result", {"ok": False, "error": "authorization timed out"})

    # ---------- публичный API для хоста и соседних сервисов ----------

    def token_rejected(self, cli: str) -> bool:
        """MED-1: CLI ответил 401 при живом токене подписки."""
        return cli in self._cli_token_rejected

    def clear_token_rejected(self, cli: str) -> bool:
        """MED-1: снять отметку (токен снова работает). True — была снята."""
        if cli in self._cli_token_rejected:
            self._cli_token_rejected.discard(cli)
            return True
        return False

    async def abort_login_if(self, op_id: str) -> None:
        """op_abort: прервать текущий вход, если это операция op_id; иначе no-op."""
        lop = self._login_op
        if lop is not None and lop["op_id"] == op_id:
            await self._abort_login("authorization aborted")

    async def _abort_login(self, reason: str):
        self._cancel_login_timers()
        self._login_op = None                 # хук увидит None → без двойной чистки
        await self.auth.stop()
        await self._auth_broadcast(
            "auth_result", {"ok": False, "error": reason})

    async def _quiet_stop_login(self):
        """Погасить идущий OAuth-флоу подписки БЕЗ broadcast auth_result.
        Нужно при активации omniroute/apikey: осиротевший setup-token (его мог
        авто-поднять on_auth_required до перехода на шлюз) иначе дожил бы до
        внутреннего 600с в auth.py и выстрелил глобальным «...600s». В отличие от
        _abort_login НЕ шлём ok:false — иначе ошибка мигнула бы сразу после
        auth_result{ok:true} активации."""
        if self.auth.running or self._login_op is not None:
            self._cancel_login_timers()
            self._login_op = None
            await self.auth.stop()
            log.info("auth.quiet_stop_login")

    async def _on_chat_auth_required(self):
        """Хук claude-сессии при AUTH_REQUIRED. Для omniroute/apikey НЕ поднимаем
        OAuth-флоу подписки: AUTH_REQUIRED в этих режимах = отказ шлюза/ключа, а
        не повод запускать setup-token, который юзер не завершит → через 600с
        ложный глобальный auth_result «...600s» (а модель при этом отвечает). Чат
        уже получил Err.AUTH_REQUIRED до вызова хука. Для подписки/без режима —
        прежнее поведение (авто-старт)."""
        mode = self.config.load_auth_config().get("mode")
        if mode in ("omniroute", "apikey"):
            log.info("auth.skip_oauth_on_alt_mode", mode=mode)
            return
        await self.auth.start()

    def _login_broadcast_hook(self, ftype: str):
        """Гасит login-таймеры по шагам (M2): start-фазу — auth_link|auth_result,
        code-фазу — только auth_result. Идемпотентно."""
        lop = self._login_op
        if lop is None:
            return
        if ftype == "auth_link" and lop["phase"] == "start":
            self._cancel_login_timers()       # ссылка пришла; ждём код (клиент)
            self._login_op = None
        elif ftype == "auth_result":
            self._cancel_login_timers()
            self._login_op = None

    @staticmethod
    def _json_obj(text: str) -> dict | None:
        """Тело ответа как JSON-объект или None (HTML/пустое/массив/скаляр)."""
        t = (text or "").lstrip()
        if not t.startswith("{"):
            return None
        try:
            obj = json.loads(t)
        except ValueError:
            return None
        return obj if isinstance(obj, dict) else None

    @staticmethod
    def _looks_like_api_error(text: str) -> bool:
        """S1-M: тело — JSON-ошибка Anthropic/OpenAI-совместимого API, т.е. это
        настоящий API-шлюз. Anthropic: {"type":"error","error":{…}}; OpenAI и
        шлюзы: {"error":{…}} (error — ОБЪЕКТ). Строковый {"error":"Not Found"}
        и FastAPI {"detail":…} — стоковые ответы чужих JSON-хостов → False."""
        obj = CliAuthService._json_obj(text)
        if obj is None:
            return False
        return obj.get("type") == "error" or isinstance(obj.get("error"), dict)

    async def _probe_auth(self, base_url: str | None, api_key: str,
                          model: str) -> tuple[bool, str | None]:
        """Лёгкая проверка креденшела: 1-токенный запрос к <base>/v1/messages
        с заголовком x-api-key.

        S1-M: НЕ считаем «валидно» всё подряд, кроме 401/403 — опечатка base_url,
        отдающая 404/5xx/HTML(даже со статусом 200 от веб-консоли/SPA-фолбэка),
        раньше активировала мусорный конфиг и перезапускала ВСЕ сессии. Теперь:
          401/403 → отказ ключа; 5xx → сервер недоступен;
          2xx → ок ТОЛЬКО если тело — JSON-объект (настоящий /v1/messages), не HTML;
          прочие 4xx → ок ТОЛЬКО если тело — Anthropic/OpenAI-подобная JSON-ошибка
          (unknown model/invalid request доказывает: ключ принят, эндпоинт настоящий).
        Остаточный компромисс: верный хост, но неверный ПУТЬ (…/api) может отдать
        валидный not_found JSON до проверки ключа — примем как «ок» (шлюзы отдают
        такой же 404 на unknown-model, отличить нельзя)."""
        import aiohttp
        root = (base_url or "https://api.anthropic.com").rstrip("/")
        url = f"{root}/v1/messages"
        headers = {
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        body = {"model": model, "max_tokens": 1,
                "messages": [{"role": "user", "content": "."}]}
        try:
            timeout = aiohttp.ClientTimeout(total=15)
            async with aiohttp.ClientSession(timeout=timeout) as sess:
                async with sess.post(url, json=body, headers=headers,
                                     allow_redirects=False) as r:
                    if 300 <= r.status < 400:   # ключ не должен уйти на чужой хост по Location
                        return False, i18n.Msg(
                            "probe.redirect", status=r.status,
                            host=key_probe.redirect_host(r.headers.get("Location")))
                    if r.status in (401, 403):
                        return False, i18n.Msg("probe.key_rejected", status=r.status)
                    if r.status >= 500:
                        return False, i18n.Msg("probe.server_unavailable_status", status=r.status)
                    # читаем ограниченный кусок тела (L: не тянем в память
                    # мегабайты с чужого хоста) — первых 64 КБ хватает для класс-ции
                    raw = await r.content.read(65536)
                    text = raw.decode("utf-8", "replace")
                    if 200 <= r.status < 300:
                        if self._json_obj(text) is not None:
                            return True, None   # настоящий JSON-ответ message
                        return False, i18n.Msg("probe.not_anthropic_200")
                    if self._looks_like_api_error(text):
                        return True, None       # ключ принят, модель/запрос отвергнуты
                    return False, i18n.Msg("probe.not_anthropic_status",
                                          status=r.status)
        except (asyncio.TimeoutError, TimeoutError):
            return False, i18n.Msg("probe.timeout")
        except aiohttp.ClientError as e:
            return False, i18n.Msg("probe.server_unavailable", detail=secrets_redact.redact(str(e)))
        except Exception as e:  # noqa: BLE001 — валидация не должна ронять хендлер
            return False, i18n.Msg("probe.check_failed", detail=secrets_redact.redact(str(e)))

    async def _activate_apikey(self, api_key: str, base_url: str | None,
                               op_id: str | None = None) -> tuple[bool, str | None]:
        ok, err = await self._probe_auth(
            base_url, api_key, "claude-3-5-haiku-latest")
        self.host._mark_committing(op_id)   # §netwait H2: сетевая фаза прошла
        if not ok:
            return False, err
        self.config.save_auth_config({
            "mode": "apikey", "api_key": api_key, "base_url": base_url or None})
        await self._quiet_stop_login()   # осиротевший setup-token → ложный «600s»
        await self.host._reset_all_chat_models()    # §models L2: выбор мог протухнуть
        await self.host._restart_cli_sessions(models.DEFAULT_CLI_TYPE)
        self.host._invalidate_models_cache()   # §models: список зависит от ключа
        await self.host._broadcast_cli_status(models.DEFAULT_CLI_TYPE)
        log.info("auth.apikey_activated", base_url=base_url or "anthropic")
        return True, None

    @staticmethod
    def _clean_omni_models(items) -> list[dict]:
        """OmniModel[] → [{id,name}] с клампом имени ≤15 (защитно; основной
        лимит длины — на клиенте). Пустое имя → id."""
        out = []
        for m in items:
            name = ((m.name or "").strip() or m.id)[:15]   # fallback тоже ≤15 (N1)
            out.append({"id": m.id, "name": name})
        return out

    async def _activate_omniroute(self, p,
                                  op_id: str | None = None) -> tuple[bool, str | None]:
        # §omni новый вид: ключ + base_url + выбранные модели (любые, без
        # opus/sonnet/haiku-логики). Легаси-вид (3 слота) — совместимость.
        if p.models:
            ids = [m.id for m in p.models]
            idset = set(ids)
            active = p.active_id if p.active_id in idset else ids[0]
            small = p.small_fast_id if p.small_fast_id in idset else active
            # §omni: активацию НЕ блокируем probe'ом шлюза. base_url+ключ уже
            # подтверждены шагом omniroute_probe_models (каталог моделей), а probe
            # КОНКРЕТНОЙ модели хрупок — free-провайдеры (deepseek/gemini) флапают
            # 5xx и зря роняли активацию «сервер недоступен (500)». Пишем конфиг
            # так же, как omniroute_set_models («Изменить модели») — без шлюза.
            self.host._mark_committing(op_id)
            self.config.save_auth_config({
                "mode": "omniroute", "api_key": p.api_key, "base_url": p.base_url,
                "models": self._clean_omni_models(p.models),
                "active_id": active, "small_fast_id": small})
            log.info("auth.omniroute_activated", base_url=p.base_url,
                     new=True, n=len(ids), active=active)
        else:
            # Легаси-вид: 3 слота + алиас default_tier (как раньше).
            tier_model = {
                "opus": p.opus_model, "sonnet": p.sonnet_model,
            }.get(p.default_tier, p.haiku_model)
            if not tier_model:
                return False, i18n.Msg("omni.no_gateway_models")
            self.host._mark_committing(op_id)   # активацию не блокируем probe'ом шлюза
            self.config.save_auth_config({
                "mode": "omniroute", "api_key": p.api_key, "base_url": p.base_url,
                "opus_model": p.opus_model, "sonnet_model": p.sonnet_model,
                "haiku_model": p.haiku_model,
                "default_tier": p.default_tier or "haiku"})
            log.info("auth.omniroute_activated", base_url=p.base_url,
                     new=False, default_tier=p.default_tier)
        await self._quiet_stop_login()   # убить осиротевший setup-token (ложный «600s»)
        await self.host._reset_all_chat_models()    # §models L2: выбор мог протухнуть
        await self.host._restart_cli_sessions(models.DEFAULT_CLI_TYPE)
        self.host._invalidate_models_cache()   # §models: список зависит от шлюза
        await self.host._broadcast_cli_status(models.DEFAULT_CLI_TYPE)
        return True, None

    async def _omniroute_catalog(self, base_url: str, api_key: str) -> dict:
        """§omni шаг 1: каталог моделей шлюза (сгруппированный) с кэшем по
        base_url. Ошибку сети/HTTP отдаём как {ok:False,error,providers:[]}."""
        # Ключ кэша учитывает и ключ (S3): разные ключи → разные entitlements/
        # валидность, не переиспользуем чужой каталог.
        key = (base_url.rstrip("/") + "\0"
               + hashlib.sha256(api_key.encode()).hexdigest()[:16])
        now = time.time()
        hit = self._omni_catalog_cache.get(key)
        if hit is not None and now - hit[0] < self._OMNI_CATALOG_TTL:
            return copy.deepcopy(hit[1])   # S4: не отдаём общий изменяемый объект
        try:
            cat = await omniroute_gw.fetch_catalog(base_url, api_key)
        except Exception as e:  # noqa: BLE001 — сетевую ошибку показываем клиенту
            log.warning("omni.catalog_error", err=repr(e))
            return {"ok": False, "error": str(e), "providers": []}
        data = {"ok": True, **cat}
        self._omni_catalog_cache[key] = (now, data)
        self._evict_omni_cache(now)
        return copy.deepcopy(data)

    def _evict_omni_cache(self, now: float) -> None:
        """L: не даём кэшу каталога расти без предела — сначала выкидываем
        просроченные, затем (если всё ещё выше потолка) самые старые."""
        cache = self._omni_catalog_cache
        for k in [k for k, (ts, _) in cache.items()
                  if now - ts >= self._OMNI_CATALOG_TTL]:
            del cache[k]
        if len(cache) > self._OMNI_CATALOG_MAX:
            for k in sorted(cache, key=lambda k: cache[k][0])[
                    :len(cache) - self._OMNI_CATALOG_MAX]:
                del cache[k]

    def _save_omniroute_models(self, p) -> tuple[bool, str | None]:
        """§omni шаг 1: сохранить выбор моделей в активный omniroute-конфиг
        (переиспользуя api_key/base_url). Без тир-лимита."""
        auth = self.config.load_auth_config()
        if auth.get("mode") != "omniroute" or not auth.get("api_key"):
            return False, i18n.Msg("omni.not_active")
        ids = [m.id for m in p.models]
        if not ids:
            return False, i18n.Msg("omni.models_empty")
        idset = set(ids)
        if p.active_id not in idset:
            return False, i18n.Msg("omni.active_not_in_list")
        if p.small_fast_id not in idset:
            return False, i18n.Msg("omni.small_not_in_list")
        new_auth = {
            "mode": "omniroute",
            "api_key": auth["api_key"], "base_url": auth.get("base_url", ""),
            "models": self._clean_omni_models(p.models),
            "active_id": p.active_id, "small_fast_id": p.small_fast_id}
        self.config.save_auth_config(new_auth)   # легаси-поля отброшены
        log.info("omni.models_saved", n=len(ids),
                 active=p.active_id, small=p.small_fast_id)
        return True, None

    async def _set_omniroute_key(self, api_key: str,
                                 op_id: str | None = None) -> tuple[bool, str | None]:
        """§omni: сменить ТОЛЬКО ключ активного omniroute-подключения. Проба по
        активной модели валидирует именно КЛЮЧ (401/403 = отказ; «unknown model»
        400/404 = ключ валиден). Модели/active/small_fast/base_url сохраняем."""
        auth = self.config.load_auth_config()
        if auth.get("mode") != "omniroute":
            return False, i18n.Msg("omni.not_active")
        base = auth.get("base_url", "")
        # активная модель для пробы: новый вид → active_id; легаси → любой слот.
        probe = (auth.get("active_id") or auth.get("haiku_model")
                 or auth.get("sonnet_model") or auth.get("opus_model") or "")
        if not probe:
            return False, i18n.Msg("omni.no_probe_model")
        ok, err = await self._probe_auth(base, api_key, probe)
        self.host._mark_committing(op_id)   # §netwait H2: сетевая фаза прошла
        if not ok:
            return False, err
        self.config.save_auth_config({**auth, "api_key": api_key})
        await self._quiet_stop_login()   # убить осиротевший setup-token (ложный «600s»)
        await self.host._restart_cli_sessions(models.DEFAULT_CLI_TYPE)   # новый ключ в env новой сессии
        self.host._invalidate_models_cache()
        await self.host._broadcast_cli_status(models.DEFAULT_CLI_TYPE)
        log.info("omni.key_updated", base_url=base)
        return True, None

    # ------------------- §multi-cli: вход не-Claude CLI -------------------

    def _auth_manager(self, cli: str):
        return {"antigravity": self.agy_auth,
                "codex": self.codex_auth,
                "grok": self.grok_auth}.get(cli)

    async def _cli_auth_err(self, conn_id, frame, code: str, text: str):
        await self.hub.send_global(conn_id, make_error(
            code, text, related=getattr(frame, "id", None)))

    async def _cli_auth_start(self, conn_id, frame, cli: str):
        if cli_registry.spec_for(cli) is None:
            return await self._cli_auth_err(conn_id, frame, Err.CLI_UNKNOWN,
                                            f"unknown cliType {cli!r}")
        mgr = self._auth_manager(cli)
        if mgr is None:
            return await self._cli_auth_err(conn_id, frame, Err.CLI_UNAVAILABLE,
                                            f"{cli!r} has no auth flow")
        async with self._auth_lock(cli):    # не стартуем вход посреди смены способа
            if auth_store.active_method(self.config, cli) != auth_store.SUBSCRIPTION:
                # активен API-ключ/шлюз: вход по подписке — только после выхода из него
                await self.hub.send_global(conn_id, make_frame("auth_result", {
                    "ok": False, "cliType": cli,
                    "error": i18n.Msg("auth.alt_mode_active")}))
                return
            await mgr.start()

    async def _cli_auth_code(self, conn_id, p):
        mgr = self._auth_manager(p.cliType)
        if mgr is not None and not getattr(mgr, "needs_code", True):
            # device-code вход (Codex): код вводят на сайте, Ёжику его слать не надо
            await self.hub.send_global(conn_id, make_frame("auth_result", {
                "ok": False, "cliType": p.cliType,
                "error": i18n.Msg("auth.code_not_needed")}))
            return
        if mgr is None or not await mgr.submit_code(p.code):
            await self.hub.send_global(conn_id, make_frame("auth_result", {
                "ok": False, "cliType": p.cliType,
                "error": "no auth flow in progress"}))

    async def _cli_logout(self, conn_id, cli: str):
        # весь выход (от quiesce до cli_status) — под замком CLI; очередь
        # возобновляем строго после выхода из него
        async with self._auth_lock(cli):
            pending = await self._cli_logout_locked(cli)
        await self.host._resume_queued(pending)

    async def _cli_logout_locked(self, cli: str) -> list:
        if auth_store.active_method(self.config, cli) != auth_store.SUBSCRIPTION:
            # снимаем активный API-ключ/шлюз; вход по подписке (токен) не трогаем
            pending = await self.host._quiesce_cli(cli, notify_busy=True)
            auth_store.clear(self.config, cli)
            try:
                await self._apply_alt_mode(cli, {})
            except Exception as e:  # noqa: BLE001 — режим уже снят, чистка best-effort
                log.warning("auth.alt_clear_failed", cli=cli,
                            err=secrets_redact.redact(repr(e)))
            await self._after_auth_change(cli)
            log.info("auth.alt_logout", cli=cli)
            return pending
        mod = LOGIN_MODULES.get(cli)
        if mod is None:
            return []
        await self._auth_manager(cli).stop()
        pending = await self.host._quiesce_cli(cli, notify_busy=False)
        mod.logout()
        self.host._invalidate_models_cache()
        log.info("auth.logout", cli=cli)
        await self.host._broadcast_cli_status(cli)
        return pending

    async def _activate_cli_alt(self, cli: str, method: str, api_key: str,
                                base_url: str | None, op_id: str | None = None, *,
                                models_sel: list[dict] | None = None,
                                active_id: str = "",
                                api_backend: str = "") -> dict:
        """§auth: активировать API-ключ или шлюз не-Claude CLI. Проверяет ключ
        запросом каталога моделей, пишет auth.<cli>.json (0600), гасит вход по
        подписке, прерывает сессии CLI с ошибкой. Возвращает payload auth_result.
        Весь процесс — под _auth_lock(cli): две активации подряд исполняются
        строго по очереди (итог = последняя), очередь чатов возобновляется
        после выхода из замка."""
        async with self._auth_lock(cli):
            res, pending = await self._activate_cli_alt_locked(
                cli, method, api_key, base_url, op_id, models_sel=models_sel,
                active_id=active_id, api_backend=api_backend)
        await self.host._resume_queued(pending)
        return res

    async def _activate_cli_alt_locked(self, cli, method, api_key, base_url,
                                       op_id, *, models_sel, active_id,
                                       api_backend) -> tuple[dict, list]:
        spec = cli_registry.spec_for(cli)
        res = {"cliType": cli, "method": method}
        if cli == "grok" and grok_auth.managed_home() is None:
            # HEDGEHOG_GROK_HOME=system: изолированного альт-каталога нет, а ключ в
            # личном ~/.grok не отключил бы токен подписки — режим недоступен
            return {**res, "ok": False,
                    "error": i18n.Msg("auth.method_unsupported")}, []
        if method == auth_store.GATEWAY and not base_url:
            return {**res, "ok": False, "error": i18n.Msg("omni.no_base_or_key")}, []
        ok, err, ids = await key_probe.probe(spec.key_probe, base_url, api_key)
        self.host._mark_committing(op_id)
        if not ok:
            return {**res, "ok": False, "error": err}, []
        rec = {"method": method, "api_key": api_key, "base_url": base_url or None,
               "updated_at": time.time()}
        if not spec.gateway_models:
            # модели фиксирует сам CLI, но с ключом доступен лишь каталог API
            # (agy: static-список содержит claude/gpt, которых у Gemini API нет)
            rec["catalog"] = [i for i in ids if i.startswith("gemini")][:100]
        if method == auth_store.GATEWAY:
            if spec.gateway_models:
                sel = [m for m in (models_sel or []) if m.get("id")] \
                    or [{"id": i, "name": i} for i in ids[:50]]
                if not sel:
                    return {**res, "ok": False,
                            "error": i18n.Msg("omni.models_empty")}, []
                known = {m["id"] for m in sel}
                if active_id and active_id not in known:
                    return {**res, "ok": False,
                            "error": i18n.Msg("omni.active_not_in_list")}, []
                rec.update(models=[{"id": m["id"],
                                    "name": (str(m.get("name") or m["id"]))[:40]}
                                   for m in sel],
                           active_id=active_id or sel[0]["id"],
                           api_backend=api_backend or None)
        prev = auth_store.load(self.config, cli)     # для отката к прежнему режиму
        pending = await self.host._quiesce_cli(cli, notify_busy=True)
        auth_store.save(self.config, cli, rec)
        try:
            await self._apply_alt_mode(cli, rec)
        except Exception as e:  # noqa: BLE001 — не оставляем полуприменённый режим
            detail = secrets_redact.redact(str(e))
            log.warning("auth.alt_apply_failed", cli=cli,
                        err=secrets_redact.redact(repr(e)))
            # откат к ПРЕЖНЕМУ режиму (а не к «подписке»): запись и побочные эффекты
            if prev:
                auth_store.save(self.config, cli, prev)
            else:
                auth_store.clear(self.config, cli)
            try:
                await self._apply_alt_mode(cli, prev)
            except Exception as e2:  # noqa: BLE001 — только в лог
                log.warning("auth.alt_rollback_failed", cli=cli,
                            err=secrets_redact.redact(repr(e2)))
            await self.host._broadcast_cli_status(cli)
            return {**res, "ok": False, "error": i18n.Msg(
                "probe.check_failed", detail=detail[:200])}, pending
        mgr = self._auth_manager(cli)
        if mgr is not None:
            await mgr.stop()             # осиротевший вход по подписке не должен
                                         # прислать ложный auth_result позже
        await self._after_auth_change(cli)
        log.info("auth.alt_activated", cli=cli, method=method,
                 base_url=base_url or "default")
        return {**res, "ok": True, "error": None}, pending

    async def _apply_alt_mode(self, cli: str, rec: dict) -> None:
        """Побочные эффекты режима для конкретного CLI (rec={} — режим снят)."""
        mod = LOGIN_MODULES.get(cli)       # apply_alt: sync или async
        if mod is None:
            return
        res = mod.apply_alt(rec)
        if asyncio.iscoroutine(res):
            await res

    async def _after_auth_change(self, cli: str) -> None:
        """Способ входа CLI изменился (сессии уже остановлены quiesce): сбросить
        выбор модели/кэш, оповестить клиентов (cli_status). Под _auth_lock.
        M4: каждому чату со сброшенной моделью — chat_updated (как у Claude в
        _reset_all_chat_models), клиент не держит протухший выбор."""
        for m in self.store.list():                      # модели прежнего способа
            st = m.cliSessions.get(cli) or {}
            if st.get("model") or st.get("effort"):
                updated = self.store.set_cli_state(m.chatId, cli, model=None,
                                                   effort=None)
                if updated is not None:
                    await self.host._broadcast_meta("chat_updated", updated)
        self._cli_token_rejected.discard(cli)   # MED-1: другой способ — другой статус
        self.host._invalidate_models_cache()
        await self.host._broadcast_cli_status(cli)

    async def _cli_auth_broadcast(self, cli: str, ftype: str, payload: dict):
        """auth_link / auth_result не-Claude CLI — глобально, только клиентам
        multi_cli (старый клиент показал бы чужую ссылку как ссылку Claude).
        H1: сессии CLI перезапускаем только после РЕАЛЬНОГО входа — не на
        already_logged_in (входа не было; иначе 401 при живом токене каскадно
        ронял бы все чаты этого CLI)."""
        await self.hub.broadcast_global(
            make_frame(ftype, {**payload, "cliType": cli}),
            require_cap=cli_registry.MULTI_CLI_CAP)
        if (ftype == "auth_result" and payload.get("ok")
                and not payload.get("already_logged_in")):
            self._cli_token_rejected.discard(cli)   # MED-1: реальный вход
            await self.host._restart_cli_sessions(cli)
            self.host._invalidate_models_cache()
            await self.host._broadcast_cli_status(cli)

    async def _on_cli_auth_required(self, cli: str):
        """Хук сессии не-Claude CLI при AUTH_REQUIRED (ошибка в чат уже ушла).
        Ключ/шлюз отвергнуты — вход по подписке не поможет, ничего не делаем.
        Токен подписки на месте (CLI всё равно ответил 401) — для codex/grok вход
        НЕ стартуем (`codex login` стёр бы живой токен; повторный «успех»
        перезапустил бы все чаты CLI), а помечаем CLI как AUTH_REQUIRED (MED-1:
        кэш моделей хранит OK) и рассылаем cli_status. Antigravity (LOW-1) —
        прежнее поведение: `agy --login` токен не стирает, авто-старт безвреден.
        Без токена — авто-старт входа."""
        if auth_store.active_method(self.config, cli) != auth_store.SUBSCRIPTION:
            return
        mod = LOGIN_MODULES.get(cli)
        if (cli not in _AUTOLOGIN_OVER_TOKEN
                and mod is not None and mod.is_logged_in()):
            log.info("auth.required_with_token", cli=cli)
            self._cli_token_rejected.add(cli)
            await self.host._broadcast_cli_status(cli)
            return
        mgr = self._auth_manager(cli)
        if mgr is not None:
            await mgr.start()
