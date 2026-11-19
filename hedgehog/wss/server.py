"""WS-сервер Ёжика: upgrade-auth, hello, маршрутизация фреймов по chatId.

protocol/messages.md §1: Bearer проверяется ДО upgrade (401 без WS),
путь строго /v1/connect (иначе 404). После upgrade сервер первым шлёт
hello. Дальше — диспетчеризация client→server фреймов (§3).

Сессии создаются лениво: ClaudeSession — на первом user_msg, PtySession —
на первом subscribe/pty_write/user_msg (bash поднимается сразу, чтобы
клиент увидел приглашение). Один процесс держит все сессии (audit:
«sync→async, multi-process→single-process»).
"""

from __future__ import annotations

import asyncio
import re
import copy
import functools
import hashlib
import hmac
import http
import json
import os
import threading
import time
from pathlib import Path
from typing import Any

import structlog
import websockets
from websockets.asyncio.server import Request, Response, ServerConnection, serve
from websockets.protocol import State

from .. import tls

from ..bus.hub import Hub
from ..config import Config, write_secret_file
from ..core.auth import AuthManager
from ..core.claude_session import ClaudeSession
from ..core.session_base import AgentSession, SessionClosed
from ..core.hedgehog_mcp import BUILTIN_MCP_NAME
from ..core.pty_session import PtySession
from ..core import models
from ..core.gateways import omniroute as omniroute_gw
from ..protocol import (
    Attachment,
    AuthOmniRoutePayload,
    BadFrame,
    ClientFrame,
    Err,
    dumps,
    make_error,
    make_frame,
    parse_client_frame,
)
from ..scheduler import DeferPendingExists
from ..core import (agy_auth, auth_store, cli_install, cli_registry, codex_auth,
                    codex_rpc, grok_auth, key_probe, secrets_redact)
from ..core.agy_auth import AgyAuthManager
from ..core.codex_auth import CodexAuthManager
from ..core.codex_session import CodexSession
from ..core.grok_auth import GrokAuthManager
from ..core.grok_session import GrokSession
from ..core.antigravity_session import AntigravitySession
from ..store.chats import ChatMeta, ChatStore, public_meta
from ..store.mcp_registry import McpRegistry
from ..store import skills_registry
from ..store import views_registry
from ..store import handlers_registry
from ..core import handler_runner
from ..store.skill_sources import SkillSources, SkillInstallError
from .. import fileserver, i18n
from .. import authlog
from .. import updater
from .. import push

log = structlog.get_logger("wss")

# §multi-cli: сессии агентов (общие операции: caps, ui_event, ответы на запросы).
_MCP_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")  # имя MCP: без «_» в начале/спецсимволов
_AGENT_SESSIONS = AgentSession    # runtime-Protocol: Claude/agy/Codex (не PTY)
# CLI, у которых вход — отдельный менеджер (device/OAuth), и модуль-«хранилище»
# (is_logged_in/logout/apply_alt — побочные эффекты режима API-ключа/шлюза).
_LOGIN_MODULES = {"antigravity": agy_auth, "codex": codex_auth,
                  "grok": grok_auth}
# LOW-1: CLI, у которых вход поверх живого токена безвреден (`agy --login`
# токен не стирает) — на 401 стартуем вход как раньше, без проверки токена.
_AUTOLOGIN_OVER_TOKEN = frozenset({"antigravity"})

WS_PATH = "/v1/connect"

# §update: короткий SHA HEAD этого процесса — клиент сравнивает его с последним
# коммитом репозитория (GitHub) и предлагает «Обновить». Меняется только при
# рестарте после update_self (git reset --hard), поэтому кэшируем один раз.
_SERVER_COMMIT = updater.current_sha()

# §reply: доставка ответа адресату для send_to_chat. Кап одновременно ожидающих
# reply-армов на чат-инициатор (память + амплификация ходов/подпроцессов) и TTL,
# после которого «повисший» арм (ход цели так и не дал результат — трейлер-гонка/
# смерть сессии) освобождает слот лениво (при следующем арме / на доставке).
_REPLY_PENDING_CAP = 8
_REPLY_TTL = 600.0            # сек (monotonic)


class ChatRoster:
    """§roster: узкий фасад для кросс-чат MCP-тулов (list_chats/send_to_chat).
    Даёт ClaudeSession снимок чатов и прямой впрыск, НЕ пробрасывая всю ссылку
    на сервер — поверхность мала и легко подменяется фейком в тестах."""

    def __init__(self, server: "HedgehogServer"):
        self._srv = server

    def snapshot(self, running_only: bool = False) -> list[dict[str, Any]]:
        """Все чаты (или только с живой сессией) с флагом running и статусом.
        Явный набор полей — meta целиком (claude_session_id и пр.) агенту не
        отдаём (лишний шум/leak в контекст)."""
        srv = self._srv
        out: list[dict[str, Any]] = []
        for m in srv.store.list():
            running = m.chatId in srv.sessions
            if running_only and not running:
                continue
            st = srv._chat_status(m.chatId)
            out.append({
                "chatId": m.chatId, "name": m.name, "addressee": m.addressee,
                "cwd": m.cwd, "running": running,
                "status": st["status"], "last_activity": st["last_activity"],
            })
        return out

    async def inject(self, chat_id: str, text: str, sender: str,
                     interrupt: bool = False, on_result=None) -> tuple[bool, Any]:
        return await self._srv.inject_message(
            chat_id, text, sender=sender, interrupt=interrupt, on_result=on_result)

    # §reply: фасад reply-роутинга для send_to_chat (не светим весь сервер).
    def chat_name(self, chat_id: str) -> str:
        m = self._srv.store.get(chat_id)
        return (m.name if m else "") or ""

    def arm_reply(self, initiator: str, armed: float) -> bool:
        """Зарезервировать слот reply-арма для чата-инициатора (prune TTL + cap).
        False → слотов нет (слишком много ожидающих ответов)."""
        return self._srv._reply_arm(initiator, armed)

    def unarm_reply(self, initiator: str, armed: float) -> None:
        self._srv._reply_unarm(initiator, armed)

    def schedule_reply(self, *, initiator: str, mode: str, armed: float,
                       sender: str = "", body: str = "",
                       handler: str = "", args: dict | None = None) -> None:
        """Запланировать доставку ответа (из воркера цели) — не блокирует воркер."""
        self._srv._schedule_reply(initiator=initiator, mode=mode, armed=armed,
                                  sender=sender, body=body, handler=handler,
                                  args=args or {})


class HedgehogServer:
    def __init__(self, config: Config):
        self.config = config
        self.token = config.load_token()
        self.store = ChatStore(config.chats_dir)
        self.mcp = McpRegistry(config.data_dir / "mcp.json")
        self.skill_sources = SkillSources(config.data_dir / "skill_sources.json")
        self.hub = Hub(self.store)
        self.sessions: dict[str, AgentSession | PtySession] = {}
        self.auth = AuthManager(config, self._auth_broadcast)
        # §multi-cli: вход Antigravity (Google OAuth через `agy acp --login`).
        self.agy_auth = AgyAuthManager(
            config, functools.partial(self._cli_auth_broadcast, "antigravity"))
        # §20: вход OpenAI Codex (device code через `codex login --device-auth`).
        self.codex_auth = CodexAuthManager(
            config, functools.partial(self._cli_auth_broadcast, "codex"))
        self._configure_grok_home()
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
        # §push: notifyKey'и устройств (для APNs-пуша при оффлайн-клиенте).
        self.push_keys = push.PushKeys(config.push_keys_file)
        # Сильные ссылки на fire-and-forget задачи пуша: asyncio держит задачи
        # лишь слабо, без ссылки их может собрать GC до завершения.
        self._push_tasks: set[asyncio.Task] = set()
        # §reply: ожидающие reply-армы по чату-инициатору (monotonic-таймстампы);
        # cap+TTL в _reply_arm. См. send_to_chat/_deliver_reply.
        self._reply_pending: dict[str, list[float]] = {}
        # §17: ленивый серверный NekoProxy (MCP-плейн neko) для neko_open_view —
        # создаётся при первом использовании, гасится в shutdown. Глобальный (не
        # per-chat): фрейм без chatId, shared-browser-context терпит неск. сессий.
        self._neko_proxy = None
        # §sched: планировщик задач + блэкборд. Ставится из main.py после
        # конструктора (нужны колбэки inject/notify, замкнутые на этот сервер).
        self.scheduler = None
        # §models: фоновый рефрешер списка моделей. Событие взводится при смене
        # авторизации (и при пустом кэше) → немедленное обновление вне суток.
        self._models_refresh_now = asyncio.Event()
        self._omni_models_sig: str | None = None   # последняя разосланная omni-выборка
        self._models_task: asyncio.Task | None = None
        # L: держим ссылку на задачу рестарта — иначе GC мог бы её собрать до
        # execv (update вернул ok, а рестарта нет).
        self._restart_task: asyncio.Task | None = None
        # Текущая one-shot проба (для отмены при входящем user_msg — не держим
        # второй CLI-процесс во время хода, §models M1) + троттлинг проб (M2).
        self._models_probe_task: asyncio.Task | None = None
        self._last_probe_ts = 0.0
        # §omni: кэш каталога шлюза по base_url ({base: (ts, data)}), TTL ниже.
        self._omni_catalog_cache: dict[str, tuple[float, dict]] = {}
        # §roster: фасад «список чатов + прямой впрыск» для кросс-чат MCP-тулов
        # (list_chats / send_to_chat), прокидывается в каждую ClaudeSession.
        self._roster = ChatRoster(self)
        # §netwait: реестр долгих операций (opId → {conn_id,kind,broadcast,
        # work_task,slow_task,abortable}) для op_slow/op_abort/hard-timeout.
        self._ops: dict[str, dict[str, Any]] = {}
        # §netwait: текущая login-операция (single-flight): {op_id,conn_id,phase,
        # slow_task,hard_task}. Логин глобальный → таймеры отдельно от _ops.
        self._login_op: dict[str, Any] | None = None
        # S1-M: chatId'ы в процессе удаления — «надгробие» на время delete_chat.
        # _ensure_session отказывается поднимать такой чат, чтобы параллельный
        # user_msg/inject (meta прочитана до удаления) не воскресил его сессию
        # (висячий CLI-процесс + падение журнала на удалённый чат).
        self._deleting: set[str] = set()
        # §multi-cli: per-chat замок на смену CLI; id запросов, отменённых
        # сменой (поздний permission/picker/ui-ответ молча игнорируем).
        self._chat_locks: dict[str, asyncio.Lock] = {}
        # §auth: замок на CLI — сериализует активацию/выход/старт входа и создание сессий
        self._auth_locks: dict[str, asyncio.Lock] = {}
        # MED-1: CLI ответил 401 при живом токене подписки — cli_status/hello
        # отдают AUTH_REQUIRED (кэш моделей хранит OK последней удачной пробы),
        # пока не будет удачной пробы, реального входа или смены способа.
        self._cli_token_rejected: set[str] = set()
        self._stale_requests: dict[str, set[str]] = {}
        # M4: update_self в полёте — второй вызов (двойной тап/второе устройство)
        # не должен запустить 2× git reset/pip/execv. Латчится при запланированном
        # рестарте (процесс вот-вот сменится — новых обновлений не начинаем).
        self._updating = False
        # §17/§cancel: install_neko/remove_neko — фоновые задачи (single-flight),
        # НЕ в цикле кадров соединения: иначе provision (pull 15-25 мин) держал
        # бы ping/subscribe/user_msg этого соединения. Ссылки держим (GC).
        self._neko_install_task: asyncio.Task | None = None
        self._neko_remove_task: asyncio.Task | None = None
        # §15: фоновый update_self (тоже вне цикла кадров соединения).
        self._update_task: asyncio.Task | None = None
        # §cli-pins: фоновая установка CLI при set_cli/create_chat на
        # неустановленный (single-flight на CLI); чаты, ждущие установку (им —
        # error CLI_INSTALL_FAILED); флаги отмены потоков установки.
        self._cli_install_tasks: dict[str, asyncio.Task] = {}
        self._cli_install_chats: dict[str, set[str]] = {}
        self._cli_install_cancel: dict[str, Any] = {}
        # §defer-clock: смещение часов Anthropic относительно локальных
        # (serverDate из заголовка Date ответа /v1/messages − time.time()).
        # Обновляется при get_limits. Нужно, чтобы планировать defer к реальному
        # сбросу лимита, даже если системные часы сервера уехали (наблюдали −22ч).
        # Якоря monotonic/wall — чтобы поймать ШАГ часов (NTP/ресинк) после замера
        # и не доверять протухшему offset (иначе defer выстрелит мгновенно).
        self._clock_offset = 0.0
        self._clock_offset_mono = 0.0
        self._clock_offset_wall = 0.0

    # ---------- §sched: точки входа для планировщика ----------

    async def inject_message(self, chat_id: str, text: str,
                             sender: str = "cron",
                             interrupt: bool = True,
                             on_result=None) -> tuple[bool, Any]:
        """Инъекция текста в чат как user-сообщения (агент отвечает штатно).
        Тот же путь, что WS user_msg: echo в ленту + handle_user_msg.

        Возвращает (ok, info): при успехе info={"cold_started":bool,"was_busy":bool},
        при отказе info — строка-причина. Дефолты (sender="cron", interrupt=True)
        сохраняют историческое поведение планировщика (тот возврат игнорирует).
        Агентский кросс-чат впрыск (§roster) зовёт с sender="agent:<src>" и
        interrupt=False — не рвать чужой живой ход."""
        text = (text or "").strip()
        if not text:
            return False, "empty text"
        meta = self.store.get(chat_id)
        if meta is None:
            log.warning("sched.inject_skip", chat=chat_id, reason="no meta")
            return False, "chat not found"
        if meta.addressee != "claude":
            log.warning("sched.inject_skip", chat=chat_id, reason="not claude")
            return False, "target is not a claude chat"
        # §models M1: cron/планировщик/roster стартует ход в обход WS-хендлера
        # user_msg — гасим фоновую пробу тут же, иначе рядом с единственной
        # авторизацией окажутся два CLI-процесса.
        self._cancel_models_probe()
        was_running = chat_id in self.sessions
        was_busy = self._chat_status(chat_id)["status"] == "busy"
        session = await self._ensure_session(meta)
        await self.hub.publish(chat_id, "user_msg_echo", {
            "content": text, "sender": sender, "related": None,
            "attachments": [], "btw": False,
        })
        await self._deliver(chat_id, session, text, interrupt=interrupt,
                            on_result=on_result)
        return True, {"cold_started": not was_running, "was_busy": was_busy}

    # ---------- §reply: доставка ответа адресату (send_to_chat reply-роутинг) ----

    def _reply_arm(self, initiator: str, armed: float) -> bool:
        """Зарезервировать слот reply-арма (prune протухших по TTL + проверка cap).
        Ключ — чат-инициатор (получатель ответа). Хранится на СЕРВЕРЕ (не на
        сессии): декремент случается в задаче доставки вне жизни сессии."""
        now = time.monotonic()
        lst = self._reply_pending.setdefault(initiator, [])
        lst[:] = [t for t in lst if now - t < _REPLY_TTL]   # lazy-TTL
        if len(lst) >= _REPLY_PENDING_CAP:
            return False
        lst.append(armed)
        return True

    def _reply_unarm(self, initiator: str, armed: float) -> None:
        """Освободить слот (впрыск не удался / доставка состоялась). Best-effort."""
        lst = self._reply_pending.get(initiator)
        if not lst:
            return
        try:
            lst.remove(armed)
        except ValueError:
            pass
        if not lst:
            self._reply_pending.pop(initiator, None)

    def _schedule_reply(self, *, initiator: str, mode: str, armed: float,
                        sender: str, body: str, handler: str,
                        args: dict) -> None:
        """Из воркера цели: освободить слот и запланировать доставку отдельной
        задачей (воркер цели не блокируется). Протухший по TTL арм — дропаем."""
        self._reply_unarm(initiator, armed)                 # слот свободен в любом исходе
        if time.monotonic() - armed > _REPLY_TTL:
            log.warning("reply.stale_dropped", initiator=initiator, mode=mode)
            return
        task = asyncio.create_task(self._deliver_reply(
            initiator=initiator, mode=mode, sender=sender, body=body,
            handler=handler, args=args))
        self._push_tasks.add(task)
        task.add_done_callback(self._push_tasks.discard)

    async def _deliver_reply(self, *, initiator: str, mode: str, sender: str,
                             body: str, handler: str, args: dict) -> None:
        """Фактическая доставка ответа. Режим A — впрыск в чат-инициатор (БЕЗ
        on_result → нет петли). Режим B — вызов зарегистрированной в чате-
        инициаторе ручки (fire-and-forget, хода НЕ триггерит). Всё под try."""
        try:
            if mode == "A":
                await self.inject_message(initiator, body,
                                          sender=sender, interrupt=False)
            elif mode == "B":
                rec = handlers_registry.get(self.config.data_dir, initiator, handler)
                meta = self.store.get(initiator)
                if rec is None or meta is None:
                    log.warning("reply.handler_gone", initiator=initiator,
                                handler=handler)
                    return
                res = await handler_runner.run(meta.cwd, rec["script"], args)
                if not res.get("ok"):
                    log.warning("reply.handler_failed", initiator=initiator,
                                handler=handler, err=str(res.get("error"))[:200])
        except Exception as e:  # noqa: BLE001 — доставка reply не критична
            log.warning("reply.deliver_failed", initiator=initiator,
                        mode=mode, err=repr(e))

    async def _defer_failed(self, chat_id: str, job_id: str) -> None:
        """§defer S4-M3: отложенное НЕ отправлено — снимаем pending-чип
        (scheduled_cancelled, журналируемо → на всех устройствах и на resume,
        иначе висел бы вечно) и сообщаем пользователю (не теряем молча)."""
        await self.hub.publish(chat_id, "scheduled_cancelled", {"jobId": job_id})
        await self.notify_chat(chat_id, i18n.Msg("defer.title"),
                               i18n.Msg("defer.failed"))

    async def inject_user_message(self, chat_id: str, text: str,
                                  attachments: list, job_id: str) -> None:
        """§defer: отложенное сообщение пользователя сработало по таймеру.
        Эхо в ленту (sender=deferred + jobId — клиент снимет pending-чип на всех
        устройствах) + промпт с вложениями. interrupt=False — НЕ прерываем
        возможный живой ход пользователя. Плюс notify (оффлайн-курьер).

        S4-M3: на ЛЮБОМ отказе (нет чата / упал подъём сессии до эха) — вызываем
        _defer_failed, чтобы отложенное не пропало молча и чип не завис."""
        meta = self.store.get(chat_id)
        if meta is None or meta.addressee != "claude":
            log.warning("defer.inject_skip", chat=chat_id,
                        reason="no meta or not claude")
            await self._defer_failed(chat_id, job_id)
            return
        echoed = False
        try:
            self._cancel_models_probe()
            atts = [Attachment(fileId=str(a.get("fileId", "")),
                               mime=str(a.get("mime", "")),
                               name=str(a.get("name", "")))
                    for a in attachments if isinstance(a, dict)]
            session = await self._ensure_session(meta)
            await self.hub.publish(chat_id, "user_msg_echo", {
                "content": text, "sender": "deferred", "related": None,
                "attachments": [a.model_dump() for a in atts], "btw": False,
                "jobId": job_id,
            })
            echoed = True   # чип снят эхом — дальше _defer_failed не нужен
            resolved = fileserver.resolve_attachment_paths(
                self.config.chats_dir, chat_id, atts)
            prompt = fileserver.compose_prompt(text, resolved)
            await self._deliver(chat_id, session, prompt, interrupt=False)
            log.info("defer.fired", chat=chat_id, job=job_id, atts=len(atts))
            # Оффлайн-курьер: устройства узнают, что отложенное ушло агенту.
            await self.notify_chat(chat_id, i18n.Msg("defer.title"),
                                   i18n.Msg("defer.sent"))
        except Exception as e:  # noqa: BLE001 — отказ не должен теряться молча
            log.warning("defer.inject_error", chat=chat_id, job=job_id,
                        err=repr(e))
            if not echoed:
                await self._defer_failed(chat_id, job_id)   # + снять чип
            else:
                # чип уже снят эхом, но агенту не доставлено — хотя бы уведомим (M).
                await self.notify_chat(chat_id, i18n.Msg("defer.title"),
                                       i18n.Msg("defer.failed"))
            raise   # чтобы планировщик записал error в job_runs

    async def notify_chat(self, chat_id: str, title: str, body: str) -> bool:
        """Уведомление (баннер/инбокс) в чат по расписанию — журналируемый фрейм.
        S1: возвращает False, если чата нет (планировщик запишет error, а не ok)."""
        if self.store.get(chat_id) is None:
            return False
        await self.hub.publish(chat_id, "notification",
                               {"title": title or "", "body": body or ""})
        self._push_offline(chat_id, title or "", body or "")
        return True

    def _push_offline(self, chat_id: str, title: str, body: str) -> None:
        """§push: доставить уведомление КАЖДОМУ известному устройству ровно один
        раз. Устройство, подписанное на ЭТОТ чат живым соединением, уже получило
        событие по WS — пуш ему не шлём. Всем остальным (закрыто ИЛИ открыт
        другой чат — по WS не дойдёт) просим релей прислать APNs-пуш. Один
        Apple-аккаунт = несколько устройств: маршрутизируем per-device по
        deviceId. Fire-and-forget.

        Критерий «онлайн» — именно подписка на ЭТОТ chat_id (устройство реально
        получит по WS), а не «есть ли вообще соединение»: иначе устройство с
        открытым чатом A не получило бы notify для чата B никак."""
        if not self.config.push_enabled:
            return
        online = self.hub.devices_subscribed(chat_id)   # получат напрямую по WS
        for device_id, key in self.push_keys.devices():
            if device_id in online:
                continue                                # уже доставлено по WS
            # §i18n: серверные уведомления (Msg) — на языке устройства; тексты
            # агента (обычные str) уходят как есть.
            dev_lang = self.push_keys.lang_of(device_id) or i18n.DEFAULT_LANG
            t_text = title.render(dev_lang) if isinstance(title, i18n.Msg) else title
            b_text = body.render(dev_lang) if isinstance(body, i18n.Msg) else body
            task = asyncio.create_task(push.send(
                list(self.config.push_relay_urls), key, t_text, b_text, chat_id))
            self._push_tasks.add(task)
            task.add_done_callback(self._push_tasks.discard)

    # ---------- запуск ----------

    async def serve_forever(self):
        # §tls: тот же self-signed серт, что у файл-сервера (один отпечаток на
        # оба порта). TLS терминируется ДО upgrade → Bearer/hello поверх TLS.
        ssl_ctx = (tls.make_ssl_context(self.config.tls_cert_file,
                                        self.config.tls_key_file)
                   if self.config.tls_enabled else None)
        async with serve(
            self._handler,
            self.config.host,
            self.config.port,
            process_request=self._process_request,
            max_size=4 * 1024 * 1024,
            ssl=ssl_ctx,
        ):
            log.info("server.listening", host=self.config.host,
                     port=self.config.port, path=WS_PATH,
                     tls=self.config.tls_enabled)
            # §models: фоновый рефрешер кэша моделей (раз в сутки + по событию).
            if self._models_task is None:
                self._models_task = asyncio.create_task(
                    self._models_refresh_loop(), name="models-refresh")
            await asyncio.get_running_loop().create_future()  # до отмены

    async def shutdown(self):
        # §netwait H3/L4: сначала гасим login-таймеры (иначе hard-таймер мог бы
        # выстрелить в зазор до отмены), затем все долгие операции.
        self._cancel_login_timers()
        self._login_op = None
        await self.auth.stop()
        await self.agy_auth.stop()
        await self.codex_auth.stop()
        await self.grok_auth.stop()
        ops = list(self._ops.values())
        for op in ops:
            op["slow_task"].cancel()
            op["work_task"].cancel()
            if op.get("wrapper") is not None:
                op["wrapper"].cancel()
        if ops:
            tasks = [t for op in ops
                     for t in (op["work_task"], op.get("wrapper")) if t is not None]
            await asyncio.gather(*tasks, return_exceptions=True)
        self._ops.clear()
        probe = self._models_probe_task   # захватываем ДО отмены (её обнулит finally)
        self._cancel_models_probe()       # осиротевшую пробу тоже гасим
        if self._models_task is not None:
            self._models_task.cancel()
            # L: gather(return_exceptions) поглощает CancelledError/исключение
            # САМОЙ задачи, но пробрасывает отмену НАШЕГО shutdown (как у probe
            # ниже) — прежний `except (CancelledError, Exception)` глотал и её.
            await asyncio.gather(self._models_task, return_exceptions=True)
            self._models_task = None
        if probe is not None:             # дожать отменённую пробу (без warning)
            await asyncio.gather(probe, return_exceptions=True)
        if self.scheduler is not None:
            await self.scheduler.stop()
        # M: гасим ВСЕ сессии параллельно с сеткой исключений — сбой .stop()
        # одной раньше прерывал цикл и оставлял остальные висеть (утечка PTY/CLI).
        # ДО дренажа пушей: умирающая сессия может через notify→_push_offline
        # создать новую пуш-задачу, и её должен подмести gather ниже.
        sessions = list(self.sessions.values())
        self.sessions.clear()
        results = await asyncio.gather(
            *(s.stop() for s in sessions), return_exceptions=True)
        for r in results:
            if isinstance(r, Exception):
                log.warning("shutdown.session_stop_failed", err=repr(r))
        # M: fire-and-forget пуши (APNs) — отменяем и дожидаемся, иначе на
        # shutdown осиротевшие задачи → «Task was destroyed but it is pending».
        if self._push_tasks:
            for t in list(self._push_tasks):
                t.cancel()
            await asyncio.gather(*self._push_tasks, return_exceptions=True)
        # §17/§15: фоновые install/remove neko и update_self — снимаем задачи.
        # Поток to_thread не отменить, а asyncio.run ждёт его на выходе →
        # идущий docker pull прерываем флагом, чтобы shutdown не висел.
        if self._neko_install_task is not None and not self._neko_install_task.done():
            from .. import neko
            neko.cancel_provision()
        for t in (self._neko_install_task, self._neko_remove_task,
                  self._update_task):
            if t is not None and not t.done():
                t.cancel()
        # §cli-pins: установки CLI — флаг отмены (поток urllib/subprocess
        # прерывается на следующем блоке) + отмена задач.
        for ev in self._cli_install_cancel.values():
            ev.set()
        cli_tasks = [t for t in self._cli_install_tasks.values() if not t.done()]
        for t in cli_tasks:
            t.cancel()
        if cli_tasks:
            await asyncio.gather(*cli_tasks, return_exceptions=True)
        self._cli_install_tasks.clear()
        if self._neko_proxy is not None:   # §17: догасить серверный MCP-проброс neko
            await self._neko_proxy.aclose()
        await self.hub.aclose()          # backpressure: догасить close-задачи шины

    # ---------- §models: фоновый рефрешер списка моделей ----------

    _MODELS_TTL = 24 * 3600      # штатный интервал обновления кэша
    _MODELS_RETRY = 120          # переспрос, если проба отложена (агент занят)
    _MODELS_MIN_INTERVAL = 60    # троттлинг: не чаще одной пробы CLI в минуту
    _OMNI_CATALOG_TTL = 300      # §omni: кэш каталога шлюза (5 мин)
    _OMNI_CATALOG_MAX = 32       # L: потолок записей кэша (не растёт бесконечно)

    async def _models_refresh_loop(self) -> None:
        """Раз в сутки (и по событию смены авторизации) обновляет кэш моделей.
        Клиентский list_models кэш только ЧИТАЕТ — CLI тут не на его пути."""
        while True:
            delay = self._MODELS_TTL
            try:
                delay = await self._refresh_models_once()
            except asyncio.CancelledError:
                raise
            except Exception as e:  # noqa: BLE001 — рефрешер не должен падать
                log.warning("models.refresh_error", err=repr(e))
            try:
                await asyncio.wait_for(self._models_refresh_now.wait(),
                                       timeout=delay)
            except asyncio.TimeoutError:
                pass
            self._models_refresh_now.clear()

    async def _refresh_models_once(self) -> float:
        """Одна попытка обновить кэш. Возвращает СЛЕДУЮЩУЮ задержку (сек):
        занят агент → скоро (RETRY); проба недавно (троттл M2) → дождаться окна;
        успех/скип → сутки. Клиентский спам list_models так не плодит процессы."""
        # §omni S1: при активной omniroute-авторизации нового вида список — это
        # ВЫБРАННЫЕ пользователем модели (не CLI-проба). Не поднимаем CLI и
        # бродкастим выбранные, иначе рефрешер (проснувшийся на invalidate после
        # set_models) затёр бы omniroute-пикер CLI-алиасами.
        omni = self._omniroute_models_list(models.DEFAULT_CLI_TYPE)
        if omni is not None:
            # Рассылаем при первом проходе и при изменении выбора, а не на
            # каждом витке (иначе старые клиенты получали бы models_list каждые
            # 1–2 мин. во время длинных ходов — ревью §multi-cli).
            sig = json.dumps(omni, sort_keys=True, default=str)
            if sig != self._omni_models_sig:
                self._omni_models_sig = sig
                await self.hub.broadcast_global(make_frame("models_list", omni))
            # §multi-cli: другие CLI омни не касается — их модели обновляем.
            if all(t == models.DEFAULT_CLI_TYPE for t in models.KNOWN_CLI_TYPES):
                return self._MODELS_TTL
        else:
            self._omni_models_sig = None
        # Не поднимаем второй CLI-процесс Claude во время активного хода
        # (§models M1); пробы других CLI (`agy models`) ходу не мешают.
        if omni is None and any(
                isinstance(s, ClaudeSession) and s.status == "busy"
                for s in self.sessions.values()):
            log.info("models.refresh_deferred_busy")
            return self._MODELS_RETRY
        # Троттлинг: между реальными пробами не меньше _MODELS_MIN_INTERVAL —
        # иначе клиент, поллящий PENDING, гнал бы процессы спина к спине (M2).
        since = time.time() - self._last_probe_ts
        if since < self._MODELS_MIN_INTERVAL:
            return self._MODELS_MIN_INTERVAL - since
        self._last_probe_ts = time.time()

        # §cli-types: обновляем кэш КАЖДОГО известного типа CLI (сейчас один —
        # claude). Каждый тип — своя проба/кэш/бродкаст.
        for cli_type in models.KNOWN_CLI_TYPES:
            if omni is not None and cli_type == models.DEFAULT_CLI_TYPE:
                continue          # claude под omniroute — список уже разослан
            if self._gateway_models_list(cli_type) is not None:
                continue          # §auth: у шлюза список из выбора, CLI не пробуем
            # Проба — отдельной таской, чтобы входящий user_msg мог её отменить
            # (M1: не держим второй процесс во время хода).
            self._models_probe_task = asyncio.create_task(
                models.probe_models(self.config, str(self.config.data_dir),
                                    cli_type))
            try:
                data = await self._models_probe_task
            except asyncio.CancelledError:
                # Различаем отмену САМОГО рефрешера (shutdown отменил
                # _models_task — у текущей таски есть pending-cancel) от отмены
                # только пробы (user_msg → _cancel_models_probe отменил лишь
                # дочернюю таску). Не полагаемся на флаг: он мог бы «проглотить»
                # отмену рефрешера.
                cur = asyncio.current_task()
                if cur is not None and cur.cancelling() > 0:
                    raise                       # отменяют рефрешер (shutdown)
                log.info("models.probe_cancelled_busy", cli=cli_type)
                return self._MODELS_RETRY       # отменили пробу из-за хода
            finally:
                self._models_probe_task = None

            if data.get("auth_state") == "OK" and data.get("models"):
                data["updated_at"] = time.time()
                models.save_cache(self.config, data, cli_type)
                log.info("models.refreshed", cli=cli_type,
                         n=len(data["models"]), current=data.get("current"))
                # §models L1: клиенты на PENDING узнают о готовности.
                # Типы, скрытые от старых клиентов (§18.3), — только multi_cli.
                spec = cli_registry.spec_for(cli_type)
                await self.hub.broadcast_global(
                    make_frame("models_list", data),
                    require_cap=(None if spec is None or spec.legacy_visible
                                 else cli_registry.MULTI_CLI_CAP))
                if cli_type in self._cli_token_rejected:   # MED-1: токен снова работает
                    self._cli_token_rejected.discard(cli_type)
                    await self._broadcast_cli_status(cli_type)
            else:
                # Не затираем последний хороший кэш (auth/нет CLI/ошибка).
                log.info("models.refresh_skip", cli=cli_type,
                         auth=data.get("auth_state"),
                         present=data.get("cli_present"))
        return self._MODELS_TTL

    def _cancel_models_probe(self) -> None:
        """§models M1: отменить фоновую пробу `/model` (пришёл user_msg — не
        держим второй CLI-процесс рядом с ходом). Проба толерантна к отмене;
        _refresh_models_once отличит эту отмену от отмены рефрешера по
        current_task().cancelling()."""
        t = self._models_probe_task
        if t is not None and not t.done():
            t.cancel()

    def _effective_clock_offset(self) -> float:
        """§defer-clock: смещение часов Anthropic для ректификации fireAt. 0, если
        замера не было, ЛИБО он протух (>1ч), ЛИБО с момента замера системные часы
        ШАГНУЛИ (расхождение wall vs monotonic > 60с) — иначе после NTP-коррекции
        протухший offset заставил бы defer выстрелить мгновенно."""
        if self._clock_offset == 0.0:
            return 0.0
        mono_elapsed = time.monotonic() - self._clock_offset_mono
        wall_elapsed = time.time() - self._clock_offset_wall
        if mono_elapsed > 3600 or abs(wall_elapsed - mono_elapsed) > 60:
            return 0.0
        return self._clock_offset

    def _invalidate_models_cache(self) -> None:
        """Смена авторизации: список моделей мог смениться. Гасим пробу в
        полёте (она под СТАРЫМИ кредами — иначе разослала бы стейл-список) и
        будим рефрешер на свежую пробу."""
        self._cancel_models_probe()
        self._models_refresh_now.set()

    async def _reset_all_chat_models(self) -> None:
        """§models L2: смена режима авторизации → per-chat выбор модели может
        стать невалидным (напр. полный id из oauth не существует в шлюзе).
        Сбрасываем meta.model во всех чатах и шлём chat_updated на каждый
        изменённый — клиент сразу видит сброс, а не ждёт рефетча (раньше
        молча расходилось: в CLI-view висела протухшая модель)."""
        for m in self.store.list():
            if m.addressee == "claude" and m.cliType != models.DEFAULT_CLI_TYPE:
                # §multi-cli: чат сейчас на другом CLI — сбрасываем только
                # сохранённую модель Claude, активную (чужого CLI) не трогаем.
                if (m.cliSessions.get("claude") or {}).get("model"):
                    self.store.set_cli_state(m.chatId, "claude", model=None)
                continue
            if getattr(m, "model", None):
                updated = self.store.update_meta(m.chatId, model=None)
                if updated is not None:
                    await self._broadcast_meta("chat_updated", updated)

    # ---------- HTTP-этап (§1.1) ----------

    def _process_request(self, connection: ServerConnection,
                         request: Request) -> Response | None:
        path = request.path.split("?", 1)[0]
        if path != WS_PATH:
            return connection.respond(http.HTTPStatus.NOT_FOUND, "not found\n")
        # N3: берём ВСЕ значения — дублированный Authorization раньше кидал
        # websockets.MultipleValuesError (LookupError, не KeyError → .get дефолт
        # не срабатывал) → 500 в обход 401+fail2ban-лога. Дубль/отсутствие → "".
        vals = request.headers.get_all("Authorization")
        auth = vals[0] if len(vals) == 1 else ""
        # L: сравнение constant-time (hmac.compare_digest) — не даём тайминг-оракул
        # для подбора токена. Клиентский заголовок декодится с surrogateescape
        # (лон-суррогаты на битых байтах) → кодируем ИМ ЖЕ, иначе strict .encode()
        # бросил бы UnicodeEncodeError → 500 в обход 401+fail2ban-лога (P0-1).
        got = auth.encode("utf-8", "surrogateescape")
        if not hmac.compare_digest(got, f"Bearer {self.token}".encode()):
            # IP атакующего — из TCP-пира (не из X-Forwarded-For: порт торчит
            # напрямую). Пишем в auth_failures.log для fail2ban (§security).
            peer = connection.remote_address
            ip = peer[0] if peer else None
            authlog.record_failure(self.config, ip, "ws", path)
            return connection.respond(http.HTTPStatus.UNAUTHORIZED, "auth failed\n")
        return None  # продолжить upgrade

    # ---------- жизненный цикл соединения ----------

    async def _handler(self, ws: ServerConnection):
        async def send(frame: dict):
            await ws.send(dumps(frame))

        async def close():
            # backpressure: Hub закрывает зависший сокет по send-таймауту
            # (1013 «Try Again Later»); ws.close сам ограничен close_timeout.
            await ws.close(1013)

        conn_id = self.hub.register(send, close)
        t0 = time.time()
        peer = ws.remote_address
        try:
            await self.hub.send_global(conn_id, make_frame("hello", {
                "server_version": self.config.server_version,
                "server_commit": _SERVER_COMMIT,   # §update: HEAD для сверки с репо
                "supported_v": list(self.config.protocol_versions),
                "capabilities": list(self.config.capabilities),
                # §cli-types: какие типы CLI-агентов умеет этот Ёžik (клиент
                # покажет выбор только из них; старый клиент поле игнорит).
                "cliTypes": list(cli_registry.legacy_visible_cli_types()),
                # §multi-cli (§18.3): присутствие/авторизация/возможности каждого
                # CLI. Поле добавочное — старый клиент его игнорирует (§9.4).
                "cliStatus": self._cli_status_snapshot(),
            }))
            async for raw in ws:
                # Кадр, дочитанный из буфера уже ПОСЛЕ закрытия клиентом (цикл
                # стоял на долгой операции): клиент считает его недоставленным
                # и пошлёт заново после переподключения — не выполнять (дубль).
                if ws.state is not State.OPEN:
                    log.info("conn.drop_after_close", conn_id=conn_id)
                    break
                await self._dispatch(conn_id, raw)
        except websockets.ConnectionClosed:
            pass
        finally:
            # §obs: причина и длительность закрытия — чтобы отличать
            # обрыв клиента / ping-timeout сервера / уход в фон.
            log.info("conn.closed", conn_id=conn_id,
                     code=getattr(ws, "close_code", None),
                     reason=(getattr(ws, "close_reason", None) or "")[:120],
                     dur=round(time.time() - t0, 1),
                     peer=(peer[0] if peer else None))
            # §client-caps: соединение уходит → пересчитать эффективные caps
            # чатов, где оно было подписано (sticky в сессии удержит, если это
            # был последний клиент с рендером). Снимаем подписки ДО unregister.
            caps_chats = self.hub.conn_subs(conn_id)
            self.hub.unregister(conn_id)
            for cid in caps_chats:
                await self._push_caps(cid)

    # ---------- §client-caps ----------

    async def _push_caps(self, chat_id: str) -> None:
        """Протолкнуть эффективный набор возможностей (union подписанных) в живую
        ClaudeSession чата. Нет сессии — ничего (подхватит при _ensure_session).
        Значение живое: его читает тул formula_mode в момент отрисовки формулы
        (сессию НЕ пересобираем — прежний rebuild+resume замораживал режим)."""
        session = self.sessions.get(chat_id)
        if isinstance(session, _AGENT_SESSIONS):
            session.set_client_caps(self.hub.caps_for_chat(chat_id))

    async def _h_client_caps(self, conn_id, frame, p):
        """§client-caps: client_hello / client_caps_update — клиент объявил
        возможности рендера. Запоминаем на соединении и пересчитываем чаты, где
        оно подписано (client_hello обычно приходит ДО subscribe → там список
        пуст, и набор подхватится при subscribe/_ensure_session)."""
        self.hub.set_conn_caps(conn_id, p.clientCapabilities)
        if frame.type == "client_hello" and p.lang:
            self._apply_language(conn_id, p.lang)    # §i18n: язык на коннекте
        log.info("client.caps", conn_id=conn_id,
                 caps=sorted(p.clientCapabilities)[:8],
                 lang=self.hub.conn_lang(conn_id))
        for cid in self.hub.conn_subs(conn_id):
            await self._push_caps(cid)

    def _apply_language(self, conn_id: int, raw: str) -> str:
        """§i18n: нормализовать и запомнить язык соединения (+ язык устройства
        для оффлайн-пушей). Возвращает применённый язык."""
        lang = i18n.normalize_lang(raw)
        self.hub.set_conn_lang(conn_id, lang)
        dev = self.hub.conn_device(conn_id)
        if dev:
            self.push_keys.set_lang(dev, lang)
        return lang

    async def _h_set_language(self, conn_id, frame, p):
        """§19: клиент сменил язык интерфейса на лету."""
        lang = self._apply_language(conn_id, p.lang)
        log.info("client.language", conn_id=conn_id, requested=p.lang[:35],
                 lang=lang)
        await self.hub.send_global(conn_id, make_frame(
            "language_set", {"lang": lang}))

    # ---------- диспетчер ----------

    async def _dispatch(self, conn_id: int, raw: str | bytes):
        try:
            frame = parse_client_frame(raw)
        except BadFrame as e:
            # Диагностика рассинхрона версий: старый клиент шлёт снятые типы
            # (напр. set_skills) → в сообщении видно тип и невалидные поля.
            # raw НЕ логируем — у auth_apikey/omniroute/register_push там секрет
            # (api_key/notifyKey); сообщение BadFrame уже без значений полей.
            msg = str(e)[:300]   # кап: гигантский type/детали не раздувают лог
            log.warning("frame.bad", err=msg)
            await self.hub.send_global(conn_id, make_error(Err.BAD_FRAME, msg))
            return

        try:
            await self._route(conn_id, frame)
        except Exception as e:
            log.error("dispatch.internal", type=frame.type, err=repr(e))
            await self.hub.send_global(conn_id, make_error(
                Err.INTERNAL, f"{type(e).__name__}: {e}",
                chat_id=frame.chatId, related=frame.id))

    # P3: диспетчеризация фреймов по таблицам (было — if-цепочка ~760 строк).
    # Системные (без чата) → _SYS_ROUTES; чат-скоупные (после резолва meta) →
    # _CHAT_ROUTES. Порядок сохранён: сперва системные, затем meta+CHAT_NOT_FOUND.
    _SYS_ROUTES = {
        'ping': '_h_ping',
        'op_abort': '_h_op_abort',
        'auth_start': '_h_auth_start',
        'auth_code': '_h_auth_code',
        'auth_apikey': '_h_auth_apikey',
        'auth_omniroute': '_h_auth_omniroute',
        'auth_gateway': '_h_auth_gateway',
        'auth_token': '_h_auth_token',
        'omniroute_probe_models': '_h_omniroute_probe_models',
        'omniroute_set_key': '_h_omniroute_set_key',
        'omniroute_set_models': '_h_omniroute_set_models',
        'logout': '_h_logout',
        'client_log': '_h_client_log',
        'register_push': '_h_register_push',
        'client_hello': '_h_client_caps',
        'client_caps_update': '_h_client_caps',
        'set_language': '_h_set_language',
        'update_self': '_h_update_self',
        'install_neko': '_h_install_neko',
        'get_neko': '_h_install_neko',
        'remove_neko': '_h_install_neko',
        'neko_open_view': '_h_neko_open_view',
        'install_skill': '_h_install_skill',
        'set_skill_default': '_h_set_skill_default',
        'list_chats': '_h_list_chats',
        'list_models': '_h_list_models',
        'create_chat': '_h_create_chat',
    }
    _CHAT_ROUTES = {
        'delete_chat': '_h_delete_chat',
        'rename_chat': '_h_rename_chat',
        'set_mode': '_h_set_mode',
        'set_model': '_h_set_model',
        'set_cli': '_h_set_cli',
        'schedule_message': '_h_schedule_message',
        'cancel_scheduled': '_h_cancel_scheduled',
        'list_scheduled': '_h_list_scheduled',
        'list_skills': '_h_list_skills',
        'set_skill_group': '_h_set_skill_group',
        'restart_agent': '_h_restart_agent',
        'clear_session': '_h_clear_session',
        'list_mcp': '_h_list_mcp',
        'add_mcp': '_h_add_mcp',
        'set_mcp_enabled': '_h_set_mcp_enabled',
        'remove_mcp': '_h_remove_mcp',
        'get_limits': '_h_get_limits',
        'subscribe_chat': '_h_subscribe_chat',
        'unsubscribe_chat': '_h_unsubscribe_chat',
        'get_log': '_h_get_log',
        'get_status': '_h_get_status',
        'ack': '_h_ack',
        'resume': '_h_resume',
        'user_msg': '_h_user_msg',
        'pty_write': '_h_pty_write',
        'pty_resize': '_h_pty_write',
        'ui_event': '_h_ui_event',
        'ui_list': '_h_ui_list',
        'ui_reopen': '_h_ui_reopen',
        'ui_forget': '_h_ui_forget',
        'ui_closed': '_h_ui_closed',
        'ui_call': '_h_ui_call',
        'ui_new_blank': '_h_ui_new_blank',
        'ui_draw_apply': '_h_ui_draw_apply',
        'ui_draw_clear': '_h_ui_draw_clear',
        'permission_response': '_h_permission_response',
        'picker_response': '_h_permission_response',
        'ui_response': '_h_permission_response',
    }

    async def _route(self, conn_id: int, frame: ClientFrame):
        ftype = frame.type
        p = frame.payload
        name = self._SYS_ROUTES.get(ftype)
        if name is not None:
            await getattr(self, name)(conn_id, frame, p)
            return
        # --- чат-скоупные: чат обязан существовать ---
        meta = self.store.get(frame.chatId)
        if meta is None:
            await self.hub.send_global(conn_id, make_error(
                Err.CHAT_NOT_FOUND, f"Chat {frame.chatId} does not exist",
                chat_id=frame.chatId, related=frame.id))
            return
        name = self._CHAT_ROUTES.get(ftype)
        if name is not None:
            await getattr(self, name)(conn_id, frame, p, meta)
            return
        raise AssertionError(  # защита от рассинхрона с protocol.py
            f"unrouted frame type {ftype}")

    async def _h_ping(self, conn_id, frame, p):
        # §obs (time-sync): кладём серверную метку в pong. Клиент помнит
        # свой t0 и ловит t2 → offset = server_ts − (t0+t2)/2, RTT = t2−t0.
        # Так серверные ts кадров переводятся в клиентскую шкалу.
        await self.hub.send_global(
            conn_id, make_frame("pong", {"server_ts": time.time()}))
        return

    async def _h_op_abort(self, conn_id, frame, p):
        # §netwait: прервать долгую операцию (login/omni/apikey), opId = id
        # инициировавшего фрейма. Любой клиент (для глобального login).
        await self._handle_op_abort(p.opId)
        return

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
            self._spawn_tracked(conn_id, frame.id, "auth_apikey", _op_cli_key())
            return
        p = p.model_copy(update={"base_url": base or None})

        async def _op_apikey():
            ok, err = await self._activate_apikey(
                p.api_key, p.base_url, frame.id)
            return "auth_result", {"ok": ok, "error": err}
        self._spawn_tracked(
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
            from .. import usage
            res = await usage.fetch_limits(self.config, token=token)
            self._mark_committing(frame.id)
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
        self._spawn_tracked(conn_id, frame.id, "auth_token", _op_token())
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
            self._spawn_tracked(conn_id, frame.id, "auth_gateway", _op_cli_gw())
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
        self._spawn_tracked(
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
        self._spawn_tracked(
            conn_id, frame.id, "omni_probe", _op_probe())
        return

    async def _h_omniroute_set_key(self, conn_id, frame, p):
        # §omni: сменить только ключ активного omniroute (модели сохраняются).
        async def _op_setkey():
            ok, err = await self._set_omniroute_key(p.api_key, frame.id)
            return "omniroute_set_result", {"ok": ok, "error": err}
        self._spawn_tracked(
            conn_id, frame.id, "omni_setkey", _op_setkey())
        return

    async def _h_omniroute_set_models(self, conn_id, frame, p):
        # §omni шаг 1: сохранить выбор моделей (без тир-лимита — режет клиент).
        ok, err = self._save_omniroute_models(p)
        if ok:
            await self._reset_all_chat_models()   # выбор мог протухнуть (§models L2)
            await self._restart_cli_sessions(models.DEFAULT_CLI_TYPE)
            self._invalidate_models_cache()
            await self._broadcast_cli_status(models.DEFAULT_CLI_TYPE)
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
        await self._reset_all_chat_models()    # §models L2: выбор мог протухнуть
        await self._restart_cli_sessions(models.DEFAULT_CLI_TYPE)
        self._invalidate_models_cache()   # §models: сбросить/переобновить
        await self._broadcast_cli_status(models.DEFAULT_CLI_TYPE)
        log.info("auth.logout")
        return

    async def _h_client_log(self, conn_id, frame, p):
        self._append_client_log(p.text)
        return

    async def _h_register_push(self, conn_id, frame, p):
        # §push: запомнить notifyKey устройства (секрет отправки) — по нему
        # попросим релей отправить APNs-пуш, когда устройство будет оффлайн.
        # deviceId привязываем к соединению → знаем, какие устройства онлайн
        # (получат напрямую по WS) и каким нужен пуш (per-device маршрутизация).
        lang = (i18n.normalize_lang(p.lang) if p.lang
                else self.hub.conn_lang_explicit(conn_id))
        self.push_keys.remember(p.notifyKey, p.deviceId, lang)
        self.hub.set_device(conn_id, p.deviceId)
        return

    async def _h_update_self(self, conn_id, frame, p):
        # §15: git pull своего исходника + перезапуск. Авторизация — тем же
        # токеном, что и WS (SSH не нужен). Работает для серверов,
        # добавленных только по порту Ёжика.
        # M4: single-flight — параллельный вызов не запускает 2× git reset/
        # pip/execv (проверка+взвод атомарны: между ними нет await).
        if self._updating:
            await self.hub.send_global(conn_id, make_frame("update_result", {
                "ok": False, "changed": False, "old": "", "new": "",
                "message": i18n.Msg("update.in_progress")}))
            return
        self._updating = True
        # git pull/pip/рестарт идут до ~15 мин (бюджет pull_latest) → ФОНОВАЯ
        # задача, как install_neko: цикл кадров соединения сразу свободен
        # (ping/user_msg не ждут апдейта). Проверка+взвод без await между ними
        # — single-flight сохраняется.
        self._update_task = asyncio.create_task(
            self._update_job(conn_id, frame.id), name="update-self")
        return

    async def _reply_or_broadcast(self, conn_id, frame):
        """Итог долгой фоновой операции (update_self, ошибка neko) —
        инициатору, если он ещё на связи; иначе всем (клиент мог
        переподключиться за время pull/pip)."""
        if self.hub.has_conn(conn_id):
            await self.hub.send_global(conn_id, frame)
        else:
            await self.hub.broadcast_global(frame)

    async def _update_job(self, conn_id, frame_id):
        """Фон update_self: pull_latest в потоке → update_result → рестарт."""
        restarting = False
        try:
            result = await asyncio.to_thread(updater.pull_latest,
                                             _SERVER_COMMIT)
            upd_payload = {
                "ok": result.ok,
                "changed": result.changed,
                "old": result.old,
                "new": result.new,
                "message": result.message,
            }
            cli_info = result.cli
            if cli_info:   # манифест совместимого SDK (опционально, §15.2)
                upd_payload["cli"] = cli_info
            await self._reply_or_broadcast(conn_id, make_frame(
                "update_result", upd_payload))
            log.info("update.self", ok=result.ok, changed=result.changed,
                     old=result.old, new=result.new)
            if result.ok and result.changed:
                restarting = True   # процесс сменится — флаг НЕ снимаем
                async def _restart():
                    await asyncio.sleep(1.0)  # дать update_result долететь
                    log.info("update.restart", to=result.new)
                    from .. import neko
                    if neko.is_provisioning():
                        # execv не ждёт поток docker: прерываем pull, иначе
                        # он доживёт сиротой, а стадия после рестарта = absent.
                        neko.cancel_provision()
                    try:
                        updater.restart_in_place()   # execv — не возвращается
                    except Exception as e:  # noqa: BLE001
                        # execv упал: диск на новом SHA, но процесс на старом.
                        # Повтор update_self теперь вернёт changed=True (S6-M5:
                        # диск ≠ SHA процесса) и рестарт будет повторён. Без
                        # явного лога это было бы тихим unhandled-task exc.
                        log.error("update.restart_failed", err=repr(e))
                        self._updating = False   # разлатчиваем — рестарт не идёт
                # L: держим ссылку (иначе GC может собрать задачу до execv).
                self._restart_task = asyncio.create_task(_restart())
        except asyncio.CancelledError:
            raise
        except Exception as e:  # noqa: BLE001 — сбой фоновой задачи не теряем
            log.error("update.job_failed", err=repr(e))
            await self._reply_or_broadcast(conn_id, make_error(
                Err.INTERNAL, f"{type(e).__name__}: {e}", related=frame_id))
        finally:
            if not restarting:
                self._updating = False

    @staticmethod
    def _neko_frame(result) -> dict:
        return make_frame("neko_result", {
            "ok": result.ok,
            "status": result.status,
            "message": result.message,
            "https_port": result.https_port,
            "user_password": result.user_password,
            "server_ip": result.server_ip,
            "mcp_port": result.mcp_port,
            "ai_control": result.ai_control,
            "stage": result.stage,
        })

    async def _h_install_neko(self, conn_id, frame, p):
        ftype = frame.type
        # §17: Neko-браузер. Авторизация — тем же токеном, что WS (без SSH).
        # install/remove — долгий блокирующий docker I/O → ФОНОВАЯ задача
        # (to_thread внутри), цикл кадров соединения сразу свободен (ping/
        # subscribe/user_msg не ждут pull). Итог install/remove рассылается
        # ВСЕМ соединениям (клиент мог переподключиться за время установки).
        # get_neko — быстрый status() без лока, отвечаем запросившему.
        from .. import neko
        if ftype == "get_neko":
            result = await asyncio.to_thread(neko.status, self.config)
            await self.hub.send_global(conn_id, self._neko_frame(result))
            log.info("neko." + ftype, ok=result.ok, status=result.status)
            return
        install = ftype == "install_neko"
        busy = self._neko_install_task if install else self._neko_remove_task
        if busy is not None and not busy.done():
            # single-flight: повтор (двойной тап/второе устройство) не запускает
            # второй provision/teardown — отвечаем текущим статусом (installing).
            result = await asyncio.to_thread(neko.status, self.config)
            await self.hub.send_global(conn_id, self._neko_frame(result))
            log.info("neko." + ftype + ".already_running", status=result.status)
            return
        # Проверка+взвод атомарны (между ними нет await) — как M4 у update_self.
        task = asyncio.create_task(
            self._neko_job(conn_id, frame.id, ftype,
                           neko.provision if install else neko.teardown),
            name=f"neko-{ftype}")
        if install:
            self._neko_install_task = task
        else:
            self._neko_remove_task = task
        return

    async def _neko_job(self, conn_id, frame_id, ftype, fn):
        """Фон install/remove: поток docker → итог ВСЕМ соединениям."""
        try:
            result = await asyncio.to_thread(fn, self.config)
        except asyncio.CancelledError:
            raise
        except Exception as e:  # noqa: BLE001 — сбой фоновой задачи не теряем
            log.error("neko.job_failed", type=ftype, err=repr(e))
            await self._reply_or_broadcast(conn_id, make_error(
                Err.INTERNAL, f"{type(e).__name__}: {e}", related=frame_id))
            return
        await self.hub.broadcast_global(self._neko_frame(result))
        log.info("neko." + ftype, ok=result.ok, status=result.status)

    async def _h_neko_open_view(self, conn_id, frame, p):
        """§17: новая вкладка/окно браузера neko через серверный NekoProxy
        (playwright-mcp `browser_tabs:new`). Если браузер открыт → вкладка в том
        же видимом окне; если был закрыт → held-context мёртв, первый вызов падает,
        ретрай `browser_navigate` поднимает новое окно. Это и есть вся обработка
        open-vs-closed (детекцию не строим — гонка, chromium сам выбирает)."""
        from .. import neko
        url = (p.url or "").strip()
        if url and not url.lower().startswith(("http://", "https://")):
            await self.hub.send_global(conn_id, make_frame(
                "neko_view_result", {"ok": False, "message": "bad url"}))
            return
        # Гейт: контейнер жив И Ёжик подключён к neko-сети (иначе MCP недостижим →
        # иначе 10с handshake-таймаут вместо быстрого отказа).
        if not await asyncio.to_thread(neko.ai_control_available):
            await self.hub.send_global(conn_id, make_frame(
                "neko_view_result", {"ok": False, "message": i18n.Msg("neko.unavailable")}))
            return
        if self._neko_proxy is None:
            from ..core.neko_proxy import NekoProxy
            self._neko_proxy = NekoProxy(
                f"http://{neko.CONTAINER}:{self.config.neko_mcp_port}/mcp")
        def _raise_if_error(res):
            # MCP-ошибки НЕ бросают — приходят CallToolResult(isError=True)
            # (playwright-mcp так рапортует «Target closed» при закрытом окне,
            # ср. ctl_server.py). Трактуем как сбой → уходим в ретрай/отказ.
            if getattr(res, "isError", False):
                txt = "".join(getattr(c, "text", "") or ""
                              for c in (getattr(res, "content", None) or []))
                raise RuntimeError(txt or "neko tool error")
        args = {"action": "new", **({"url": url} if url else {})}
        ok, msg = True, ""
        try:
            _raise_if_error(await self._neko_proxy.call("browser_tabs", args, timeout=20))
        except Exception:   # noqa: BLE001 — окно закрыли (isError) или транспорт
            try:
                _raise_if_error(await self._neko_proxy.call(
                    "browser_navigate", {"url": url or "about:blank"}, timeout=20))
            except Exception as e2:  # noqa: BLE001
                ok, msg = False, f"neko: {e2}"
                log.warning("neko.open_view_failed", err=repr(e2))
        await self.hub.send_global(conn_id, make_frame(
            "neko_view_result", {"ok": ok, "message": msg}))
        log.info("neko.open_view", ok=ok, had_url=bool(url))
        return

    async def _h_install_skill(self, conn_id, frame, p):
        # Установка скиллов из git-репо (§skills v2). Сетевой I/O —
        # в отдельном потоке, чтобы не блокировать event loop. Клиент
        # доверие подтверждает у себя (тумблер) — сервер просто ставит.
        try:
            result = await asyncio.to_thread(
                self.skill_sources.install, p.url, p.default_for_new)
            log.info("skills.install_ok", url=p.url,
                     source=result["source"], count=len(result["skills"]))
            await self.hub.send_global(conn_id, make_frame(
                "install_skill_result", {"ok": True, **result}))
        except SkillInstallError as e:
            await self.hub.send_global(conn_id, make_frame(
                "install_skill_result",
                {"ok": False, "error": i18n.msg_of(e)}))   # §i18n: Msg сохраняем
        except Exception as e:  # noqa: BLE001
            log.warning("skills.install_fail", url=p.url, err=repr(e))
            await self.hub.send_global(conn_id, make_frame(
                "install_skill_result",
                {"ok": False, "error": f"{type(e).__name__}: {e}"}))
        return

    async def _h_set_skill_default(self, conn_id, frame, p):
        ok = self.skill_sources.set_default_for_new(p.source, p.default_for_new)
        log.info("skills.default_changed", source=p.source,
                 default_for_new=p.default_for_new, ok=ok)
        await self.hub.send_global(conn_id, make_frame(
            "skill_default_result",
            {"ok": ok, "source": p.source,
             "default_for_new": p.default_for_new}))
        return

    async def _h_list_chats(self, conn_id, frame, p):
        chats = []
        multi = self.hub.conn_has_cap(conn_id, cli_registry.MULTI_CLI_CAP)
        for m in self.store.list():
            entry = (public_meta(m, include_cli_sessions=multi)
                     | self._chat_status(m.chatId))
            chats.append(entry)
        await self.hub.send_global(conn_id, make_frame("chat_list", {"chats": chats}))
        return

    async def _h_list_models(self, conn_id, frame, p):
        # §models/§cli-types: отдаём кэш нужного типа CLI МГНОВЕННО (CLI не
        # дёргаем). Неизвестный тип → UNSUPPORTED; нет кэша → PENDING + будим
        # фоновый рефрешер.
        cli_type = p.cliType
        if cli_type not in models.KNOWN_CLI_TYPES:
            data = {"cliType": cli_type, "models": [], "current": None,
                    "raw": "", "auth_state": "UNSUPPORTED",
                    "cli_present": False, "updated_at": 0}
        elif (omni := self._omniroute_models_list(cli_type)) is not None:
            # §omni: при omniroute-авторизации источник — ВЫБРАННЫЕ модели
            # (шаг 1), а не CLI-проба. Тир-лимит (первые N) применяет клиент.
            data = omni
        elif (gw := self._gateway_models_list(cli_type)) is not None:
            data = gw       # §auth: шлюз другого CLI — выбранные модели
        else:
            data = models.load_cache(self.config, cli_type)
            if data is None:
                data = {"cliType": cli_type, "models": [], "current": None,
                        "raw": "", "auth_state": "PENDING",
                        "cli_present": None, "updated_at": 0}
                self._models_refresh_now.set()
        await self.hub.send_global(
            conn_id, make_frame("models_list", data))
        return

    async def _h_create_chat(self, conn_id, frame, p):
        # cwd задан клиентом → используем его. Иначе, если сервер знает
        # базу проектов (default_cwd, напр. /root/projects), заводим
        # ПАПКУ ПОД ЧАТ по имени: <base>/<slug> (§3.7). Без базы — свой
        # изолированный каталог data/chats/<id>.
        # Сидируем новый чат скиллами групп с флагом default_for_new
        # (§skills v2). Только для агентских чатов.
        seed_skills = None
        if p.addressee == "claude":
            seed_skills = self.skill_sources.new_chat_skill_names() or None
        # §cli-types: неизвестный тип клампим к дефолту — meta не должна
        # врать о типе (сессию по нему поднимаем; сейчас всегда claude).
        cli_type = models.DEFAULT_CLI_TYPE
        install_cli = None
        if p.addressee == "claude":
            multi = self.hub.conn_has_cap(conn_id, cli_registry.MULTI_CLI_CAP)
            # §cli-pins: клиенту §18 — неустановленный CLI с пином ставим фоном
            err = self._cli_error(p.cliType, allow_install=multi)
            if err is None and not self._cli_present(p.cliType):
                install_cli = p.cliType
            if err is not None and multi:
                # §multi-cli (§18.4): клиент §18 выбирает из hello.cliStatus —
                # неизвестный/недоступный CLI для него ошибка.
                await self.hub.send_global(conn_id, make_error(
                    err[0], err[1], related=frame.id))
                return
            if err is not None:
                # Клиент без multi_cli: прежний кламп к дефолту (поведение до
                # фичи не меняем).
                log.warning("chat.clitype_unknown", requested=p.cliType,
                            fallback=cli_type)
            else:
                cli_type = p.cliType
        meta = self.store.create(
            p.name, p.addressee, p.cwd,
            mcp=p.mcp, permission_mode=p.permission_mode,
            log_kb=p.log_kb, skills=seed_skills,
            cli_type=cli_type,
            projects_base=self.config.default_cwd)
        log.info("chat.created", chat=meta.chatId, name=meta.name,
                 addressee=meta.addressee, cwd=meta.cwd, mcp=meta.mcp,
                 permission_mode=meta.permission_mode, log_kb=meta.log_kb,
                 skills=seed_skills or [])
        await self._broadcast_meta("chat_created", meta)
        if install_cli is not None:
            self._start_cli_install(install_cli, meta.chatId)
        return

    async def _h_delete_chat(self, conn_id, frame, p, meta):
        # S1-M: метим «удаляется» ДО _stop_session — окно между стопом и
        # store.delete иначе даёт гонку воскрешения (см. _ensure_session).
        self._deleting.add(frame.chatId)
        try:
            # Сессия закрывается всегда; рабочая папка (cwd) — по флагу.
            await self._stop_session(frame.chatId)
            self._chat_locks.pop(frame.chatId, None)
            self._stale_requests.pop(frame.chatId, None)
            self.store.delete(frame.chatId, delete_cwd=p.delete_cwd,
                              projects_base=self.config.default_cwd)
            views_registry.clear_chat(self.config.data_dir, frame.chatId)  # §views
            handlers_registry.clear_chat(self.config.data_dir, frame.chatId)  # §handlers
            if self.scheduler is not None:   # §defer: не оставляем осиротевшие jobs
                await self.scheduler.purge_chat(frame.chatId)
            log.info("chat.deleted", chat=frame.chatId, delete_cwd=p.delete_cwd)
            await self.hub.broadcast_global(
                make_frame("chat_deleted", {"chatId": frame.chatId}))
        finally:
            self._deleting.discard(frame.chatId)
        return

    async def _h_rename_chat(self, conn_id, frame, p, meta):
        updated = self.store.update_meta(frame.chatId, name=p.name)
        log.info("chat.renamed", chat=frame.chatId, name=p.name)
        if updated is not None:
            await self._broadcast_meta("chat_updated", updated)
        return

    async def _h_set_mode(self, conn_id, frame, p, meta):
        updated = self.store.update_meta(
            frame.chatId, permission_mode=p.permission_mode)
        if updated is None:   # L: чат исчез (конкурентный delete) → vars(None)
            return
        # Стопаем сессию — новый режим применится при следующем user_msg.
        await self._restart_session(frame.chatId)
        log.info("chat.mode_changed", chat=frame.chatId,
                 permission_mode=p.permission_mode)
        await self._broadcast_meta("chat_updated", updated)
        return

    # ---------- §multi-cli ----------

    def _cli_present(self, cli_type: str) -> bool:
        spec = cli_registry.spec_for(cli_type)
        if spec is None:
            return False
        if spec.bundled or not spec.binary:
            return True
        return cli_registry.find_binary(cli_type) is not None

    def _cli_error(self, cli_type: str, *, allow_install: bool = False
                   ) -> tuple[str, str] | None:
        """Валидация типа CLI для create_chat/set_cli: (код, текст) или None.
        allow_install: CLI не установлен, но в compat.json есть валидная запись
        для этой платформы (или установка уже идёт) — не ошибка, вызывающий
        запустит фоновую установку (_start_cli_install)."""
        if cli_registry.spec_for(cli_type) is None:
            return Err.CLI_UNKNOWN, f"unknown cliType {cli_type!r}"
        if not self._cli_present(cli_type):
            if allow_install and (self._cli_installing(cli_type)
                                  or cli_install.installable(cli_type)):
                return None
            return Err.CLI_UNAVAILABLE, f"CLI {cli_type!r} is not installed"
        return None

    # ---------- §cli-pins: фоновая установка CLI ----------

    def _cli_installing(self, cli: str) -> bool:
        t = self._cli_install_tasks.get(cli)
        return t is not None and not t.done()

    def _start_cli_install(self, cli: str, chat_id: str | None = None) -> None:
        """Запустить фоновую установку CLI (single-flight): CLI не установлен,
        в compat.json есть запись. Ждущие сессии этого CLI (воркер,
        cli_install.wait_pending) стартуют после неё."""
        if self._cli_present(cli):
            return
        if chat_id:
            self._cli_install_chats.setdefault(cli, set()).add(chat_id)
        if self._cli_installing(cli):
            return
        cancel = self._cli_install_cancel[cli] = threading.Event()
        task = asyncio.create_task(self._cli_install_job(cli, cancel),
                                   name=f"cli-install:{cli}")
        self._cli_install_tasks[cli] = task
        cli_install.track(cli, task)

    async def _cli_install_job(self, cli: str, cancel) -> None:
        res: dict = {"ok": False, "error": "cancelled"}
        try:
            log.info("cli.install_start", cli=cli)
            await self._broadcast_cli_status(cli, install=True)   # installing: true
            res = await asyncio.to_thread(cli_install.ensure_installed, cli,
                                          cancel=cancel)
        except asyncio.CancelledError:
            raise
        except Exception as e:  # noqa: BLE001 — сбой установки не роняет сервер
            res = {"ok": False, "error": f"{type(e).__name__}: {e}"}
        finally:
            if self._cli_install_tasks.get(cli) is asyncio.current_task():
                self._cli_install_tasks.pop(cli, None)
            self._cli_install_cancel.pop(cli, None)
        chats = self._cli_install_chats.pop(cli, set())
        log.info("cli.install_done", cli=cli, ok=res.get("ok"),
                 version=res.get("version"), err=res.get("error"))
        if res.get("ok"):
            self._invalidate_models_cache()
        else:
            for chat_id in sorted(chats):
                if self.store.get(chat_id) is None:
                    continue
                # Старый клиент кода не знает — ему хватит CLI_UNAVAILABLE
                # от воркера сессии на ждавший ход.
                await self.hub.publish(chat_id, "error", {
                    "code": Err.CLI_INSTALL_FAILED, "cliType": cli,
                    "message": i18n.Msg("cli.install_failed", cli=cli,
                                        error=str(res.get("error") or "")[:300])},
                    require_cap=cli_registry.MULTI_CLI_CAP)
        await self._broadcast_cli_status(cli, install=True)   # present, installing: false

    def _cli_status_snapshot(self) -> dict[str, dict]:
        """hello.cliStatus (§18.3): present/auth_state/cliCapabilities по CLI."""
        out: dict[str, dict] = {}
        for cli_type, spec in cli_registry.CLI_SPECS.items():
            present = self._cli_present(cli_type)
            cache = models.load_cache(self.config, cli_type) if present else None
            if not present:
                state = "NO_CLI"
            elif (cli_type in _LOGIN_MODULES
                  and auth_store.active_method(self.config, cli_type)
                  == auth_store.SUBSCRIPTION
                  and not _LOGIN_MODULES[cli_type].is_logged_in()):
                state = "AUTH_REQUIRED"      # токена нет — проба не нужна
            elif cli_type in self._cli_token_rejected:
                state = "AUTH_REQUIRED"      # MED-1: токен есть, но CLI ответил 401
            else:
                state = (cache or {}).get("auth_state") or "PENDING"
            out[cli_type] = {"present": present, "auth_state": state,
                             **self._install_flags(cli_type, present),
                             "cliCapabilities": list(spec.capabilities),
                             "experimental": spec.experimental,
                             # §auth: какие способы входа реализованы и какой активен
                             "authMethods": [
                                 m.public() for m in spec.auth_methods
                                 if not (cli_type == "grok"
                                         and grok_auth.managed_home() is None
                                         and m.id != cli_registry.AUTH_DEVICE_CODE)],
                             "activeMethod": auth_store.active_method(
                                 self.config, cli_type),
                             "authDetail": auth_store.detail(self.config, cli_type)}
        return out

    def _install_flags(self, cli: str, present: bool) -> dict:
        """§cli-pins (hello.cliStatus): installing — идёт фоновая установка;
        installable — CLI нет, но Ёжик поставит его при set_cli/create_chat.
        Поля добавочные и только когда true (иначе — как до фичи)."""
        if present:
            return {}
        if self._cli_installing(cli):
            return {"installing": True}
        if cli_registry.spec_for(cli) is not None and cli_install.installable(cli):
            return {"installable": True}
        return {}

    async def _broadcast_meta(self, ftype: str, meta: ChatMeta) -> None:
        """chat_created/chat_updated: клиентам multi_cli — с cliSessions (без
        session_id), остальным — wire как до фичи."""
        await self.hub.broadcast_variants(
            make_frame(ftype, public_meta(meta)),
            make_frame(ftype, public_meta(meta, include_cli_sessions=True)),
            cli_registry.MULTI_CLI_CAP)

    def _auth_lock(self, cli: str) -> asyncio.Lock:
        lock = self._auth_locks.get(cli)
        if lock is None:
            lock = self._auth_locks[cli] = asyncio.Lock()
        return lock

    def _chat_lock(self, chat_id: str) -> asyncio.Lock:
        lock = self._chat_locks.get(chat_id)
        if lock is None:
            lock = self._chat_locks[chat_id] = asyncio.Lock()
        return lock

    async def _h_set_cli(self, conn_id, frame, p, meta):
        """§18.5: сменить активный CLI чата. Контекст не переносится."""
        if meta.addressee != "claude":
            await self.hub.send_global(conn_id, make_error(
                Err.BAD_FRAME, "set_cli: only for agent chats",
                chat_id=frame.chatId, related=frame.id))
            return
        err = self._cli_error(p.cliType, allow_install=True)
        if err is not None:
            await self.hub.send_global(conn_id, make_error(
                err[0], err[1], chat_id=frame.chatId, related=frame.id))
            return
        if not self._cli_present(p.cliType):
            # §cli-pins: CLI нет, но есть пин — переключаем как обычно, ставим фоном
            self._start_cli_install(p.cliType, frame.chatId)
        # M3: идёт смена способа входа нового CLI — ждём её, иначе сессия под
        # чатовым замком стартовала бы со старыми кредами (между quiesce и save).
        # Коснуться-и-отпустить ДО _chat_lock: порядок auth→chat (как в
        # _ensure_session), иначе дедлок с активацией. MED-2: между отпусканием
        # _auth_lock и захватом _chat_lock активация могла снова взять замок —
        # тогда отпускаем _chat_lock, снова ждём _auth_lock и повторяем.
        auth_lock = self._auth_lock(p.cliType)
        while True:
            async with auth_lock:
                pass
            async with self._chat_lock(frame.chatId):
                if auth_lock.locked():
                    continue
                cur = self.store.get(frame.chatId)      # мета могла устареть
                if cur is None:
                    return
                if cur.cliType == p.cliType:             # идемпотентно
                    await self._broadcast_meta("chat_updated", cur)
                    return
                old_cli = cur.cliType
                queued = self._detach_queue(frame.chatId)
                await self._stop_session(frame.chatId)
                res = self.store.set_active_cli(frame.chatId, p.cliType)
                if res is None:      # чат удалили, пока ждали
                    return
                new_meta, first_init = res
                log.info("chat.cli_switched", chat=frame.chatId, frm=old_cli,
                         to=p.cliType, first_init=first_init, queued=len(queued))
                await self.hub.publish(
                    frame.chatId, "cli_switched",
                    {"from": old_cli, "to": p.cliType, "first_init": first_init},
                    require_cap=cli_registry.MULTI_CLI_CAP)
                await self._broadcast_meta("chat_updated", new_meta)
                if queued:   # сообщения, ждавшие в очереди, едут в новый CLI
                    new_session = await self._ensure_session_locked(new_meta)
                    for content, on_result in queued:
                        await new_session.handle_user_msg(
                            content, interrupt=False, on_result=on_result)
                return

    async def _h_set_model(self, conn_id, frame, p, meta):
        # §models: пустая строка → сброс к дефолту CLI (None). Как set_mode:
        # стоп сессии → применится opts["model"] на следующем user_msg
        # (resume сохранит контекст), затем broadcast обновлённой meta.
        # N1: отсекаем непечатаемые символы (уедут в argv --model мусором).
        new_model = "".join(
            ch for ch in (p.model or "").strip() if ch.isprintable()
        ) or None
        updated = self.store.update_meta(frame.chatId, model=new_model)
        if updated is None:   # L: чат исчез (конкурентный delete) → vars(None)
            return
        if p.effort is not None:       # §20: уровень рассуждения активного CLI
            effort = "".join(ch for ch in p.effort.strip()
                             if ch.isalnum()) or None
            updated = self.store.set_cli_state(
                frame.chatId, updated.cliType, effort=effort) or updated
        await self._restart_session(frame.chatId)
        log.info("chat.model_changed", chat=frame.chatId, model=new_model,
                 effort=p.effort)
        await self._broadcast_meta("chat_updated", updated)
        return

    async def _h_schedule_message(self, conn_id, frame, p, meta):
        # §defer: отложить сообщение до сброса лимита. fireAt клампим (не
        # доверяем клиентскому времени). Лимит «1 на чат» enforce'ит
        # планировщик под локом (DeferPendingExists).
        if self.scheduler is None:
            await self.hub.send_global(conn_id, make_error(
                Err.INTERNAL, "scheduler unavailable",
                chat_id=frame.chatId, related=frame.id))
            return
        now = time.time()
        # §defer-clock: fireAt — целевой сброс по часам Anthropic. Считаем
        # СКОЛЬКО осталось до него по тем же часам (now + offset), затем ставим
        # на локальную шкалу планировщика (now + delay). Так задержка верна,
        # даже если системные часы сервера смещены (offset их компенсирует; при
        # offset=0 формула эквивалентна прежнему клампу [now+1 … now+7д]).
        offset = self._effective_clock_offset()
        delay = float(p.fireAt) - (now + offset)
        delay = max(1.0, min(delay, 7 * 24 * 3600))
        fire_at = now + delay                # локальная шкала — для планировщика
        atts = [a.model_dump() for a in p.attachments]
        try:
            jid = await self.scheduler.add_job(
                chat_id=frame.chatId, kind="once", spec=str(fire_at),
                action="inject_user",
                payload={"text": p.text, "attachments": atts},
                created_by="user")
        except DeferPendingExists:
            await self.hub.send_global(conn_id, make_error(
                Err.RATE_LIMITED,
                i18n.Msg("defer.already_scheduled"),
                chat_id=frame.chatId, related=frame.id))
            return
        except Exception as e:  # noqa: BLE001
            await self.hub.send_global(conn_id, make_error(
                Err.INTERNAL, f"schedule failed: {e}",
                chat_id=frame.chatId, related=frame.id))
            return
        # Журналируемое событие → pending-чип восстановится на resume и
        # появится на других устройствах сразу. fireAt в чип отдаём в РЕАЛЬНОЙ
        # шкале (обратно + offset) — у клиента часы верные, чип покажет верное
        # время сброса, хотя в планировщике храним локальное fire_at.
        await self.hub.publish(frame.chatId, "scheduled", {
            "jobId": jid, "text": p.text, "attachments": atts,
            "fireAt": fire_at + offset})
        log.info("defer.scheduled", chat=frame.chatId, job=jid,
                 fire_at=fire_at)
        return

    async def _h_cancel_scheduled(self, conn_id, frame, p, meta):
        ok = (await self.scheduler.cancel_job(
                p.jobId, frame.chatId, action="inject_user")
              if self.scheduler else False)
        if ok:
            # Журналируемо → чип снимется на всех устройствах и на resume.
            await self.hub.publish(frame.chatId, "scheduled_cancelled",
                                   {"jobId": p.jobId})
            log.info("defer.cancelled", chat=frame.chatId, job=p.jobId)
        else:
            # Уже сработало/не найдено (гонка D) — сообщаем инициатору.
            await self.hub.send_global(conn_id, make_frame(
                "scheduled_cancel_failed", {"jobId": p.jobId}, frame.chatId))
        return

    async def _h_list_scheduled(self, conn_id, frame, p, meta):
        jobs = (await self.scheduler.list_jobs(frame.chatId)
                if self.scheduler else [])
        # §defer-clock: next_run хранится в ЛОКАЛЬНОЙ шкале → для чипа отдаём
        # в реальной (+offset), чтобы клиент с верными часами показал время
        # сброса правильно.
        offset = self._effective_clock_offset()
        pending = []
        for j in jobs:
            if j.get("action") != "inject_user" or j.get("enabled") != 1:
                continue
            pl = {}
            try:
                pl = json.loads(j.get("payload") or "{}")
            except ValueError:
                pl = {}
            nr = j.get("next_run")
            pending.append({
                "jobId": j["id"],
                "fireAt": (nr + offset) if isinstance(nr, (int, float)) else nr,
                "text": pl.get("text", ""),
                "attachments": pl.get("attachments", []),
            })
        await self.hub.send_global(conn_id, make_frame(
            "scheduled_list", {"jobs": pending}, frame.chatId))
        return

    async def _h_list_skills(self, conn_id, frame, p, meta):
        # Дерево: источник (репо) → его скиллы (§skills v2). enabled —
        # ВСЕ скиллы группы во включённом наборе чата (meta.skills).
        await self.hub.send_global(conn_id, make_frame(
            "skills_response", self._skills_tree(meta), frame.chatId))
        return

    async def _h_set_skill_group(self, conn_id, frame, p, meta):
        # Групповое вкл/выкл источника в этом чате: добавляем/убираем
        # ИМЕНА скиллов группы из meta.skills. Рестарт применит (как set_mode).
        group = set(self.skill_sources.sources().get(p.source, {}).get(
            "skills", []))
        if not group:  # источник без записи → трактуем как одиночный
            group = {p.source}
        current = list(meta.skills or [])
        if p.enabled:
            current = list(dict.fromkeys(current + sorted(group)))
        else:
            current = [s for s in current if s not in group]
        updated = self.store.update_meta(
            frame.chatId, skills=(current or None))
        if updated is None:   # L: чат исчез (конкурентный delete) → vars(None)
            return
        await self._restart_session(frame.chatId)
        log.info("chat.skill_group_changed", chat=frame.chatId,
                 source=p.source, enabled=p.enabled,
                 skills=updated.skills or [])
        await self._broadcast_meta("chat_updated", updated)
        return

    async def _h_restart_agent(self, conn_id, frame, p, meta):
        # Контекст жив (resume по claude_session_id) — стоп-сессия лишь
        # роняет коннект; новый MCP-набор подхватится на первом user_msg.
        await self._restart_session(frame.chatId)
        log.info("chat.agent_restarted", chat=frame.chatId)
        await self.hub.send_global(conn_id, make_frame(
            "mcp_response", self._mcp_tree(meta), frame.chatId))
        return

    async def _h_clear_session(self, conn_id, frame, p, meta):
        # §clear: сброс контекста — роняем сессию И забываем session_id CLI,
        # чтобы следующий user_msg стартовал СВЕЖУЮ сессию без resume.
        # Спасает «отравленный» чат (напр. залипший на 400 content-filter),
        # минуя модель. Видимая переписка чата не трогается.
        await self._stop_session(frame.chatId)
        cur = self.store.get(frame.chatId) or meta     # cliType мог смениться
        if cur.cliType == "claude":
            self.store.update_meta(frame.chatId, claude_session_id=None)
        else:   # §multi-cli: забываем сессию АКТИВНОГО CLI
            self.store.set_cli_state(frame.chatId, cur.cliType,
                                     session_id=None, initialized=False)
        log.info("chat.context_cleared", chat=frame.chatId)
        # Подтверждаем клиенту — он покажет заметку ТОЛЬКО по этому фрейму
        # (иначе на старом Ёжике без хендлера был бы ложный «очищено»).
        await self.hub.send_global(conn_id, make_frame(
            "session_cleared", {}, frame.chatId))
        return

    async def _h_list_mcp(self, conn_id, frame, p, meta):
        await self.hub.send_global(conn_id, make_frame(
            "mcp_response", self._mcp_tree(meta), frame.chatId))
        return

    async def _h_add_mcp(self, conn_id, frame, p, meta):
        # Имя встроенного зарезервировано: иначе в реестре появился бы второй
        # «hedgehog» → дубль в _mcp_tree и неудаляемая строка на клиенте (guard
        # set/remove съел бы запрос). Игнорируем, отвечаем актуальным деревом.
        if (p.name.strip().lower() == BUILTIN_MCP_NAME
                or not _MCP_NAME_RE.fullmatch(p.name)):
            await self.hub.send_global(conn_id, make_frame(
                "mcp_response", self._mcp_tree(meta), frame.chatId))
            return
        self.mcp.add(p.name, self._mcp_config(p))
        enabled = list(dict.fromkeys(list(meta.mcp or []) + [p.name]))
        updated = self.store.update_meta(frame.chatId, mcp=enabled)
        if updated is None:   # L: чат исчез (конкурентный delete) → vars(None)
            return
        await self._restart_session(frame.chatId)  # применить новый MCP
        log.info("chat.mcp_added", chat=frame.chatId, name=p.name,
                 transport=p.transport)
        await self._broadcast_meta("chat_updated", updated)
        await self.hub.send_global(conn_id, make_frame(
            "mcp_response", self._mcp_tree(updated), frame.chatId))
        return

    async def _h_set_mcp_enabled(self, conn_id, frame, p, meta):
        # Встроенный hedgehog всегда вкл и не хранится в реестре — отключить
        # нельзя (иначе у агента пропадут notify/ask_ui/ui_*). Игнорируем, но
        # отвечаем актуальным деревом, чтобы клиент перерисовал состояние.
        if p.name == BUILTIN_MCP_NAME:
            await self.hub.send_global(conn_id, make_frame(
                "mcp_response", self._mcp_tree(meta), frame.chatId))
            return
        current = list(meta.mcp or [])
        if p.enabled:
            current = list(dict.fromkeys(current + [p.name]))
        else:
            current = [n for n in current if n != p.name]
        updated = self.store.update_meta(frame.chatId, mcp=current)
        if updated is None:   # L: чат исчез (конкурентный delete) → vars(None)
            return
        await self._restart_session(frame.chatId)  # рестарт агента
        log.info("chat.mcp_enabled", chat=frame.chatId, name=p.name,
                 enabled=p.enabled)
        await self._broadcast_meta("chat_updated", updated)
        await self.hub.send_global(conn_id, make_frame(
            "mcp_response", self._mcp_tree(updated), frame.chatId))
        return

    async def _h_remove_mcp(self, conn_id, frame, p, meta):
        if p.name == BUILTIN_MCP_NAME:   # встроенный нельзя удалить из реестра
            await self.hub.send_global(conn_id, make_frame(
                "mcp_response", self._mcp_tree(meta), frame.chatId))
            return
        self.mcp.remove(p.name)
        current = [n for n in (meta.mcp or []) if n != p.name]
        updated = self.store.update_meta(frame.chatId, mcp=current)
        if updated is None:   # L: чат исчез (конкурентный delete) → vars(None)
            return
        await self._restart_session(frame.chatId)
        log.info("chat.mcp_removed", chat=frame.chatId, name=p.name)
        await self._broadcast_meta("chat_updated", updated)
        await self.hub.send_global(conn_id, make_frame(
            "mcp_response", self._mcp_tree(updated), frame.chatId))
        return

    async def _h_get_limits(self, conn_id, frame, p, meta):
        # §multi-cli (§18.6): лимиты есть не у каждого CLI. Клиентам multi_cli —
        # честный ответ supported:false; клиент без multi_cli всегда получает
        # лимиты Claude (поведение до фичи).
        cli = p.cliType or meta.cliType
        multi = self.hub.conn_has_cap(conn_id, cli_registry.MULTI_CLI_CAP)
        if multi and auth_store.active_method(self.config, cli) \
                != auth_store.SUBSCRIPTION:
            # лимиты подписки к ключу/шлюзу не относятся
            await self.hub.send_global(conn_id, make_frame(
                "limits_result", {"cliType": cli, "supported": False,
                                  "reason": auth_store.active_method(self.config, cli)},
                frame.chatId))
            return
        if multi and not cli_registry.supports(cli, cli_registry.CAP_LIMITS):
            await self.hub.send_global(conn_id, make_frame(
                "limits_result", {"cliType": cli, "supported": False},
                frame.chatId))
            return
        if multi and cli == "codex":
            # §20: лимиты аккаунта ChatGPT/Codex — `account/rateLimits/read`
            # в той же форме, что у Claude (fiveHour/sevenDay).
            await self.hub.send_global(conn_id, make_frame(
                "limits_result", await codex_rpc.fetch_limits(), frame.chatId))
            return
        # §limits: лимиты подписки из заголовков /v1/messages (usage.py).
        from .. import usage
        data = await usage.fetch_limits(self.config)
        # §defer-clock: запоминаем смещение часов Anthropic от локальных —
        # им потом ректифицируем fireAt в schedule_message. Якорим на monotonic.
        sd = data.get("serverDate")
        if sd:
            self._clock_offset = sd - time.time()
            self._clock_offset_mono = time.monotonic()
            self._clock_offset_wall = time.time()
            if abs(self._clock_offset) > 120:
                log.warning("clock.skew", offset_s=round(self._clock_offset))
        await self.hub.send_global(conn_id, make_frame(
            "limits_result", data, frame.chatId))
        return

    async def _h_subscribe_chat(self, conn_id, frame, p, meta):
        self.hub.subscribe(conn_id, frame.chatId)
        log.info("chat.subscribe", conn_id=conn_id, chat_id=frame.chatId)
        # §client-caps: это соединение теперь влияет на эффективный набор чата.
        await self._push_caps(frame.chatId)
        # Для shell-чата поднимаем bash сразу — клиент увидит prompt.
        if meta.addressee == "broker_shell":
            session = await self._ensure_session(meta)
            # S5-H2: снапшоты не в pending → шлём ТЕКУЩИЙ экран этому
            # соединению (реконнект к живому shell не увидит его иначе).
            if isinstance(session, PtySession):
                await self.hub.send_global(conn_id, make_frame(
                    "screen_snapshot", session.current_snapshot(),
                    frame.chatId))
        # §views авто-возврат: если в чате есть ОТКРЫТОЕ окно (current),
        # ре-пушим его этому соединению — окно переживает рестарт/реконнект
        # (клиент на реконнекте пере-сидит ленту и теряет живое окно).
        # Точечно (send_global) — не броадкастим другим устройствам.
        snap = views_registry.get(self.config.data_dir, frame.chatId)
        cur = snap.get("current")
        if isinstance(cur, dict) and cur.get("html"):
            await self.hub.send_global(conn_id, make_frame("ui_request", {
                "html": cur.get("html", ""),
                "title": cur.get("title", "Interactive"),
                "persistent": True,
                "allow_external": bool(cur.get("allow_external", False)),
                "view_id": cur.get("id", ""),
                "kind": cur.get("kind", "app"),
            }, frame.chatId))
        return

    async def _h_unsubscribe_chat(self, conn_id, frame, p, meta):
        self.hub.unsubscribe(conn_id, frame.chatId)
        # §client-caps: пересчитать без этого соединения (sticky удержит).
        await self._push_caps(frame.chatId)
        return

    async def _h_get_log(self, conn_id, frame, p, meta):
        lang = self.hub.conn_lang(conn_id)         # §i18n: как resume (§19.2)
        payload: dict[str, Any] = {
            "events": [i18n.localize_frame(e, lang) for e in
                       self.store.read_transcript_tail(frame.chatId, p.tail)]}
        if self.store.transcript_limit(frame.chatId) <= 0:
            payload["disabled"] = True  # чат создан с log_kb=0
        # MED-3: события журнала уже редактированы при publish — без повторной
        # редакции (тяжёлый regex по всему хвосту на event loop).
        await self.hub.send_global(conn_id, make_frame(
            "log_response", payload, frame.chatId), redact=False)
        return

    async def _h_get_status(self, conn_id, frame, p, meta):
        await self.hub.send_global(conn_id, make_frame(
            "status_response",
            self._chat_status(frame.chatId, with_result=True),
            frame.chatId))
        return

    async def _h_ack(self, conn_id, frame, p, meta):
        # ack под per-chat lock Hub'а (сериализация с журналом-в-потоке) + сам
        # rewrite в поток — иначе гонка с append терял бы свежий фрейм (§5.1).
        await self.hub.ack(frame.chatId, p.last_seen_id)
        log.info("chat.ack", chat_id=frame.chatId,
                 last_seen=(p.last_seen_id or "")[-6:])
        return

    async def _h_resume(self, conn_id, frame, p, meta):
        # M7: отставший девайс тянет хвост вечного транскрипта — читаем в
        # отдельном потоке, чтобы дисковый разбор не стопорил event loop.
        events, full_replay = await asyncio.to_thread(
            self.store.events_after, frame.chatId, p.last_seen_id)
        log.info("chat.resume", conn_id=conn_id, chat_id=frame.chatId,
                 events=len(events), full=full_replay,
                 last_seen=(p.last_seen_id or "")[-6:])
        # §multi-cli гейт: фреймы §18 (cli_switched) — только клиентам multi_cli.
        # cursor считаем по ПОЛНОМУ списку, чтобы не переполучать отфильтрованное.
        cursor = events[-1]["id"] if events else p.last_seen_id
        if not self.hub.conn_has_cap(conn_id, cli_registry.MULTI_CLI_CAP):
            events = [e for e in events
                      if e.get("type") not in cli_registry.MULTI_CLI_ONLY_TYPES]
        lang = self.hub.conn_lang(conn_id)         # §i18n: ключи журнала → язык
        events = [i18n.localize_frame(e, lang) for e in events]
        payload: dict[str, Any] = {
            "events": events,
            "cursor": cursor,
            "full_replay": full_replay,
        }
        if self.store.had_partial_loss(frame.chatId):
            payload["partial_loss"] = True
            self.store.clear_partial_loss(frame.chatId)
        # Прямой ответ, не через журнал — иначе resume зациклится.
        # MED-3: журнал редактирован при publish — повторно не гоняем regex.
        await self.hub.send_global(
            conn_id, make_frame("resume_response", payload, frame.chatId),
            redact=False)
        return

    async def _h_user_msg(self, conn_id, frame, p, meta):
        # §models M1: пришёл ход → гасим фоновую пробу /model, чтобы не
        # держать второй CLI-процесс рядом с единственной авторизацией.
        self._cancel_models_probe()
        # Эхо (§4.15): в чат пишут несколько писателей (устройства
        # пользователя, менеджер-агент, cron) — журналим и рассылаем
        # входящее ДО исполнения, чтобы все клиенты видели полную ленту.
        # Вложения (§7.3): эхо несёт их для чипов в ленте; агенту в промпт
        # дописываем абсолютные пути (Claude читает их Read'ом). Без
        # вложений поведение идентично прежнему.
        session = await self._ensure_session(meta)
        # /btw (§btw-interrupt A1): агент занят → сообщение ПРЕРВЁТ текущий
        # ход (handle_user_msg → client.interrupt()) и поедет следующим
        # ходом с контекстом. Помечаем эхо флагом btw — клиенты показывают
        # реплику как «дослано» (уточнение/«стой»).
        is_btw = (isinstance(session, _AGENT_SESSIONS)
                  and session.status == "busy")
        await self.hub.publish(frame.chatId, "user_msg_echo", {
            "content": p.content,
            "sender": p.sender,
            "related": frame.id,
            "attachments": [a.model_dump() for a in p.attachments],
            "btw": is_btw,
        })
        resolved = fileserver.resolve_attachment_paths(
            self.config.chats_dir, frame.chatId, p.attachments)
        prompt = fileserver.compose_prompt(p.content, resolved)
        # §draw: если сообщение несёт разметку окна — подкладываем её агенту
        # (скриншот + координаты + подсказка по HTML).
        if p.draw_view_id:
            note = self._draw_note(frame.chatId, p.draw_view_id)
            if note:
                prompt = f"{prompt}\n\n{note}" if prompt.strip() else note
        await self._deliver(frame.chatId, session, prompt)
        return

    async def _h_pty_write(self, conn_id, frame, p, meta):
        ftype = frame.type
        if meta.addressee != "broker_shell":
            await self.hub.send_global(conn_id, make_error(
                Err.BAD_FRAME, f"{ftype} is only valid for broker_shell chats",
                chat_id=frame.chatId, related=frame.id))
            return
        session = await self._ensure_session(meta)
        if ftype == "pty_write":
            await session.write(p.data)
        else:
            await session.resize(p.rows, p.cols)
        return

    async def _h_ui_event(self, conn_id, frame, p, meta):
        # §ui async: действие в постоянном окне (hedgehog.notify) →
        # полноценный ход агента, как обычное сообщение. Окна открывает только
        # ClaudeSession (ui_open — её инструмент) → для bash-чата ui_event
        # мусорный, сессию зря не поднимаем.
        if meta.addressee != "claude":
            return
        # §models M1: как в user_msg — гасим фоновую пробу /model, чтобы не
        # держать второй CLI-процесс рядом с единственной авторизацией.
        self._cancel_models_probe()
        # M: поднимаем сессию (после рестарта Ёжика окно ре-пушится клиенту
        # из views_registry, а sessions пуст — с sessions.get нажатие молча
        # терялось бы).
        session = await self._ensure_session(meta)
        if isinstance(session, _AGENT_SESSIONS):
            await self._deliver(frame.chatId, session, p.data, ui=True)
        return

    async def _h_ui_list(self, conn_id, frame, p, meta):
        # §views: список окон чата (текущее + история закрытых) БЕЗ html —
        # клиент строит меню «переоткрыть». Ответ только спросившему.
        await self.hub.send_global(conn_id, make_frame(
            "ui_list_response",
            views_registry.summary(self.config.data_dir, frame.chatId),
            frame.chatId))
        return

    async def _h_ui_reopen(self, conn_id, frame, p, meta):
        # §views: детерминированный пушер — сервер сам повторно шлёт
        # сохранённый ui_request в чат, БЕЗ хода агента (ноль токенов).
        # Уходит всем подписчикам чата (мультидевайс) + в журнал.
        rec = views_registry.reopen(self.config.data_dir, frame.chatId, p.id)
        if rec:
            await self.hub.publish(frame.chatId, "ui_request", {
                "html": rec.get("html", ""),
                "title": rec.get("title", "Interactive"),
                "persistent": True,
                "allow_external": bool(rec.get("allow_external", False)),
                "view_id": rec.get("id", ""),
                "kind": rec.get("kind", "app"),
            })
        else:
            await self.hub.send_global(conn_id, make_error(
                Err.BAD_FRAME, f"no view {p.id}",
                chat_id=frame.chatId, related=frame.id))
        return

    async def _h_ui_forget(self, conn_id, frame, p, meta):
        # §views: убрать окно из истории; вернуть обновлённый список.
        views_registry.forget(self.config.data_dir, frame.chatId, p.id)
        # §handlers: ручки, привязанные к этому окну, тоже стираем.
        handlers_registry.unregister_by_view(
            self.config.data_dir, frame.chatId, p.id)
        await self.hub.send_global(conn_id, make_frame(
            "ui_list_response",
            views_registry.summary(self.config.data_dir, frame.chatId),
            frame.chatId))
        return

    async def _h_ui_closed(self, conn_id, frame, p, meta):
        # §views: пользователь закрыл ПОСТОЯННОЕ окно крестиком с телефона →
        # архивируем текущее в историю (агентский ui_close делает это же
        # серверно). Возвращаем свежий список спросившему.
        views_registry.record_close(self.config.data_dir, frame.chatId)
        await self.hub.send_global(conn_id, make_frame(
            "ui_list_response",
            views_registry.summary(self.config.data_dir, frame.chatId),
            frame.chatId))
        return

    async def _h_ui_call(self, conn_id, frame, p, meta):
        # §handlers Ф-2: окно зовёт серверную ручку — детерминированно, БЕЗ
        # хода агента. Находим ручку в реестре чата, запускаем подпроцессом
        # (stdin=args → stdout=JSON), результат — тем же callId спросившему.
        rec = handlers_registry.get(
            self.config.data_dir, frame.chatId, p.name)
        if rec is None:
            await self.hub.send_global(conn_id, make_frame(
                "ui_call_result",
                {"callId": p.callId, "ok": False,
                 "error": f"no handler '{p.name}'"}, frame.chatId))
            return
        try:
            args_obj = json.loads(p.args or "{}")
        except ValueError:
            await self.hub.send_global(conn_id, make_frame(
                "ui_call_result",
                {"callId": p.callId, "ok": False,
                 "error": "args not JSON"}, frame.chatId))
            return
        res = await handler_runner.run(meta.cwd, rec["script"], args_obj)
        if res.get("ok"):
            payload = {"callId": p.callId, "ok": True,
                       "data": json.dumps(res.get("data"),
                                          ensure_ascii=False)}
        else:
            payload = {"callId": p.callId, "ok": False,
                       "error": res.get("error", "handler error")}
        await self.hub.send_global(
            conn_id, make_frame("ui_call_result", payload, frame.chatId))
        return

    async def _h_ui_new_blank(self, conn_id, frame, p, meta):
        # §draw: пользователь нажал ＋ — создаём пустое белое §views-окно
        # (холст для свободного рисунка) и пушим его как обычное окно.
        blank = ("<!DOCTYPE html><html><head><meta charset='UTF-8'>"
                 "<meta name='viewport' content='width=device-width,"
                 "initial-scale=1,maximum-scale=1'></head>"
                 "<body style='margin:0;background:#ffffff;'></body></html>")
        lang = self.hub.conn_lang(conn_id)
        title = p.title or i18n.t("ui.blank_canvas", lang)
        rec = views_registry.record_open(
            self.config.data_dir, frame.chatId,
            title=title, html=blank,
            persistent=True, allow_external=False, kind="blank")
        await self.hub.publish(frame.chatId, "ui_request", {
            "html": blank,
            "title": (rec.get("title", title) if p.title
                      else i18n.Msg("ui.blank_canvas")),
            "persistent": True, "allow_external": False,
            "view_id": rec.get("id", ""), "kind": "blank",
        })
        return

    async def _h_ui_draw_apply(self, conn_id, frame, p, meta):
        # §draw: «Применить» — сохранить рисунок (координаты + скриншот) на view.
        try:
            figs = json.loads(p.figures or "[]")
        except ValueError:
            figs = []
        res = views_registry.set_drawing(
            self.config.data_dir, frame.chatId, p.view_id,
            size={"w": p.width, "h": p.height}, figures=figs,
            image=p.image_id or "")
        if res and res.get("old_image"):
            self._delete_chat_file(frame.chatId, res["old_image"])
        return

    async def _h_ui_draw_clear(self, conn_id, frame, p, meta):
        # §draw: «Очистить/Стереть» — снять рисунок с view (+ удалить картинку).
        old = views_registry.clear_drawing(
            self.config.data_dir, frame.chatId, p.view_id)
        if old:
            self._delete_chat_file(frame.chatId, old)
        return

    async def _h_permission_response(self, conn_id, frame, p, meta):
        ftype = frame.type
        session = self.sessions.get(frame.chatId)
        resolved = False
        if isinstance(session, _AGENT_SESSIONS):
            # значение ответа зависит от типа фрейма; резолв — единый (§req).
            value = (p.decision if ftype == "permission_response"
                     else p.option_id if ftype == "picker_response"
                     else p.data)
            resolved = session.resolve(p.related, value)
        if not resolved and p.related in self._stale_requests.get(
                frame.chatId, ()):
            # §multi-cli: запрос отменён сменой CLI — поздний ответ не ошибка.
            self._stale_requests[frame.chatId].discard(p.related)
            return
        if not resolved:
            await self.hub.send_global(conn_id, make_error(
                Err.BAD_FRAME, f"no pending request {p.related}",
                chat_id=frame.chatId, related=frame.id))
        return

    # ---------- §draw: файлы разметки + инъекция в промпт ----------

    def _chat_file_path(self, chat_id: str, file_id: str) -> str | None:
        """fileId → абсолютный путь в хранилище файлов чата (или None)."""
        if not file_id or not file_id.isalnum():
            return None
        files_dir = self.config.chats_dir / chat_id / "files"
        try:
            matches = sorted(files_dir.glob(f"{file_id}__*")) \
                if files_dir.exists() else []
        except OSError:
            return None
        return str(matches[0]) if matches else None

    def _delete_chat_file(self, chat_id: str, file_id: str) -> None:
        path = self._chat_file_path(chat_id, file_id)
        if path:
            try:
                Path(path).unlink()
            except OSError:
                pass

    def _draw_note(self, chat_id: str, view_id: str) -> str:
        """Текст-приписка к промпту с разметкой окна (скриншот + координаты)."""
        view = views_registry.get_view(self.config.data_dir, chat_id, view_id)
        dr = (view or {}).get("drawing")
        if not isinstance(dr, dict):
            return ""
        figs = dr.get("figures") or []
        size = dr.get("size") or {}
        lines = [f"§draw: the user drew a marking over the window "
                 f"«{view.get('title', '')}» (view_id={view_id}). "
                 f"Figures: {len(figs)} (one figure = one stroke), "
                 f"view size {size.get('w')}×{size.get('h')} CSS-px."]
        img = self._chat_file_path(chat_id, dr.get("image", ""))
        if img:
            lines.append("Screenshot of the window WITH the drawing (BE SURE to view "
                         "it with the Read tool — it shows what is marked over the "
                         f"real state of the screen): {img}")
        lines.append("Figure coordinates (CSS-px, in drawing order): "
                     + json.dumps(figs, ensure_ascii=False)[:4000])
        if view.get("kind") != "blank":
            lines.append("This is an app window: match the drawing to the elements "
                         "and edit its HTML (ui_update / ui_open with the same title).")
        else:
            lines.append("This is an empty canvas — the user is drawing an idea from "
                         "scratch.")
        return "\n".join(lines)

    # ---------- лог приложения-клиента (§14) ----------

    def _append_client_log(self, text: str):
        """Дописать строку лога клиента в data/client.log с лимитом
        (512 МБ, хвост). Файл читается онлайн (напр. tail -f)."""
        path = self.config.client_log_file
        cap = self.config.client_log_cap
        line = text if text.endswith("\n") else text + "\n"
        try:
            with path.open("a", encoding="utf-8") as fh:
                fh.write(line)
            if path.stat().st_size > cap + cap // 10:
                self._truncate_client_log(path, cap)
        except OSError as e:
            log.warning("client_log.write_failed", err=str(e))

    @staticmethod
    def _truncate_client_log(path, cap: int):
        try:
            with path.open("rb") as fh:
                fh.seek(-cap, 2)
                tail = fh.read()
            nl = tail.find(b"\n")
            if nl != -1:
                tail = tail[nl + 1:]
            tmp = path.with_suffix(".log.tmp")
            tmp.write_bytes(tail)
            tmp.replace(path)
        except OSError:
            pass

    # ---------- авторизация (§13) ----------

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
        await self._reset_all_chat_models()      # per-chat выбор мог быть omniroute-id
        # Новый OAuth-токен: пересоздаём claude-сессии, чтобы SDK
        # подхватил env CLAUDE_CODE_OAUTH_TOKEN на следующем user_msg.
        await self._restart_cli_sessions(models.DEFAULT_CLI_TYPE)
        self._invalidate_models_cache()   # §models: список мог смениться
        await self._broadcast_cli_status(models.DEFAULT_CLI_TYPE)

    # ---------- статус чата (§3.7c) ----------

    # Хвост транскрипта, в котором ищем последний agent_done для last_result.
    _STATUS_SCAN_TAIL = 200
    _RESULT_MAX_CHARS = 1000

    @staticmethod
    def _mcp_config(p) -> dict:
        """AddMcpPayload → конфиг в схеме Claude Agent SDK (mcp_servers)."""
        cfg: dict[str, Any] = {"type": p.transport}
        if p.transport in ("http", "sse"):
            cfg["url"] = p.url or ""
            if p.header_name and p.header_value:
                cfg["headers"] = {p.header_name: p.header_value}
        else:  # stdio
            cfg["command"] = p.command or ""
            if p.args:
                cfg["args"] = list(p.args)
        return cfg

    def _mcp_tree(self, meta: ChatMeta) -> dict[str, Any]:
        """Список MCP-серверов: встроенный hedgehog (всегда вкл, read-only) +
        серверы реестра с флагом «включён в этом чате» (meta.mcp). Единый
        источник истины — показываем ВСЁ, что реально у агента. Секреты
        (значения заголовков/токены) наружу НЕ отдаём — только имя+тип."""
        enabled = set(meta.mcp or [])
        # Встроенный hedgehog (notify/ask_ui/send_to_chat/ui_* …) инжектится в
        # КАЖДУЮ сессию (claude_session) и в реестре не лежит — добавляем
        # синтетически. builtin=True → клиент рисует строку read-only.
        servers = [{"name": BUILTIN_MCP_NAME, "type": "builtin",
                    "enabled": True, "builtin": True}]
        # Реестровый сервер с именем встроенного (старые/битые данные) не
        # дублируем — встроенный уже добавлен выше.
        servers += [{**m, "enabled": m["name"] in enabled, "builtin": False}
                    for m in self.mcp.list_meta() if m["name"] != BUILTIN_MCP_NAME]
        # Имена, включённые в чате, но отсутствующие в реестре (битые/удалённые
        # руками) — показываем, чтобы их можно было выключить.
        known = {s["name"] for s in servers}
        for name in sorted(enabled - known):
            servers.append({"name": name, "type": None,
                            "enabled": True, "builtin": False})
        return {"servers": servers}

    def _skills_tree(self, meta: ChatMeta) -> dict[str, Any]:
        """Дерево источник→скиллы для skills_response (§skills v2).

        Источники берём из реестра (skill_sources.json), описания скиллов —
        из скана ФС (discover). Скиллы на диске без записи в реестре
        (положены руками/из проекта) показываем одиночными группами.
        enabled группы = ВСЕ её (существующие) скиллы в meta.skills.
        """
        discovered = {s["name"]: s for s in skills_registry.discover(meta.cwd)}
        allow = set(meta.skills or [])
        registry = self.skill_sources.sources()
        sources: list[dict] = []
        covered: set[str] = set()
        for name, info in registry.items():
            skill_names = [n for n in info.get("skills", []) if n in discovered]
            covered.update(info.get("skills", []))
            if not skill_names:
                continue  # все папки группы удалены с диска — пропускаем
            skills = [{"name": n, "description": discovered[n]["description"]}
                      for n in skill_names]
            sources.append({
                "source": name,
                "url": info.get("url"),
                "default_for_new": bool(info.get("default_for_new")),
                "enabled": all(n in allow for n in skill_names),
                "skills": skills,
            })
        # Осиротевшие скиллы (на ФС, но не привязаны к источнику) — одиночные группы.
        for name in sorted(discovered):
            if name in covered:
                continue
            sources.append({
                "source": name,
                "url": None,
                "default_for_new": False,
                "enabled": name in allow,
                "skills": [{"name": name,
                            "description": discovered[name]["description"]}],
            })
        return {"sources": sources}

    def _chat_status(self, chat_id: str, with_result: bool = False) -> dict[str, Any]:
        """status/last_activity чата; busy-детекция есть только у claude-сессий
        (PtySession без сигнала занятости — для него честный статус idle)."""
        session = self.sessions.get(chat_id)
        out: dict[str, Any] = {
            "status": getattr(session, "status", "idle"),
            "last_activity": self.store.transcript_mtime(chat_id),
        }
        if with_result:
            out["last_result"] = None
            for ev in reversed(self.store.read_transcript_tail(
                    chat_id, self._STATUS_SCAN_TAIL)):
                if ev.get("type") == "agent_done":
                    result = str((ev.get("payload") or {}).get("result", ""))
                    out["last_result"] = result[:self._RESULT_MAX_CHARS]
                    out["last_result_ts"] = ev.get("ts")
                    break
        return out

    def _chat_status_notifier(self, chat_id: str):
        """Колбэк для ClaudeSession: единая точка смены статуса чата.

        Сейчас — глобальный broadcast `chat_status` (обновляет точку в
        доке/списке у ВСЕХ клиентов, без polling). Сюда же позже вешаем
        push-уведомления (busy→idle = «агент ответил»)."""
        async def notify(status: str):
            # §obs: видимость реальных смен busy⇄idle (для проверки статуса).
            log.info("chat.status", chat_id=chat_id, status=status)
            await self.hub.broadcast_global(make_frame(
                "chat_status", {"chatId": chat_id, "status": status}))
            # TODO(push): триггер push-уведомления на переходе busy→idle.
        return notify

    # ---------- сессии ----------

    async def _deliver(self, chat_id: str, session, content: str, *,
                       ui: bool = False, **kw) -> None:
        """handle_user_msg с повтором: сессию могли закрыть (set_cli) между
        _ensure_session и постановкой в очередь — берём актуальную сессию чата."""
        for _ in range(3):
            try:
                if ui:
                    await session.handle_ui_event(content)
                else:
                    await session.handle_user_msg(content, **kw)
                return
            except SessionClosed:
                meta = self.store.get(chat_id)
                if meta is None:
                    return
                session = await self._ensure_session(meta)
        if ui:
            await session.handle_ui_event(content)
        else:
            await session.handle_user_msg(content, **kw)

    async def _ensure_session(self, meta: ChatMeta) -> ClaudeSession | PtySession:
        # S1-M: чат удаляется прямо сейчас — не поднимаем сессию (иначе воскресим).
        if meta.chatId in self._deleting:
            raise RuntimeError(f"chat {meta.chatId} is being deleted")
        session = self.sessions.get(meta.chatId)
        if session is not None:
            return session
        # §multi-cli (§18.5): создание сессии идёт под тем же per-chat замком, что
        # и set_cli — иначе user_msg посреди смены CLI поднял бы сессию СТАРОГО
        # CLI между stop и записью нового cliType. Мету перечитываем под замком.
        # §auth: пока идёт смена способа входа этого CLI, новую сессию не создаём
        # (иначе она взяла бы старые креды между quiesce и save). Ждём замок ДО
        # _chat_lock и тут же отпускаем: порядок замков auth→chat у активации
        # (quiesce берёт chat_lock под auth_lock), обратный порядок дал бы дедлок.
        while True:
            fresh = self.store.get(meta.chatId) or meta
            auth_lock = (self._auth_lock(fresh.cliType)
                         if fresh.addressee == "claude" else None)
            if auth_lock is not None:
                async with auth_lock:
                    pass
            async with self._chat_lock(meta.chatId):
                fresh = self.store.get(meta.chatId) or meta
                # Как в set_cli: активация могла захватить auth-замок ПОСЛЕ
                # «коснуться и отпустить» — тогда quiesce уже мог пройти этот
                # чат, и сессия поднялась бы со старыми кредами. Перепроверяем
                # под чатовым замком; занят → выходим из него и ждём снова.
                lk = (self._auth_lock(fresh.cliType)
                      if fresh.addressee == "claude" else None)
                if lk is None or not lk.locked():
                    return await self._ensure_session_locked(fresh)

    async def _ensure_session_locked(self, meta: ChatMeta):
        """Тело _ensure_session; вызывающий держит _chat_lock чата."""
        if meta.chatId in self._deleting:
            raise RuntimeError(f"chat {meta.chatId} is being deleted")
        session = self.sessions.get(meta.chatId)
        if session is not None:
            return session

        async def publish(ftype: str, payload: dict) -> dict:
            result = await self.hub.publish(meta.chatId, ftype, payload)
            # §push: агентский notify при оффлайн-клиенте → APNs-пуш через релей.
            if ftype == "notification":
                self._push_offline(meta.chatId, payload.get("title", ""),
                                   payload.get("body", ""))
            return result

        if meta.addressee == "claude":
            # §multi-cli: фабрика по активному CLI чата (сейчас только claude).
            session = await self._make_agent_session(meta, publish)
        else:
            session = PtySession(meta, publish, self.config)
        return await self._register_session(meta, session)

    async def _make_agent_session(self, meta: ChatMeta, publish):
        """§multi-cli: создать сессию агента по meta.cliType. Неизвестный тип
        (рассинхрон meta/сервера) — откат к claude с предупреждением."""
        cli_type = meta.cliType
        if cli_type not in self._AGENT_FACTORIES:
            log.warning("chat.clitype_no_factory", chat=meta.chatId,
                        cli=cli_type)
            cli_type = models.DEFAULT_CLI_TYPE
        # §cli-pins: CLI чата пропал/не доустановился (рестарт посреди
        # установки, сбой) — запускаем установку снова; воркер сессии её дождётся.
        if not self._cli_present(cli_type) and cli_install.installable(cli_type):
            self._start_cli_install(cli_type, meta.chatId)
        return await getattr(self, self._AGENT_FACTORIES[cli_type])(meta, publish)

    # cliType → имя метода-фабрики (расширяется по мере появления CLI).
    _AGENT_FACTORIES = {"claude": "_make_claude_session",
                        "antigravity": "_make_antigravity_session",
                        "codex": "_make_codex_session",
                        "grok": "_make_grok_session"}

    async def _make_acp_session(self, cls, cli: str, meta: ChatMeta, publish):
        """Общая фабрика не-Claude CLI-сессий: MCP = встроенный hedgehog
        (stdio-мост) + пользовательские из реестра."""
        async def chat_error(code: str, message: str):
            await self.hub.publish(meta.chatId, "error",
                                   {"code": code, "message": message,
                                    "cliType": cli})

        def save_session_id(sid: str | None, chat_id=meta.chatId):
            self.store.set_cli_state(chat_id, cli, session_id=sid,
                                     initialized=bool(sid))

        return cls(
            meta, publish, chat_error, self.config,
            mcp_servers=await self._agent_mcp_servers(meta),
            on_session_id=save_session_id,
            on_auth_required=functools.partial(self._on_cli_auth_required, cli),
            on_status=self._chat_status_notifier(meta.chatId),
            scheduler=self.scheduler, roster=self._roster)

    async def _make_codex_session(self, meta: ChatMeta, publish):
        """§20: сессия OpenAI Codex (`codex app-server`)."""
        return await self._make_acp_session(
            CodexSession, "codex", meta, publish)

    def _configure_grok_home(self) -> None:
        """§21.3: управляемый GROK_HOME (data_dir/grok-home) с правилами прав.
        HEDGEHOG_GROK_HOME=system — работать с личным ~/.grok без правил."""
        c = self.config
        if os.environ.get("HEDGEHOG_GROK_HOME") == "system":
            grok_auth.configure_managed_home(None, config=c)
            return
        grok_auth.configure_managed_home(c.data_dir / "grok-home", [
            str(c.token_file), str(c.oauth_token_file), str(c.auth_config_file),
            str(c.image_config_file), str(c.push_keys_file), str(c.tls_dir),
            str(c.data_dir / "grok-home"), str(c.data_dir / "grok-home-alt"), str(c.data_dir / "codex-home-alt"), str(c.data_dir / "agy-home-alt"),
            str(c.data_dir / "cli-bin"),
            str(c.data_dir / "auth.*.json")], config=c)

    async def _make_grok_session(self, meta: ChatMeta, publish):
        """§21: сессия Grok Build (`grok agent stdio`)."""
        return await self._make_acp_session(
            GrokSession, "grok", meta, publish)

    async def _make_antigravity_session(self, meta: ChatMeta, publish):
        """§multi-cli: сессия Antigravity (`agy acp`)."""
        return await self._make_acp_session(
            AntigravitySession, "antigravity", meta, publish)

    async def _agent_mcp_servers(self, meta: ChatMeta) -> dict[str, dict]:
        """Пользовательские MCP чата + авто-выдача браузера neko (общая для всех
        CLI)."""
        mcp_servers = self.mcp.resolve(meta.mcp)
        # §AI-control: если общий браузер neko поднят — АВТО-выдаём агенту
        # браузерные инструменты (@playwright/mcp по ВЫДЕЛЕННОЙ docker-сети
        # hedgehog↔neko). Реестр и meta.mcp не трогаем: доступно всем чатам,
        # пока neko жив; применяется при (пере)старте сессии. Порт наружу не
        # публикуется — достижим только отсюда.
        from .. import neko
        # N3: выдаём браузерный MCP только если AI-control РЕАЛЬНО доступен
        # (контейнер жив И Ёжик в neko-сети) — иначе агент получил бы
        # недостижимый MCP (клиент не публикует порт наружу).
        if await asyncio.to_thread(neko.ai_control_available):
            mcp_servers = {**mcp_servers, "neko_browser": {
                "type": "http",
                "url": f"http://{neko.CONTAINER}:{self.config.neko_mcp_port}/mcp",
            }}
        return mcp_servers

    async def _make_claude_session(self, meta: ChatMeta, publish):
        async def chat_error(code: str, message: str):
            await self.hub.publish(meta.chatId, "error",
                                   {"code": code, "message": message})
        mcp_servers = await self._agent_mcp_servers(meta)

        def save_session_id(sid: str | None, chat_id=meta.chatId):
            self.store.update_meta(chat_id, claude_session_id=sid)

        session = ClaudeSession(meta, publish, chat_error, self.config,
                                mcp_servers=mcp_servers,
                                on_auth_required=self._on_chat_auth_required,
                                on_session_id=save_session_id,
                                on_status=self._chat_status_notifier(meta.chatId),
                                scheduler=self.scheduler,
                                roster=self._roster)
        return session

    async def _register_session(self, meta: ChatMeta, session):
        # M6: пока строили сессию (await neko.ai_control_available / build_auth_env), в неё
        # мог параллельно впрыснуть cron/roster и уже поднять её — не плодим
        # второй CLI-процесс. re-check→assign без await между ними → атомарно.
        # S1-M: за время await'ов чат мог начать удаляться ИЛИ уже удалиться
        # целиком (delete пробежал и снял tombstone, пока мы висели на
        # neko.ai_control_available) — проверяем и метку, и наличие в сторе. store.get
        # синхронный, между ним и assign нет await → атомарно.
        if meta.chatId in self._deleting or self.store.get(meta.chatId) is None:
            raise RuntimeError(f"chat {meta.chatId} is being deleted")
        existing = self.sessions.get(meta.chatId)
        if existing is not None:
            return existing
        # §multi-cli (§18.5): пока строили сессию, мог прийти set_cli — тогда
        # сессия собрана под устаревший CLI. Выбрасываем её (не стартована) и
        # собираем заново по актуальной мете.
        fresh = self.store.get(meta.chatId)
        if (meta.addressee == "claude" and fresh is not None
                and fresh.cliType != meta.cliType):
            return await self._ensure_session_locked(fresh)
        self.sessions[meta.chatId] = session
        # §client-caps: инициализируем ветку рендера формул по подписчикам
        # (sticky возьмёт первый непустой набор — первый ход не уйдёт в текст,
        # если iOS уже прислал client_hello и подписался).
        if isinstance(session, AgentSession):
            session.set_client_caps(self.hub.caps_for_chat(meta.chatId))
        await session.start()
        return session

    def _detach_queue(self, chat_id: str) -> list:
        """Закрыть приём сессии чата и забрать ждущие в очереди сообщения;
        id её висящих запросов помечаются устаревшими (поздний ответ клиента
        молча игнорируется). Закрытие ДО take_queued: гонящийся
        handle_user_msg получит SessionClosed и повторит доставку."""
        session = self.sessions.get(chat_id)
        if not isinstance(session, AgentSession):     # нет сессии / PTY
            return []
        session.close_intake()
        queued = session.take_queued()
        self._stale_requests.setdefault(chat_id, set()).update(
            session.pending_request_ids())
        return queued

    async def _restart_session(self, chat_id: str) -> None:
        """Перезапуск сессии (смена режима/модели/MCP/скиллов): сообщения из
        очереди, уже показанные эхом, не теряются — едут в новую сессию."""
        # M2: detach+stop под чатовым замком — иначе _ensure_session, начатый
        # user_msg по СТАРОЙ мете (до set_mode/set_model), зарегистрировал бы
        # сессию уже после нашего stop. Подъём/доставка — ВНЕ замка:
        # _ensure_session берёт его сам (asyncio.Lock нереентерабелен).
        async with self._chat_lock(chat_id):
            queued = self._detach_queue(chat_id)
            await self._stop_session(chat_id)
        meta = self.store.get(chat_id)
        if queued and meta is not None:
            session = await self._ensure_session(meta)
            for content, on_result in queued:
                await self._deliver(chat_id, session, content,
                                    interrupt=False, on_result=on_result)

    async def _stop_session(self, chat_id: str):
        session = self.sessions.pop(chat_id, None)
        if session is not None:
            # сессия ушла из реестра: гонящийся handle_user_msg не должен её
            # оживить (получит SessionClosed и повторит через новую)
            if isinstance(session, AgentSession):
                session.close_intake()
            await session.stop()

    # ------------------------- §altauth: активация ----------------------------

    async def _quiesce_cli(self, cli: str, *, notify_busy: bool) -> list:
        """Остановить сессии чатов указанного CLI, сохранив ждущие в очереди
        сообщения. Под _chat_lock каждого чата (не гонимся с ensure/set_cli).
        notify_busy: идущему ходу — error AUTH_CHANGED. Возвращает
        [(chat_id, queued)] для _resume_queued (вызывать ВНЕ _auth_lock)."""
        pending = []
        for m in list(self.store.list()):
            if m.addressee != "claude" or m.cliType != cli:
                continue
            async with self._chat_lock(m.chatId):
                session = self.sessions.get(m.chatId)
                if session is None:
                    continue
                if notify_busy and getattr(session, "status", "idle") == "busy":
                    await self.hub.publish(m.chatId, "error", {
                        "code": Err.AUTH_CHANGED, "cliType": cli,
                        "message": i18n.Msg("auth.changed")})
                queued = self._detach_queue(m.chatId)
                await self._stop_session(m.chatId)
            if queued:
                pending.append((m.chatId, queued))
        return pending

    async def _resume_queued(self, pending: list) -> None:
        """Доставить сохранённую очередь в новые сессии. НЕ вызывать под
        _auth_lock: _ensure_session ждёт этот же замок."""
        for chat_id, queued in pending:
            meta = self.store.get(chat_id)
            if meta is None:
                continue
            try:
                session = await self._ensure_session(meta)
                for content, on_result in queued:
                    await self._deliver(chat_id, session, content,
                                        interrupt=False, on_result=on_result)
            except Exception as e:  # noqa: BLE001 — не терять остальные чаты
                log.warning("auth.resume_queued_failed", chat=chat_id,
                            err=secrets_redact.redact(repr(e)))

    async def _restart_cli_sessions(self, cli: str) -> None:
        """Уронить сессии CLI → следующий ход поднимет их с новыми кредами;
        очередь переезжает в новую сессию. Вне _auth_lock."""
        await self._resume_queued(await self._quiesce_cli(cli, notify_busy=False))

    # ------------------------- §netwait: долгие операции ----------------------

    async def _emit_op_slow(self, op_id: str, kind: str, conn_id: int,
                            broadcast: bool):
        """Через op_slow_after секунд без ответа → op_slow («>10с, прервать?»).
        Операция продолжает идти. Отмена таймера = ответ пришёл раньше."""
        try:
            await asyncio.sleep(self.config.op_slow_after)
        except asyncio.CancelledError:
            return
        frame = make_frame("op_slow", {"opId": op_id, "kind": kind})
        if broadcast:                       # login глобальный — всем устройствам
            await self.hub.broadcast_global(frame)
        else:                               # omni/apikey — адресно инициатору (H1)
            await self.hub.send_global(conn_id, frame)

    def _mark_committing(self, op_id: str | None):
        """Сетевая фаза операции прошла → op_abort её больше НЕ рвёт (H2):
        коммит (save_auth_config + restart) доходит до конца, придёт реальный
        результат. no-op вне трекинга (op_id=None / уже снят)."""
        op = self._ops.get(op_id) if op_id else None
        if op is not None:
            op["abortable"] = False

    def _spawn_tracked(self, conn_id: int, op_id: str, kind: str, coro,
                       *, broadcast: bool = False):
        """§netwait H1: запускаем операцию ОТДЕЛЬНОЙ задачей, не блокируя
        reader-loop соединения — иначе op_abort/ping этого клиента не читались бы
        до конца операции (abort не работал бы, ping-timeout → ложный reconnect).
        _run_tracked самодостаточен (сам шлёт ответ/ошибки).

        Известное (принято, L5/L6): op регистрируется в _ops только при первом
        запуске _run_tracked — в суб-миллисекундном окне до этого op_abort/shutdown
        его «не видят». Недостижимо на практике (abort жмут только после op_slow
        через 10с; shutdown в этот тик — teardown процесса, максимум долетит
        безвредный save_auth_config)."""
        asyncio.create_task(
            self._run_tracked(conn_id, op_id, kind, coro, broadcast=broadcast),
            name=f"netwait-{kind}")

    async def _run_tracked(self, conn_id: int, op_id: str, kind: str, coro,
                           *, broadcast: bool = False):
        """Обёртка долгой операции: slow(op_slow) + hard-timeout + abort.
        coro → (result_ftype, payload); ответ адресно инициатору с related=opId.
        Абортится только сетевая фаза (до _mark_committing). Держит сетку
        исключений (H3): любой сбой → адресный error(related)."""
        # M: op_id == frame.id. Если клиент переиспользовал id для второй
        # параллельной операции — регистрация ниже перезаписала бы первую, а её
        # finally-pop снял бы вторую из _ops (abort/shutdown её «не видят»).
        # Отказываемся стартовать дубль (первый доработает штатно).
        if op_id in self._ops:
            if asyncio.iscoroutine(coro):
                coro.close()          # не запускаем корутину — без «never awaited»
            else:                     # Task/Future (не случается) — не теряем управление
                asyncio.ensure_future(coro).cancel()
            # дубль frame.id — клиентское нарушение протокола, не сбой сервера
            # (иначе retry-on-INTERNAL у клиента зациклится на том же id).
            await self.hub.send_global(conn_id, make_error(
                Err.BAD_FRAME, "duplicate operation id", related=op_id))
            return
        slow = asyncio.create_task(
            self._emit_op_slow(op_id, kind, conn_id, broadcast))
        work = asyncio.ensure_future(coro)
        self._ops[op_id] = {"conn_id": conn_id, "kind": kind,
                            "broadcast": broadcast, "work_task": work,
                            "slow_task": slow, "abortable": True,
                            "wrapper": asyncio.current_task()}
        try:
            try:
                ftype, payload = await asyncio.wait_for(
                    asyncio.shield(work), self.config.op_hard_timeout)
            except asyncio.TimeoutError:
                if not work.done() and self._ops.get(
                        op_id, {}).get("abortable", False):
                    work.cancel()
                    await self.hub.send_global(conn_id, make_error(
                        Err.OP_TIMEOUT, "operation timed out", related=op_id))
                    return
                ftype, payload = await work   # коммит уже идёт — дождёмся итога
            await self.hub.send_global(conn_id, make_frame(
                ftype, {**payload, "related": op_id}))
        except asyncio.CancelledError:
            if work.cancelled():              # прервано op_abort — штатно
                await self.hub.send_global(conn_id, make_error(
                    Err.OP_ABORTED, "operation aborted", related=op_id))
            else:
                raise                         # отмена самого _run_tracked (shutdown)
        except Exception as e:                # noqa: BLE001 — H3: сетка исключений
            log.warning("netwait.op_failed", op=op_id, kind=kind,
                        err=secrets_redact.redact(repr(e)))
            await self.hub.send_global(conn_id, make_error(
                Err.INTERNAL, secrets_redact.redact(f"operation failed: {e}"),
                related=op_id))
        finally:
            slow.cancel()
            # снимаем ТОЛЬКО свою запись (defense-in-depth к дубль-отказу выше):
            # если бы в _ops оказался чужой op с тем же id — не трогаем его.
            if self._ops.get(op_id, {}).get("wrapper") is asyncio.current_task():
                self._ops.pop(op_id, None)

    async def _handle_op_abort(self, op_id: str):
        """op_abort от клиента: прервать сетевую фазу операции. login —
        глобально (любой клиент). Неизвестный/завершённый opId — тихий no-op (M4)."""
        op = self._ops.get(op_id)
        if op is not None:
            if op["abortable"] and not op["work_task"].done():
                op["work_task"].cancel()      # _run_tracked пошлёт OP_ABORTED
            return
        lop = self._login_op
        if lop is not None and lop["op_id"] == op_id:
            await self._abort_login("authorization aborted")

    # -- login single-flight: таймеры на сетевые под-ожидания (M2) --

    def _start_login_timers(self, op_id: str, conn_id: int, phase: str):
        """phase='start' (auth_start→auth_link) или 'code' (auth_code→auth_result).
        Один набор одновременно (single-flight)."""
        self._cancel_login_timers()
        slow = asyncio.create_task(
            self._emit_op_slow(op_id, "login", conn_id, True))   # broadcast
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
        await self._resume_queued(pending)

    async def _cli_logout_locked(self, cli: str) -> list:
        if auth_store.active_method(self.config, cli) != auth_store.SUBSCRIPTION:
            # снимаем активный API-ключ/шлюз; вход по подписке (токен) не трогаем
            pending = await self._quiesce_cli(cli, notify_busy=True)
            auth_store.clear(self.config, cli)
            try:
                await self._apply_alt_mode(cli, {})
            except Exception as e:  # noqa: BLE001 — режим уже снят, чистка best-effort
                log.warning("auth.alt_clear_failed", cli=cli,
                            err=secrets_redact.redact(repr(e)))
            await self._after_auth_change(cli)
            log.info("auth.alt_logout", cli=cli)
            return pending
        mod = _LOGIN_MODULES.get(cli)
        if mod is None:
            return []
        await self._auth_manager(cli).stop()
        pending = await self._quiesce_cli(cli, notify_busy=False)
        mod.logout()
        self._invalidate_models_cache()
        log.info("auth.logout", cli=cli)
        await self._broadcast_cli_status(cli)
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
        await self._resume_queued(pending)
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
        self._mark_committing(op_id)
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
        pending = await self._quiesce_cli(cli, notify_busy=True)
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
            await self._broadcast_cli_status(cli)
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
        mod = _LOGIN_MODULES.get(cli)       # apply_alt: sync или async
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
            if (m.cliSessions.get(cli) or {}).get("model"):
                updated = self.store.set_cli_state(m.chatId, cli, model=None,
                                                   effort=None)
                if updated is not None:
                    await self._broadcast_meta("chat_updated", updated)
        self._cli_token_rejected.discard(cli)   # MED-1: другой способ — другой статус
        self._invalidate_models_cache()
        await self._broadcast_cli_status(cli)

    async def _broadcast_cli_status(self, cli: str, *, install: bool = False) -> None:
        """cli_status (§18.7) — глобально, только клиентам multi_cli.
        §cli-pins: поле installing — в кадрах фоновой установки (install=True:
        старт → true, итог → false) и пока она идёт; иначе поля нет (= false)."""
        if not self.hub.any_conn_has_cap(cli_registry.MULTI_CLI_CAP):
            return
        snap = self._cli_status_snapshot().get(cli)
        if snap is None:
            return
        payload = {
            "cliType": cli, "present": snap["present"],
            "auth_state": snap["auth_state"],
            "activeMethod": snap["activeMethod"],
            "authDetail": snap["authDetail"]}
        if install or self._cli_installing(cli):
            payload["installing"] = self._cli_installing(cli)
        await self.hub.broadcast_global(make_frame("cli_status", payload),
                                        require_cap=cli_registry.MULTI_CLI_CAP)

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
            await self._restart_cli_sessions(cli)
            self._invalidate_models_cache()
            await self._broadcast_cli_status(cli)

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
        mod = _LOGIN_MODULES.get(cli)
        if (cli not in _AUTOLOGIN_OVER_TOKEN
                and mod is not None and mod.is_logged_in()):
            log.info("auth.required_with_token", cli=cli)
            self._cli_token_rejected.add(cli)
            await self._broadcast_cli_status(cli)
            return
        mgr = self._auth_manager(cli)
        if mgr is not None:
            await mgr.start()

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
        obj = HedgehogServer._json_obj(text)
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
        self._mark_committing(op_id)   # §netwait H2: сетевая фаза прошла
        if not ok:
            return False, err
        self.config.save_auth_config({
            "mode": "apikey", "api_key": api_key, "base_url": base_url or None})
        await self._quiet_stop_login()   # осиротевший setup-token → ложный «600s»
        await self._reset_all_chat_models()    # §models L2: выбор мог протухнуть
        await self._restart_cli_sessions(models.DEFAULT_CLI_TYPE)
        self._invalidate_models_cache()   # §models: список зависит от ключа
        await self._broadcast_cli_status(models.DEFAULT_CLI_TYPE)
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
            self._mark_committing(op_id)
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
            self._mark_committing(op_id)   # активацию не блокируем probe'ом шлюза
            self.config.save_auth_config({
                "mode": "omniroute", "api_key": p.api_key, "base_url": p.base_url,
                "opus_model": p.opus_model, "sonnet_model": p.sonnet_model,
                "haiku_model": p.haiku_model,
                "default_tier": p.default_tier or "haiku"})
            log.info("auth.omniroute_activated", base_url=p.base_url,
                     new=False, default_tier=p.default_tier)
        await self._quiet_stop_login()   # убить осиротевший setup-token (ложный «600s»)
        await self._reset_all_chat_models()    # §models L2: выбор мог протухнуть
        await self._restart_cli_sessions(models.DEFAULT_CLI_TYPE)
        self._invalidate_models_cache()   # §models: список зависит от шлюза
        await self._broadcast_cli_status(models.DEFAULT_CLI_TYPE)
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
        self._mark_committing(op_id)   # §netwait H2: сетевая фаза прошла
        if not ok:
            return False, err
        self.config.save_auth_config({**auth, "api_key": api_key})
        await self._quiet_stop_login()   # убить осиротевший setup-token (ложный «600s»)
        await self._restart_cli_sessions(models.DEFAULT_CLI_TYPE)   # новый ключ в env новой сессии
        self._invalidate_models_cache()
        await self._broadcast_cli_status(models.DEFAULT_CLI_TYPE)
        log.info("omni.key_updated", base_url=base)
        return True, None

    def _gateway_models_list(self, cli_type: str) -> dict | None:
        """§auth: models_list из выбранных моделей шлюза не-Claude CLI."""
        if cli_type == models.DEFAULT_CLI_TYPE:
            return None
        rec = auth_store.load(self.config, cli_type)
        if rec.get("catalog") and rec.get("method") in (auth_store.API_KEY,
                                                        auth_store.GATEWAY):
            # CLI с фиксированными моделями (Antigravity) под ключом: каталог API
            return {"cliType": cli_type, "models": list(rec["catalog"]),
                    "names": {i: i for i in rec["catalog"]}, "current": None,
                    "source": "api", "raw": "", "auth_state": "OK",
                    "cli_present": True, "updated_at": 0}
        if rec.get("method") != auth_store.GATEWAY or not rec.get("models"):
            return None
        sel = rec["models"]
        return {"cliType": cli_type, "models": [m["id"] for m in sel],
                "names": {m["id"]: m.get("name") or m["id"] for m in sel},
                "current": rec.get("active_id"), "source": "gateway", "raw": "",
                "auth_state": "OK", "cli_present": True, "updated_at": 0}

    def _omniroute_models_list(self, cli_type: str) -> dict | None:
        """§omni: models_list из ВЫБРАННЫХ моделей (если активна omniroute-авториз.
        нового вида). Иначе None → обычный источник (CLI-проба). Тир НЕ режем —
        отдаём всё, первые N покажет клиент."""
        auth = self.config.load_auth_config()
        if auth.get("mode") != "omniroute" or not auth.get("active_id"):
            return None
        sel = auth.get("models") or []
        # Метка чипа в CLI-view = «алиас/имя» (напр. cc/Opus): алиас = префикс id
        # (namespace, no-think снят), имя — заданное пользователем.
        def _label(m: dict) -> str:
            name = m.get("name") or m["id"]
            alias = omniroute_gw._namespace(m["id"])
            return f"{alias}/{name}"
        return {
            "cliType": cli_type,
            "models": [m["id"] for m in sel],                       # compat: id-строки
            "names": {m["id"]: _label(m) for m in sel},             # id→«алиас/имя»
            "current": auth.get("active_id"),
            "source": "omniroute",
            "raw": "", "auth_state": "OK",
            "cli_present": True, "updated_at": 0,
        }
