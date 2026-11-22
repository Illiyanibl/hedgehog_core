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
import functools
import hmac
import http
import json
import operator
import os
import time
from pathlib import Path
from typing import Any

import structlog
import websockets
from websockets.asyncio.server import Request, Response, ServerConnection, serve
from websockets.protocol import State

from .. import tls

from ..bus.hub import Hub
from ..config import Config
from ..core.claude_session import ClaudeSession
from ..core.session_base import AgentSession, SessionClosed
from ..core.hedgehog_mcp import BUILTIN_MCP_NAME
from ..core.pty_session import PtySession
from ..core import models
from ..core import effort as effort_mod
from ..protocol import (
    Attachment,
    BadFrame,
    ClientFrame,
    Err,
    dumps,
    make_error,
    make_frame,
    parse_client_frame,
)
from ..scheduler import DeferPendingExists
from ..core import (auth_store, cli_install, cli_registry, codex_rpc, grok_auth,
                    secrets_redact)
from ..core.codex_session import CodexSession
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
from .. import push
from .services.cli_auth import CliAuthService
from .services.cli_installer import CliInstallService
from .services.models import ModelsRefresher
from .services.neko import NekoController
from .services.update import SERVER_COMMIT, UpdateController

log = structlog.get_logger("wss")

# §multi-cli: сессии агентов (общие операции: caps, ui_event, ответы на запросы).
_MCP_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")  # имя MCP: без «_» в начале/спецсимволов
_AGENT_SESSIONS = AgentSession    # runtime-Protocol: Claude/agy/Codex (не PTY)

WS_PATH = "/v1/connect"

# §update: короткий SHA HEAD этого процесса (SERVER_COMMIT) — определён в
# services/update.py (там же update_self), сюда импортирован для hello.

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
        # §auth: вход/выход/смена способа авторизации CLI — отдельный сервис.
        # Создаётся здесь же: менеджеры входа, GROK_HOME, configure() модулей
        # входа, каталог CLI и источники редакции секретов — в прежнем порядке.
        self.cli_auth = CliAuthService(self)
        # §push: notifyKey'и устройств (для APNs-пуша при оффлайн-клиенте).
        self.push_keys = push.PushKeys(config.push_keys_file)
        # Сильные ссылки на fire-and-forget задачи пуша: asyncio держит задачи
        # лишь слабо, без ссылки их может собрать GC до завершения.
        self._push_tasks: set[asyncio.Task] = set()
        # §reply: ожидающие reply-армы по чату-инициатору (monotonic-таймстампы);
        # cap+TTL в _reply_arm. См. send_to_chat/_deliver_reply.
        self._reply_pending: dict[str, list[float]] = {}
        # §17: install/get/remove neko и neko_open_view (серверный NekoProxy) — сервис.
        self.neko_ctl = NekoController(self)
        # §sched: планировщик задач + блэкборд. Ставится из main.py после
        # конструктора (нужны колбэки inject/notify, замкнутые на этот сервер).
        self.scheduler = None
        # §models: фоновый рефрешер/кэш списка моделей и models_list — сервис.
        self.models_refresher = ModelsRefresher(self)
        # §roster: фасад «список чатов + прямой впрыск» для кросс-чат MCP-тулов
        # (list_chats / send_to_chat), прокидывается в каждую ClaudeSession.
        self._roster = ChatRoster(self)
        # §netwait: реестр долгих операций (opId → {conn_id,kind,broadcast,
        # work_task,slow_task,abortable}) для op_slow/op_abort/hard-timeout.
        self._ops: dict[str, dict[str, Any]] = {}
        # S1-M: chatId'ы в процессе удаления — «надгробие» на время delete_chat.
        # _ensure_session отказывается поднимать такой чат, чтобы параллельный
        # user_msg/inject (meta прочитана до удаления) не воскресил его сессию
        # (висячий CLI-процесс + падение журнала на удалённый чат).
        self._deleting: set[str] = set()
        # §multi-cli: per-chat замок на смену CLI; id запросов, отменённых
        # сменой (поздний permission/picker/ui-ответ молча игнорируем).
        self._chat_locks: dict[str, asyncio.Lock] = {}
        self._stale_requests: dict[str, set[str]] = {}
        # §15: update_self (single-flight, фоновая задача, рестарт) — сервис.
        self.update_ctl = UpdateController(self)
        # §cli-pins: присутствие CLI, фоновая установка и cli_status — сервис.
        self.cli_installer = CliInstallService(self)
        # §defer-clock: смещение часов Anthropic относительно локальных
        # (serverDate из заголовка Date ответа /v1/messages − time.time()).
        # Обновляется при get_limits. Нужно, чтобы планировать defer к реальному
        # сбросу лимита, даже если системные часы сервера уехали (наблюдали −22ч).
        # Якоря monotonic/wall — чтобы поймать ШАГ часов (NTP/ресинк) после замера
        # и не доверять протухшему offset (иначе defer выстрелит мгновенно).
        self._clock_offset = 0.0
        self._clock_offset_mono = 0.0
        self._clock_offset_wall = 0.0

    _SERVICE_ATTRS = ("cli_auth", "cli_installer", "models_refresher",
                      "neko_ctl", "update_ctl")

    def __setattr__(self, name: str, value):
        # Запись имени, которое живёт в сервисе, создала бы на сервере тень,
        # которую сервис не видит (подмена в тесте тихо перестала бы
        # действовать) — запрещаем. По факту, а не по списку: имя не объявлено
        # у класса сервера, но есть у одного из созданных сервисов.
        # config/hub/store — общие ссылки сервера, сервисы читают их через
        # host (property-прокси), поэтому тенью они не бывают.
        if name not in HedgehogServer._SERVICE_ATTRS \
                and name not in ("config", "hub", "store") \
                and not hasattr(type(self), name):
            d = self.__dict__
            for attr in HedgehogServer._SERVICE_ATTRS:
                svc = d.get(attr)
                if svc is not None and (hasattr(type(svc), name)
                                        or name in vars(svc)):
                    raise AttributeError(
                        f"{name!r} lives in {type(svc).__name__}: "
                        f"set s.{attr}.{name}")
        object.__setattr__(self, name, value)

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
        self.models_refresher.cancel_models_probe()
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
            self.models_refresher.cancel_models_probe()
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
            self.models_refresher.start()
            await asyncio.get_running_loop().create_future()  # до отмены

    async def shutdown(self):
        # §netwait H3/L4: сначала гасим login-таймеры (иначе hard-таймер мог бы
        # выстрелить в зазор до отмены) и вход, затем все долгие операции.
        await self.cli_auth.shutdown()
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
        await self.models_refresher.shutdown()   # проба + рефрешер моделей
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
        self.neko_ctl.cancel_jobs()
        self.update_ctl.cancel_jobs()
        # §cli-pins: установки CLI — флаг отмены + отмена задач.
        await self.cli_installer.shutdown()
        await self.neko_ctl.shutdown()     # §17: догасить серверный MCP-проброс neko
        await self.hub.aclose()          # backpressure: догасить close-задачи шины

    # ---------- §models: рефрешер/кэш моделей — ModelsRefresher ----------
    # (на сервере — делегат _invalidate_models_cache и сброс выбора по чатам)

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
        # Контракт хоста для CliAuthService/CliInstallService: делегируем.
        self.models_refresher.invalidate_models_cache()

    async def _push_models_list(self, cli: str) -> None:
        # Контракт хоста для CliInstallService: делегируем.
        await self.models_refresher.push_models_list(cli)

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
                # §23: и уровень — под новым способом входа он мог стать
                # недоступным (шлюз).
                st = m.cliSessions.get("claude") or {}
                if st.get("model") or st.get("effort"):
                    updated = self.store.set_cli_state(
                        m.chatId, "claude", model=None, effort=None)
                    if updated is not None:     # L6: как M4 — клиент видит сброс
                        await self._broadcast_meta("chat_updated", updated)
                continue
            st = m.cliSessions.get("claude") or {}
            if getattr(m, "model", None) or st.get("effort"):
                updated = self.store.update_meta(m.chatId, model=None)
                if updated is not None and st.get("effort"):
                    updated = self.store.set_cli_state(
                        m.chatId, "claude", effort=None) or updated
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
                "server_commit": SERVER_COMMIT,   # §update: HEAD для сверки с репо
                "supported_v": list(self.config.protocol_versions),
                "capabilities": list(self.config.capabilities),
                # §cli-types: какие типы CLI-агентов умеет этот Ёžik (клиент
                # покажет выбор только из них; старый клиент поле игнорит).
                "cliTypes": list(cli_registry.legacy_visible_cli_types()),
                # §multi-cli (§18.3): присутствие/авторизация/возможности каждого
                # CLI. Поле добавочное — старый клиент его игнорирует (§9.4).
                "cliStatus": self.cli_installer.cli_status_snapshot(),
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
    # Точечное имя ('cli_auth._h_x') — хендлер сервиса (operator.attrgetter).
    _SYS_ROUTES = {
        'ping': '_h_ping',
        'op_abort': '_h_op_abort',
        'auth_start': 'cli_auth._h_auth_start',
        'auth_code': 'cli_auth._h_auth_code',
        'auth_apikey': 'cli_auth._h_auth_apikey',
        'auth_omniroute': 'cli_auth._h_auth_omniroute',
        'auth_gateway': 'cli_auth._h_auth_gateway',
        'auth_token': 'cli_auth._h_auth_token',
        'omniroute_probe_models': 'cli_auth._h_omniroute_probe_models',
        'omniroute_set_key': 'cli_auth._h_omniroute_set_key',
        'omniroute_set_models': 'cli_auth._h_omniroute_set_models',
        'logout': 'cli_auth._h_logout',
        'client_log': '_h_client_log',
        'register_push': '_h_register_push',
        'client_hello': '_h_client_caps',
        'client_caps_update': '_h_client_caps',
        'set_language': '_h_set_language',
        'update_self': 'update_ctl._h_update_self',
        'install_neko': 'neko_ctl._h_install_neko',
        'get_neko': 'neko_ctl._h_install_neko',
        'remove_neko': 'neko_ctl._h_install_neko',
        'neko_open_view': 'neko_ctl._h_neko_open_view',
        'install_skill': '_h_install_skill',
        'set_skill_default': '_h_set_skill_default',
        'list_chats': '_h_list_chats',
        'list_models': 'models_refresher._h_list_models',
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
            await operator.attrgetter(name)(self)(conn_id, frame, p)
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
            await operator.attrgetter(name)(self)(conn_id, frame, p, meta)
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

    async def _reply_or_broadcast(self, conn_id, frame):
        """Итог долгой фоновой операции (update_self, ошибка neko) —
        инициатору, если он ещё на связи; иначе всем (клиент мог
        переподключиться за время pull/pip)."""
        if self.hub.has_conn(conn_id):
            await self.hub.send_global(conn_id, frame)
        else:
            await self.hub.broadcast_global(frame)

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
            err = self.cli_installer.cli_error(p.cliType, allow_install=multi)
            if err is None and not self.cli_installer.cli_present(p.cliType):
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
            self.cli_installer.start_cli_install(install_cli, meta.chatId)
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
    # Присутствие CLI, фоновая установка (§cli-pins) и cli_status — в
    # CliInstallService (self.cli_installer).

    async def _broadcast_cli_status(self, cli: str, *, install: bool = False) -> None:
        # Контракт хоста для CliAuthService (AuthHost): делегируем в сервис.
        await self.cli_installer.broadcast_cli_status(cli, install=install)

    async def _broadcast_meta(self, ftype: str, meta: ChatMeta) -> None:
        """chat_created/chat_updated: клиентам multi_cli — с cliSessions (без
        session_id), остальным — wire как до фичи."""
        await self.hub.broadcast_variants(
            make_frame(ftype, public_meta(meta)),
            make_frame(ftype, public_meta(meta, include_cli_sessions=True)),
            cli_registry.MULTI_CLI_CAP)

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
        err = self.cli_installer.cli_error(p.cliType, allow_install=True)
        if err is not None:
            await self.hub.send_global(conn_id, make_error(
                err[0], err[1], chat_id=frame.chatId, related=frame.id))
            return
        if not self.cli_installer.cli_present(p.cliType):
            # §cli-pins: CLI нет, но есть пин — переключаем как обычно, ставим фоном
            self.cli_installer.start_cli_install(p.cliType, frame.chatId)
        # M3: идёт смена способа входа нового CLI — ждём её, иначе сессия под
        # чатовым замком стартовала бы со старыми кредами (между quiesce и save).
        # Коснуться-и-отпустить ДО _chat_lock: порядок auth→chat (как в
        # _ensure_session), иначе дедлок с активацией. MED-2: между отпусканием
        # auth_lock и захватом _chat_lock активация могла снова взять замок —
        # тогда отпускаем _chat_lock, снова ждём auth_lock и повторяем.
        auth_lock = self.cli_auth.auth_lock(p.cliType)
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
        # §23: effort валидируем ДО записи — при ошибке мета не меняется вовсе
        # (ни модель, ни уровень). Отсутствует → не менять (но уровень, не
        # допустимый для новой модели, сбрасывается); "" → null.
        req_effort = getattr(p, "effort", None)
        stored = new_effort = None
        if meta is not None and meta.addressee == "claude":
            cli = meta.cliType
            stored = new_effort = (meta.cliSessions.get(cli) or {}).get("effort")
            data = self.models_refresher.models_data(cli)
            if req_effort is not None:
                # L4: как у model — только непечатаемые и пробелы по краям
                # (длину ограничивает протокол); '-' и т.п. допустимы.
                effort = "".join(ch for ch in req_effort
                                 if ch.isprintable()).strip() or None
                try:
                    new_effort = effort_mod.validate(data, new_model, effort,
                                                     cli)
                except effort_mod.UnknownEffort:
                    await self.hub.send_global(conn_id, make_error(
                        Err.BAD_FRAME, "unknown effort",
                        chat_id=frame.chatId, related=frame.id))
                    return
            else:
                new_effort = effort_mod.reconcile(data, new_model, stored, cli)
        updated = self.store.update_meta(frame.chatId, model=new_model)
        if updated is None:   # L: чат исчез (конкурентный delete) → vars(None)
            return
        if updated.addressee == "claude" and (new_effort != stored
                                              or req_effort is not None):
            updated = self.store.set_cli_state(
                frame.chatId, updated.cliType, effort=new_effort) or updated
        await self._restart_session(frame.chatId)
        log.info("chat.model_changed", chat=frame.chatId, model=new_model,
                 effort=new_effort)
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
        self.models_refresher.cancel_models_probe()
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
        self.models_refresher.cancel_models_probe()
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
            auth_lock = (self.cli_auth.auth_lock(fresh.cliType)
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
                lk = (self.cli_auth.auth_lock(fresh.cliType)
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
        if not self.cli_installer.cli_present(cli_type) and cli_install.installable(cli_type):
            self.cli_installer.start_cli_install(cli_type, meta.chatId)
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
            on_auth_required=functools.partial(self.cli_auth.on_cli_auth_required, cli),
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
                                on_auth_required=self.cli_auth.on_chat_auth_required,
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
        [(chat_id, queued)] для _resume_queued (вызывать ВНЕ auth_lock)."""
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
        auth_lock: _ensure_session ждёт этот же замок."""
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
        очередь переезжает в новую сессию. Вне auth_lock."""
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
        await self.cli_auth.abort_login_if(op_id)

