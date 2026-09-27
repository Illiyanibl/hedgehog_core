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
import copy
import hashlib
import http
import json
import time
from pathlib import Path
from typing import Any

import structlog
import websockets
from websockets.asyncio.server import Request, Response, ServerConnection, serve

from .. import tls

from ..bus.hub import Hub
from ..config import Config
from ..core.auth import AuthManager
from ..core.claude_session import ClaudeSession
from ..core.pty_session import PtySession
from ..core import models
from ..core.gateways import omniroute as omniroute_gw
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
from ..store.chats import ChatMeta, ChatStore
from ..store.mcp_registry import McpRegistry
from ..store import skills_registry
from ..store import views_registry
from ..store import handlers_registry
from ..core import handler_runner
from ..store.skill_sources import SkillSources, SkillInstallError
from .. import fileserver
from .. import authlog
from .. import updater
from .. import push

log = structlog.get_logger("wss")

WS_PATH = "/v1/connect"

# §update: короткий SHA HEAD этого процесса — клиент сравнивает его с последним
# коммитом репозитория (GitHub) и предлагает «Обновить». Меняется только при
# рестарте после update_self (git reset --hard), поэтому кэшируем один раз.
_SERVER_COMMIT = updater.current_sha()


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
                     interrupt: bool = False) -> tuple[bool, Any]:
        return await self._srv.inject_message(
            chat_id, text, sender=sender, interrupt=interrupt)


class HedgehogServer:
    def __init__(self, config: Config):
        self.config = config
        self.token = config.load_token()
        self.store = ChatStore(config.chats_dir)
        self.mcp = McpRegistry(config.data_dir / "mcp.json")
        self.skill_sources = SkillSources(config.data_dir / "skill_sources.json")
        self.hub = Hub(self.store)
        self.sessions: dict[str, ClaudeSession | PtySession] = {}
        self.auth = AuthManager(config, self._auth_broadcast)
        # §push: notifyKey'и устройств (для APNs-пуша при оффлайн-клиенте).
        self.push_keys = push.PushKeys(config.push_keys_file)
        # Сильные ссылки на fire-and-forget задачи пуша: asyncio держит задачи
        # лишь слабо, без ссылки их может собрать GC до завершения.
        self._push_tasks: set[asyncio.Task] = set()
        # §sched: планировщик задач + блэкборд. Ставится из main.py после
        # конструктора (нужны колбэки inject/notify, замкнутые на этот сервер).
        self.scheduler = None
        # §models: фоновый рефрешер списка моделей. Событие взводится при смене
        # авторизации (и при пустом кэше) → немедленное обновление вне суток.
        self._models_refresh_now = asyncio.Event()
        self._models_task: asyncio.Task | None = None
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
        # M4: update_self в полёте — второй вызов (двойной тап/второе устройство)
        # не должен запустить 2× git reset/pip/execv. Латчится при запланированном
        # рестарте (процесс вот-вот сменится — новых обновлений не начинаем).
        self._updating = False

    # ---------- §sched: точки входа для планировщика ----------

    async def inject_message(self, chat_id: str, text: str,
                             sender: str = "cron",
                             interrupt: bool = True) -> tuple[bool, Any]:
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
        await session.handle_user_msg(text, interrupt=interrupt)
        return True, {"cold_started": not was_running, "was_busy": was_busy}

    async def _defer_failed(self, chat_id: str, job_id: str) -> None:
        """§defer S4-M3: отложенное НЕ отправлено — снимаем pending-чип
        (scheduled_cancelled, журналируемо → на всех устройствах и на resume,
        иначе висел бы вечно) и сообщаем пользователю (не теряем молча)."""
        await self.hub.publish(chat_id, "scheduled_cancelled", {"jobId": job_id})
        await self.notify_chat(chat_id, "Отложенное сообщение",
                               "Не удалось отправить после сброса лимита")

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
            await session.handle_user_msg(prompt, interrupt=False)
            log.info("defer.fired", chat=chat_id, job=job_id, atts=len(atts))
            # Оффлайн-курьер: устройства узнают, что отложенное ушло агенту.
            await self.notify_chat(chat_id, "Отложенное сообщение",
                                   "Отправлено агенту после сброса лимита")
        except Exception as e:  # noqa: BLE001 — отказ не должен теряться молча
            log.warning("defer.inject_error", chat=chat_id, job=job_id,
                        err=repr(e))
            if not echoed:
                await self._defer_failed(chat_id, job_id)   # + снять чип
            else:
                # чип уже снят эхом, но агенту не доставлено — хотя бы уведомим (M).
                await self.notify_chat(chat_id, "Отложенное сообщение",
                                       "Не удалось отправить после сброса лимита")
            raise   # чтобы планировщик записал error в job_runs

    async def notify_chat(self, chat_id: str, title: str, body: str) -> None:
        """Уведомление (баннер/инбокс) в чат по расписанию — журналируемый фрейм."""
        if self.store.get(chat_id) is None:
            return
        await self.hub.publish(chat_id, "notification",
                               {"title": title or "", "body": body or ""})
        self._push_offline(chat_id, title or "", body or "")

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
            task = asyncio.create_task(push.send(
                list(self.config.push_relay_urls), key, title, body, chat_id))
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
            try:
                await self._models_task
            except (asyncio.CancelledError, Exception):
                pass
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
        await self.hub.aclose()          # backpressure: догасить close-задачи шины

    # ---------- §models: фоновый рефрешер списка моделей ----------

    _MODELS_TTL = 24 * 3600      # штатный интервал обновления кэша
    _MODELS_RETRY = 120          # переспрос, если проба отложена (агент занят)
    _MODELS_MIN_INTERVAL = 60    # троттлинг: не чаще одной пробы CLI в минуту
    _OMNI_CATALOG_TTL = 300      # §omni: кэш каталога шлюза (5 мин)

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
            await self.hub.broadcast_global(make_frame("models_list", omni))
            return self._MODELS_TTL
        # Не поднимаем второй CLI-процесс во время активного хода (§models M1).
        if any(isinstance(s, ClaudeSession) and s.status == "busy"
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
                await self.hub.broadcast_global(
                    make_frame("models_list", data))
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

    def _invalidate_models_cache(self) -> None:
        """Смена авторизации: список моделей мог смениться. Гасим пробу в
        полёте (она под СТАРЫМИ кредами — иначе разослала бы стейл-список) и
        будим рефрешер на свежую пробу."""
        self._cancel_models_probe()
        self._models_refresh_now.set()

    def _reset_all_chat_models(self) -> None:
        """§models L2: смена режима авторизации → per-chat выбор модели может
        стать невалидным (напр. полный id из oauth не существует в шлюзе).
        Сбрасываем meta.model во всех чатах — пользователь выберет заново."""
        for m in self.store.list():
            if getattr(m, "model", None):
                self.store.update_meta(m.chatId, model=None)

    # ---------- HTTP-этап (§1.1) ----------

    def _process_request(self, connection: ServerConnection,
                         request: Request) -> Response | None:
        path = request.path.split("?", 1)[0]
        if path != WS_PATH:
            return connection.respond(http.HTTPStatus.NOT_FOUND, "not found\n")
        auth = request.headers.get("Authorization", "")
        if auth != f"Bearer {self.token}":
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
                "cliTypes": list(models.KNOWN_CLI_TYPES),
            }))
            async for raw in ws:
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
            self.hub.unregister(conn_id)

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

    async def _route(self, conn_id: int, frame: ClientFrame):
        ftype = frame.type
        p = frame.payload

        # --- системные ---
        if ftype == "ping":
            # §obs (time-sync): кладём серверную метку в pong. Клиент помнит
            # свой t0 и ловит t2 → offset = server_ts − (t0+t2)/2, RTT = t2−t0.
            # Так серверные ts кадров переводятся в клиентскую шкалу.
            await self.hub.send_global(
                conn_id, make_frame("pong", {"server_ts": time.time()}))
            return
        if ftype == "op_abort":
            # §netwait: прервать долгую операцию (login/omni/apikey), opId = id
            # инициировавшего фрейма. Любой клиент (для глобального login).
            await self._handle_op_abort(p.opId)
            return
        if ftype == "auth_start":
            # §netwait: single-flight — если флоу уже идёт, auth.start() лишь
            # пере-шлёт ссылку; новые таймеры ставим ТОЛЬКО на реально новый флоу.
            was_running = self.auth.running
            await self.auth.start()
            if not was_running and self.auth.running:
                self._start_login_timers(frame.id, conn_id, "start")
            return
        if ftype == "auth_code":
            if not await self.auth.submit_code(p.code):
                # Единый путь у клиента: неуспех — тоже auth_result.
                await self.hub.send_global(conn_id, make_frame(
                    "auth_result",
                    {"ok": False, "error": "no auth flow in progress"}))
                return
            # §netwait: ждём auth_result по коду (обмен кода на токен — сеть).
            self._start_login_timers(frame.id, conn_id, "code")
            return
        if ftype == "auth_apikey":
            # §altauth: активировать прямой API-ключ (заголовок x-api-key).
            async def _op_apikey():
                ok, err = await self._activate_apikey(
                    p.api_key, p.base_url, frame.id)
                return "auth_result", {"ok": ok, "error": err}
            self._spawn_tracked(
                conn_id, frame.id, "auth_apikey", _op_apikey())
            return
        if ftype == "auth_omniroute":
            # §altauth: активировать шлюз (ключ + base_url + выбранные модели).
            async def _op_omni():
                ok, err = await self._activate_omniroute(p, frame.id)
                return "auth_result", {"ok": ok, "error": err}
            self._spawn_tracked(
                conn_id, frame.id, "omni_activate", _op_omni())
            return
        if ftype == "omniroute_probe_models":
            # §omni шаг 1: каталог моделей шлюза. Ключ пуст → берём сохранённый
            # (редактирование без ввода ключа), но ТОЛЬКО на сохранённый base_url:
            # не отправляем секрет на произвольный клиентский URL (Fable SF1).
            base = (p.base_url or "").strip()
            key = (p.api_key or "").strip()
            if not key:
                auth = self.config.load_auth_config()
                if auth.get("mode") == "omniroute":
                    stored_base = auth.get("base_url", "")
                    if not base or base == stored_base:
                        base = base or stored_base
                        key = auth.get("api_key", "")
            if not base or not key:
                # §netwait L2: мгновенный отказ — op не регистрируем.
                await self.hub.send_global(conn_id, make_frame(
                    "omniroute_catalog",
                    {"ok": False, "error": "нет base_url/ключа",
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
        if ftype == "omniroute_set_key":
            # §omni: сменить только ключ активного omniroute (модели сохраняются).
            async def _op_setkey():
                ok, err = await self._set_omniroute_key(p.api_key, frame.id)
                return "omniroute_set_result", {"ok": ok, "error": err}
            self._spawn_tracked(
                conn_id, frame.id, "omni_setkey", _op_setkey())
            return
        if ftype == "omniroute_set_models":
            # §omni шаг 1: сохранить выбор моделей (без тир-лимита — режет клиент).
            ok, err = self._save_omniroute_models(p)
            if ok:
                self._reset_all_chat_models()   # выбор мог протухнуть (§models L2)
                await self._restart_claude_sessions()
                self._invalidate_models_cache()
            await self.hub.send_global(conn_id, make_frame(
                "omniroute_set_result", {"ok": ok, "error": err}))
            return
        if ftype == "logout":
            # §13: разлогин. /logout в SDK не работает (интерактивная
            # команда), поэтому удаляем сохранённый OAuth-токен и пересоздаём
            # claude-сессии. Следующий user_msg → AUTH_REQUIRED → auth-флоу.
            # M: если прямо сейчас идёт OAuth-флоу — гасим его ДО unlink, иначе он
            # дожуёт код и запишет токен уже ПОСЛЕ разлогина (broadcast ok). stop()
            # отменяет задачу флоу до удаления файла → сохранения после нет.
            if self.auth.running or self._login_op is not None:
                await self._abort_login("logged out")
            try:
                self.config.oauth_token_file.unlink(missing_ok=True)
            except OSError as e:
                log.warning("auth.logout_unlink_failed", err=str(e))
            # §altauth: разлогин сбрасывает и альт-способ (API-ключ/OmniRoute).
            self.config.clear_auth_config()
            self._reset_all_chat_models()    # §models L2: выбор мог протухнуть
            for chat_id, session in list(self.sessions.items()):
                if isinstance(session, ClaudeSession):
                    await self._stop_session(chat_id)
            self._invalidate_models_cache()   # §models: сбросить/переобновить
            log.info("auth.logout")
            return
        if ftype == "client_log":
            self._append_client_log(p.text)
            return
        if ftype == "register_push":
            # §push: запомнить notifyKey устройства (секрет отправки) — по нему
            # попросим релей отправить APNs-пуш, когда устройство будет оффлайн.
            # deviceId привязываем к соединению → знаем, какие устройства онлайн
            # (получат напрямую по WS) и каким нужен пуш (per-device маршрутизация).
            self.push_keys.remember(p.notifyKey, p.deviceId)
            self.hub.set_device(conn_id, p.deviceId)
            return
        if ftype == "update_self":
            # §15: git pull своего исходника + перезапуск. Авторизация — тем же
            # токеном, что и WS (SSH не нужен). Работает для серверов,
            # добавленных только по порту Ёжика.
            # M4: single-flight — параллельный вызов не запускает 2× git reset/
            # pip/execv (проверка+взвод атомарны: между ними нет await).
            if self._updating:
                await self.hub.send_global(conn_id, make_frame("update_result", {
                    "ok": False, "changed": False, "old": "", "new": "",
                    "message": "обновление уже идёт"}))
                return
            self._updating = True
            restarting = False
            try:
                from .. import updater
                result = await asyncio.to_thread(updater.pull_latest)
                await self.hub.send_global(conn_id, make_frame("update_result", {
                    "ok": result.ok,
                    "changed": result.changed,
                    "old": result.old,
                    "new": result.new,
                    "message": result.message,
                }))
                log.info("update.self", ok=result.ok, changed=result.changed,
                         old=result.old, new=result.new)
                if result.ok and result.changed:
                    restarting = True   # процесс сменится — флаг НЕ снимаем
                    async def _restart():
                        await asyncio.sleep(1.0)  # дать update_result долететь
                        log.info("update.restart", to=result.new)
                        try:
                            updater.restart_in_place()   # execv — не возвращается
                        except Exception as e:  # noqa: BLE001
                            # execv упал: код уже на новом SHA (повтор вернёт
                            # changed=False), но без явного лога это было бы тихим
                            # unhandled-task exc — сервер тихо остался бы на старом.
                            log.error("update.restart_failed", err=repr(e))
                            self._updating = False   # разлатчиваем — рестарт не идёт
                    asyncio.create_task(_restart())
            finally:
                if not restarting:
                    self._updating = False
            return
        if ftype in ("install_neko", "get_neko", "remove_neko"):
            # §17: Neko-браузер. Провижининг/снос — блокирующий docker I/O в
            # отдельном потоке. Авторизация — тем же токеном, что WS (без SSH).
            from .. import neko
            if ftype == "install_neko":
                result = await asyncio.to_thread(neko.provision, self.config)
            elif ftype == "remove_neko":
                result = await asyncio.to_thread(neko.teardown, self.config)
            else:
                result = await asyncio.to_thread(neko.status, self.config)
            await self.hub.send_global(conn_id, make_frame("neko_result", {
                "ok": result.ok,
                "status": result.status,
                "message": result.message,
                "https_port": result.https_port,
                "user_password": result.user_password,
                "server_ip": result.server_ip,
                "mcp_port": result.mcp_port,
                "ai_control": result.ai_control,
                "stage": result.stage,
            }))
            log.info("neko." + ftype, ok=result.ok, status=result.status)
            return
        if ftype == "install_skill":
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
                    "install_skill_result", {"ok": False, "error": str(e)}))
            except Exception as e:  # noqa: BLE001
                log.warning("skills.install_fail", url=p.url, err=repr(e))
                await self.hub.send_global(conn_id, make_frame(
                    "install_skill_result",
                    {"ok": False, "error": f"{type(e).__name__}: {e}"}))
            return
        if ftype == "set_skill_default":
            ok = self.skill_sources.set_default_for_new(p.source, p.default_for_new)
            log.info("skills.default_changed", source=p.source,
                     default_for_new=p.default_for_new, ok=ok)
            await self.hub.send_global(conn_id, make_frame(
                "skill_default_result",
                {"ok": ok, "source": p.source,
                 "default_for_new": p.default_for_new}))
            return
        if ftype == "list_chats":
            chats = []
            for m in self.store.list():
                entry = vars(m) | self._chat_status(m.chatId)
                chats.append(entry)
            await self.hub.send_global(conn_id, make_frame("chat_list", {"chats": chats}))
            return
        if ftype == "list_models":
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
        if ftype == "create_chat":
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
            cli_type = (p.cliType if p.cliType in models.KNOWN_CLI_TYPES
                        else models.DEFAULT_CLI_TYPE)
            if cli_type != p.cliType:
                log.warning("chat.clitype_unknown", requested=p.cliType,
                            fallback=cli_type)
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
            await self.hub.broadcast_global(make_frame("chat_created", vars(meta)))
            return

        # --- чат-скоупные: чат обязан существовать ---
        meta = self.store.get(frame.chatId)
        if meta is None:
            await self.hub.send_global(conn_id, make_error(
                Err.CHAT_NOT_FOUND, f"Chat {frame.chatId} does not exist",
                chat_id=frame.chatId, related=frame.id))
            return

        if ftype == "delete_chat":
            # S1-M: метим «удаляется» ДО _stop_session — окно между стопом и
            # store.delete иначе даёт гонку воскрешения (см. _ensure_session).
            self._deleting.add(frame.chatId)
            try:
                # Сессия закрывается всегда; рабочая папка (cwd) — по флагу.
                await self._stop_session(frame.chatId)
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

        if ftype == "rename_chat":
            updated = self.store.update_meta(frame.chatId, name=p.name)
            log.info("chat.renamed", chat=frame.chatId, name=p.name)
            if updated is not None:
                await self.hub.broadcast_global(
                    make_frame("chat_updated", vars(updated)))
            return

        if ftype == "set_mode":
            updated = self.store.update_meta(
                frame.chatId, permission_mode=p.permission_mode)
            # Стопаем сессию — новый режим применится при следующем user_msg.
            await self._stop_session(frame.chatId)
            log.info("chat.mode_changed", chat=frame.chatId,
                     permission_mode=p.permission_mode)
            await self.hub.broadcast_global(
                make_frame("chat_updated", vars(updated)))
            return

        if ftype == "set_model":
            # §models: пустая строка → сброс к дефолту CLI (None). Как set_mode:
            # стоп сессии → применится opts["model"] на следующем user_msg
            # (resume сохранит контекст), затем broadcast обновлённой meta.
            # N1: отсекаем непечатаемые символы (уедут в argv --model мусором).
            new_model = "".join(
                ch for ch in (p.model or "").strip() if ch.isprintable()
            ) or None
            updated = self.store.update_meta(frame.chatId, model=new_model)
            await self._stop_session(frame.chatId)
            log.info("chat.model_changed", chat=frame.chatId, model=new_model)
            await self.hub.broadcast_global(
                make_frame("chat_updated", vars(updated)))
            return

        if ftype == "schedule_message":
            # §defer: отложить сообщение до сброса лимита. fireAt клампим (не
            # доверяем клиентскому времени). Лимит «1 на чат» enforce'ит
            # планировщик под локом (DeferPendingExists).
            if self.scheduler is None:
                await self.hub.send_global(conn_id, make_error(
                    Err.INTERNAL, "scheduler unavailable",
                    chat_id=frame.chatId, related=frame.id))
                return
            now = time.time()
            fire_at = max(now + 1, min(float(p.fireAt), now + 7 * 24 * 3600))
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
                    "В этом чате уже есть отложенное сообщение (лимит 1)",
                    chat_id=frame.chatId, related=frame.id))
                return
            except Exception as e:  # noqa: BLE001
                await self.hub.send_global(conn_id, make_error(
                    Err.INTERNAL, f"schedule failed: {e}",
                    chat_id=frame.chatId, related=frame.id))
                return
            # Журналируемое событие → pending-чип восстановится на resume и
            # появится на других устройствах сразу.
            await self.hub.publish(frame.chatId, "scheduled", {
                "jobId": jid, "text": p.text, "attachments": atts,
                "fireAt": fire_at})
            log.info("defer.scheduled", chat=frame.chatId, job=jid,
                     fire_at=fire_at)
            return

        if ftype == "cancel_scheduled":
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

        if ftype == "list_scheduled":
            jobs = (await self.scheduler.list_jobs(frame.chatId)
                    if self.scheduler else [])
            pending = []
            for j in jobs:
                if j.get("action") != "inject_user" or j.get("enabled") != 1:
                    continue
                pl = {}
                try:
                    pl = json.loads(j.get("payload") or "{}")
                except ValueError:
                    pl = {}
                pending.append({
                    "jobId": j["id"],
                    "fireAt": j.get("next_run"),
                    "text": pl.get("text", ""),
                    "attachments": pl.get("attachments", []),
                })
            await self.hub.send_global(conn_id, make_frame(
                "scheduled_list", {"jobs": pending}, frame.chatId))
            return

        if ftype == "list_skills":
            # Дерево: источник (репо) → его скиллы (§skills v2). enabled —
            # ВСЕ скиллы группы во включённом наборе чата (meta.skills).
            await self.hub.send_global(conn_id, make_frame(
                "skills_response", self._skills_tree(meta), frame.chatId))
            return

        if ftype == "set_skill_group":
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
            await self._stop_session(frame.chatId)
            log.info("chat.skill_group_changed", chat=frame.chatId,
                     source=p.source, enabled=p.enabled,
                     skills=updated.skills or [])
            await self.hub.broadcast_global(
                make_frame("chat_updated", vars(updated)))
            return

        # ---------- §mcp: перезапуск агента + управление MCP ----------

        if ftype == "restart_agent":
            # Контекст жив (resume по claude_session_id) — стоп-сессия лишь
            # роняет коннект; новый MCP-набор подхватится на первом user_msg.
            await self._stop_session(frame.chatId)
            log.info("chat.agent_restarted", chat=frame.chatId)
            await self.hub.send_global(conn_id, make_frame(
                "mcp_response", self._mcp_tree(meta), frame.chatId))
            return

        if ftype == "clear_session":
            # §clear: сброс контекста — роняем сессию И забываем session_id CLI,
            # чтобы следующий user_msg стартовал СВЕЖУЮ сессию без resume.
            # Спасает «отравленный» чат (напр. залипший на 400 content-filter),
            # минуя модель. Видимая переписка чата не трогается.
            await self._stop_session(frame.chatId)
            self.store.update_meta(frame.chatId, claude_session_id=None)
            log.info("chat.context_cleared", chat=frame.chatId)
            # Подтверждаем клиенту — он покажет заметку ТОЛЬКО по этому фрейму
            # (иначе на старом Ёжике без хендлера был бы ложный «очищено»).
            await self.hub.send_global(conn_id, make_frame(
                "session_cleared", {}, frame.chatId))
            return

        if ftype == "list_mcp":
            await self.hub.send_global(conn_id, make_frame(
                "mcp_response", self._mcp_tree(meta), frame.chatId))
            return

        if ftype == "add_mcp":
            self.mcp.add(p.name, self._mcp_config(p))
            enabled = list(dict.fromkeys(list(meta.mcp or []) + [p.name]))
            updated = self.store.update_meta(frame.chatId, mcp=enabled)
            await self._stop_session(frame.chatId)  # применить новый MCP
            log.info("chat.mcp_added", chat=frame.chatId, name=p.name,
                     transport=p.transport)
            await self.hub.broadcast_global(make_frame("chat_updated", vars(updated)))
            await self.hub.send_global(conn_id, make_frame(
                "mcp_response", self._mcp_tree(updated), frame.chatId))
            return

        if ftype == "set_mcp_enabled":
            current = list(meta.mcp or [])
            if p.enabled:
                current = list(dict.fromkeys(current + [p.name]))
            else:
                current = [n for n in current if n != p.name]
            updated = self.store.update_meta(frame.chatId, mcp=current)
            await self._stop_session(frame.chatId)  # рестарт агента
            log.info("chat.mcp_enabled", chat=frame.chatId, name=p.name,
                     enabled=p.enabled)
            await self.hub.broadcast_global(make_frame("chat_updated", vars(updated)))
            await self.hub.send_global(conn_id, make_frame(
                "mcp_response", self._mcp_tree(updated), frame.chatId))
            return

        if ftype == "remove_mcp":
            self.mcp.remove(p.name)
            current = [n for n in (meta.mcp or []) if n != p.name]
            updated = self.store.update_meta(frame.chatId, mcp=current)
            await self._stop_session(frame.chatId)
            log.info("chat.mcp_removed", chat=frame.chatId, name=p.name)
            await self.hub.broadcast_global(make_frame("chat_updated", vars(updated)))
            await self.hub.send_global(conn_id, make_frame(
                "mcp_response", self._mcp_tree(updated), frame.chatId))
            return

        if ftype == "get_limits":
            # §limits: лимиты подписки из заголовков /v1/messages (usage.py).
            from .. import usage
            data = await usage.fetch_limits(self.config)
            await self.hub.send_global(conn_id, make_frame(
                "limits_result", data, frame.chatId))
            return

        if ftype == "subscribe_chat":
            self.hub.subscribe(conn_id, frame.chatId)
            log.info("chat.subscribe", conn_id=conn_id, chat_id=frame.chatId)
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
        if ftype == "unsubscribe_chat":
            self.hub.unsubscribe(conn_id, frame.chatId)
            return

        if ftype == "get_log":
            payload: dict[str, Any] = {
                "events": self.store.read_transcript_tail(frame.chatId, p.tail)}
            if self.store.transcript_limit(frame.chatId) <= 0:
                payload["disabled"] = True  # чат создан с log_kb=0
            await self.hub.send_global(conn_id, make_frame(
                "log_response", payload, frame.chatId))
            return

        if ftype == "get_status":
            await self.hub.send_global(conn_id, make_frame(
                "status_response",
                self._chat_status(frame.chatId, with_result=True),
                frame.chatId))
            return

        if ftype == "ack":
            self.store.ack(frame.chatId, p.last_seen_id)
            log.info("chat.ack", chat_id=frame.chatId,
                     last_seen=(p.last_seen_id or "")[-6:])
            return

        if ftype == "resume":
            events, full_replay = self.store.events_after(frame.chatId, p.last_seen_id)
            log.info("chat.resume", conn_id=conn_id, chat_id=frame.chatId,
                     events=len(events), full=full_replay,
                     last_seen=(p.last_seen_id or "")[-6:])
            payload: dict[str, Any] = {
                "events": events,
                "cursor": events[-1]["id"] if events else p.last_seen_id,
                "full_replay": full_replay,
            }
            if self.store.had_partial_loss(frame.chatId):
                payload["partial_loss"] = True
                self.store.clear_partial_loss(frame.chatId)
            # Прямой ответ, не через журнал — иначе resume зациклится.
            await self.hub.send_global(
                conn_id, make_frame("resume_response", payload, frame.chatId))
            return

        if ftype == "user_msg":
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
            is_btw = (isinstance(session, ClaudeSession)
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
            await session.handle_user_msg(prompt)
            return

        if ftype in ("pty_write", "pty_resize"):
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

        if ftype == "ui_event":
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
            if isinstance(session, ClaudeSession):
                await session.handle_ui_event(p.data)
            return

        if ftype == "ui_list":
            # §views: список окон чата (текущее + история закрытых) БЕЗ html —
            # клиент строит меню «переоткрыть». Ответ только спросившему.
            await self.hub.send_global(conn_id, make_frame(
                "ui_list_response",
                views_registry.summary(self.config.data_dir, frame.chatId),
                frame.chatId))
            return

        if ftype == "ui_reopen":
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

        if ftype == "ui_forget":
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

        if ftype == "ui_closed":
            # §views: пользователь закрыл ПОСТОЯННОЕ окно крестиком с телефона →
            # архивируем текущее в историю (агентский ui_close делает это же
            # серверно). Возвращаем свежий список спросившему.
            views_registry.record_close(self.config.data_dir, frame.chatId)
            await self.hub.send_global(conn_id, make_frame(
                "ui_list_response",
                views_registry.summary(self.config.data_dir, frame.chatId),
                frame.chatId))
            return

        if ftype == "ui_call":
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

        if ftype == "ui_new_blank":
            # §draw: пользователь нажал ＋ — создаём пустое белое §views-окно
            # (холст для свободного рисунка) и пушим его как обычное окно.
            blank = ("<!DOCTYPE html><html><head><meta charset='UTF-8'>"
                     "<meta name='viewport' content='width=device-width,"
                     "initial-scale=1,maximum-scale=1'></head>"
                     "<body style='margin:0;background:#ffffff;'></body></html>")
            rec = views_registry.record_open(
                self.config.data_dir, frame.chatId,
                title=p.title or "Empty canvas", html=blank,
                persistent=True, allow_external=False, kind="blank")
            await self.hub.publish(frame.chatId, "ui_request", {
                "html": blank, "title": rec.get("title", "Empty canvas"),
                "persistent": True, "allow_external": False,
                "view_id": rec.get("id", ""), "kind": "blank",
            })
            return

        if ftype == "ui_draw_apply":
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

        if ftype == "ui_draw_clear":
            # §draw: «Очистить/Стереть» — снять рисунок с view (+ удалить картинку).
            old = views_registry.clear_drawing(
                self.config.data_dir, frame.chatId, p.view_id)
            if old:
                self._delete_chat_file(frame.chatId, old)
            return

        if ftype in ("permission_response", "picker_response", "ui_response"):
            session = self.sessions.get(frame.chatId)
            resolved = False
            if isinstance(session, ClaudeSession):
                # значение ответа зависит от типа фрейма; резолв — единый (§req).
                value = (p.decision if ftype == "permission_response"
                         else p.option_id if ftype == "picker_response"
                         else p.data)
                resolved = session.resolve(p.related, value)
            if not resolved:
                await self.hub.send_global(conn_id, make_error(
                    Err.BAD_FRAME, f"no pending request {p.related}",
                    chat_id=frame.chatId, related=frame.id))
            return

        raise AssertionError(f"unrouted frame type {ftype}")  # защита от рассинхрона с protocol.py

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
            # §omni: OAuth-успех = вход по подписке → СТИРАЕМ альт-авторизацию
            # (auth.json), иначе остался бы mode=omniroute и build_auth_env/
            # list_models продолжили бы отдавать модели шлюза (баг: после входа
            # по подписке в CLI-view висели omniroute-модели). Только OAuth идёт
            # через этот колбэк — apikey/omniroute шлют auth_result напрямую.
            self.config.clear_auth_config()
            self._reset_all_chat_models()      # per-chat выбор мог быть omniroute-id
            # Новый OAuth-токен: пересоздаём claude-сессии, чтобы SDK
            # подхватил env CLAUDE_CODE_OAUTH_TOKEN на следующем user_msg.
            for chat_id, session in list(self.sessions.items()):
                if isinstance(session, ClaudeSession):
                    await self._stop_session(chat_id)
            self._invalidate_models_cache()   # §models: список мог смениться

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
        """Список MCP-серверов реестра + флаг «включён в этом чате» (meta.mcp).
        Секреты (значения заголовков/токены) наружу НЕ отдаём — только имя+тип."""
        enabled = set(meta.mcp or [])
        servers = [{**m, "enabled": m["name"] in enabled}
                   for m in self.mcp.list_meta()]
        # Имена, включённые в чате, но отсутствующие в реестре (битые/удалённые
        # руками) — показываем, чтобы их можно было выключить.
        known = {m["name"] for m in servers}
        for name in sorted(enabled - known):
            servers.append({"name": name, "type": None, "enabled": True})
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

    async def _ensure_session(self, meta: ChatMeta) -> ClaudeSession | PtySession:
        # S1-M: чат удаляется прямо сейчас — не поднимаем сессию (иначе воскресим).
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
            async def chat_error(code: str, message: str):
                await self.hub.publish(meta.chatId, "error",
                                       {"code": code, "message": message})
            mcp_servers = self.mcp.resolve(meta.mcp)
            # §AI-control: если общий браузер neko поднят — АВТО-выдаём агенту
            # браузерные инструменты (@playwright/mcp по ВЫДЕЛЕННОЙ docker-сети
            # hedgehog↔neko). Реестр и meta.mcp не трогаем: доступно всем чатам,
            # пока neko жив; применяется при (пере)старте сессии. Порт наружу не
            # публикуется — достижим только отсюда.
            from .. import neko
            if await asyncio.to_thread(neko.is_running):
                mcp_servers = {**mcp_servers, "neko_browser": {
                    "type": "http",
                    "url": f"http://{neko.CONTAINER}:{self.config.neko_mcp_port}/mcp",
                }}

            def save_session_id(sid: str | None, chat_id=meta.chatId):
                self.store.update_meta(chat_id, claude_session_id=sid)

            session = ClaudeSession(meta, publish, chat_error, self.config,
                                    mcp_servers=mcp_servers,
                                    on_auth_required=self.auth.start,
                                    on_session_id=save_session_id,
                                    on_status=self._chat_status_notifier(meta.chatId),
                                    scheduler=self.scheduler,
                                    roster=self._roster)
        else:
            session = PtySession(meta, publish, self.config)
        # M6: пока строили сессию (await neko.is_running / build_auth_env), в неё
        # мог параллельно впрыснуть cron/roster и уже поднять её — не плодим
        # второй CLI-процесс. re-check→assign без await между ними → атомарно.
        # S1-M: за время await'ов чат мог начать удаляться ИЛИ уже удалиться
        # целиком (delete пробежал и снял tombstone, пока мы висели на
        # neko.is_running) — проверяем и метку, и наличие в сторе. store.get
        # синхронный, между ним и assign нет await → атомарно.
        if meta.chatId in self._deleting or self.store.get(meta.chatId) is None:
            raise RuntimeError(f"chat {meta.chatId} is being deleted")
        existing = self.sessions.get(meta.chatId)
        if existing is not None:
            return existing
        self.sessions[meta.chatId] = session
        await session.start()
        return session

    async def _stop_session(self, chat_id: str):
        session = self.sessions.pop(chat_id, None)
        if session is not None:
            await session.stop()

    # ------------------------- §altauth: активация ----------------------------

    async def _restart_claude_sessions(self):
        """Уронить активные claude-сессии → следующий ход поднимет их с новым
        env (тем же путём, что logout). PTY-сессии не трогаем."""
        for chat_id, session in list(self.sessions.items()):
            if isinstance(session, ClaudeSession):
                await self._stop_session(chat_id)

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
            log.warning("netwait.op_failed", op=op_id, kind=kind, err=repr(e))
            await self.hub.send_global(conn_id, make_error(
                Err.INTERNAL, f"operation failed: {e}", related=op_id))
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
                async with sess.post(url, json=body, headers=headers) as r:
                    if r.status in (401, 403):
                        return False, f"ключ отклонён ({r.status})"
                    if r.status >= 500:
                        return False, f"сервер недоступен ({r.status})"
                    # читаем ограниченный кусок тела (L: не тянем в память
                    # мегабайты с чужого хоста) — первых 64 КБ хватает для класс-ции
                    raw = await r.content.read(65536)
                    text = raw.decode("utf-8", "replace")
                    if 200 <= r.status < 300:
                        if self._json_obj(text) is not None:
                            return True, None   # настоящий JSON-ответ message
                        return False, "endpoint не похож на Anthropic API (200 без JSON)"
                    if self._looks_like_api_error(text):
                        return True, None       # ключ принят, модель/запрос отвергнуты
                    return False, (f"endpoint не похож на Anthropic API "
                                   f"({r.status})")
        except (asyncio.TimeoutError, TimeoutError):
            return False, "таймаут проверки (15с)"
        except aiohttp.ClientError as e:
            return False, f"сервер недоступен: {e}"
        except Exception as e:  # noqa: BLE001 — валидация не должна ронять хендлер
            return False, f"ошибка проверки: {e}"

    async def _activate_apikey(self, api_key: str, base_url: str | None,
                               op_id: str | None = None) -> tuple[bool, str | None]:
        ok, err = await self._probe_auth(
            base_url, api_key, "claude-3-5-haiku-latest")
        self._mark_committing(op_id)   # §netwait H2: сетевая фаза прошла
        if not ok:
            return False, err
        self.config.save_auth_config({
            "mode": "apikey", "api_key": api_key, "base_url": base_url or None})
        self._reset_all_chat_models()    # §models L2: выбор мог протухнуть
        await self._restart_claude_sessions()
        self._invalidate_models_cache()   # §models: список зависит от ключа
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
            ok, err = await self._probe_auth(p.base_url, p.api_key, active)
            self._mark_committing(op_id)   # §netwait H2: сетевая фаза прошла
            if not ok:
                return False, err
            self.config.save_auth_config({
                "mode": "omniroute", "api_key": p.api_key, "base_url": p.base_url,
                "models": self._clean_omni_models(p.models),
                "active_id": active, "small_fast_id": small})
            log.info("auth.omniroute_activated", base_url=p.base_url,
                     new=True, n=len(ids), active=active)
        else:
            # Легаси-вид: 3 слота + алиас default_tier (как раньше).
            probe_model = {
                "opus": p.opus_model, "sonnet": p.sonnet_model,
            }.get(p.default_tier, p.haiku_model)
            if not probe_model:
                return False, "не заданы модели шлюза"
            ok, err = await self._probe_auth(p.base_url, p.api_key, probe_model)
            self._mark_committing(op_id)   # §netwait H2: сетевая фаза прошла
            if not ok:
                return False, err
            self.config.save_auth_config({
                "mode": "omniroute", "api_key": p.api_key, "base_url": p.base_url,
                "opus_model": p.opus_model, "sonnet_model": p.sonnet_model,
                "haiku_model": p.haiku_model,
                "default_tier": p.default_tier or "haiku"})
            log.info("auth.omniroute_activated", base_url=p.base_url,
                     new=False, default_tier=p.default_tier)
        self._reset_all_chat_models()    # §models L2: выбор мог протухнуть
        await self._restart_claude_sessions()
        self._invalidate_models_cache()   # §models: список зависит от шлюза
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
        return copy.deepcopy(data)

    def _save_omniroute_models(self, p) -> tuple[bool, str | None]:
        """§omni шаг 1: сохранить выбор моделей в активный omniroute-конфиг
        (переиспользуя api_key/base_url). Без тир-лимита."""
        auth = self.config.load_auth_config()
        if auth.get("mode") != "omniroute" or not auth.get("api_key"):
            return False, "OmniRoute не активирован"
        ids = [m.id for m in p.models]
        if not ids:
            return False, "список моделей пуст"
        idset = set(ids)
        if p.active_id not in idset:
            return False, "active_id вне списка"
        if p.small_fast_id not in idset:
            return False, "small_fast_id вне списка"
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
            return False, "OmniRoute не активирован"
        base = auth.get("base_url", "")
        # активная модель для пробы: новый вид → active_id; легаси → любой слот.
        probe = (auth.get("active_id") or auth.get("haiku_model")
                 or auth.get("sonnet_model") or auth.get("opus_model") or "")
        if not probe:
            return False, "нет модели для проверки ключа"
        ok, err = await self._probe_auth(base, api_key, probe)
        self._mark_committing(op_id)   # §netwait H2: сетевая фаза прошла
        if not ok:
            return False, err
        self.config.save_auth_config({**auth, "api_key": api_key})
        await self._restart_claude_sessions()   # новый ключ в env новой сессии
        self._invalidate_models_cache()
        log.info("omni.key_updated", base_url=base)
        return True, None

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
