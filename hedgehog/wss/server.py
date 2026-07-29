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
import http
from typing import Any

import structlog
import websockets
from websockets.asyncio.server import Request, Response, ServerConnection, serve

from ..bus.hub import Hub
from ..config import Config
from ..core.auth import AuthManager
from ..core.claude_session import ClaudeSession
from ..core.pty_session import PtySession
from ..protocol import (
    BadFrame,
    ClientFrame,
    Err,
    dumps,
    make_error,
    make_frame,
    parse_client_frame,
)
from ..store.chats import ChatMeta, ChatStore
from ..store.mcp_registry import McpRegistry
from ..store import skills_registry
from ..store.skill_sources import SkillSources, SkillInstallError
from .. import fileserver
from .. import authlog

log = structlog.get_logger("wss")

WS_PATH = "/v1/connect"


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

    # ---------- запуск ----------

    async def serve_forever(self):
        async with serve(
            self._handler,
            self.config.host,
            self.config.port,
            process_request=self._process_request,
            max_size=4 * 1024 * 1024,
        ):
            log.info("server.listening", host=self.config.host,
                     port=self.config.port, path=WS_PATH)
            await asyncio.get_running_loop().create_future()  # до отмены

    async def shutdown(self):
        await self.auth.stop()
        for session in list(self.sessions.values()):
            await session.stop()
        self.sessions.clear()

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

        conn_id = self.hub.register(send)
        try:
            await self.hub.send_global(conn_id, make_frame("hello", {
                "server_version": self.config.server_version,
                "supported_v": list(self.config.protocol_versions),
                "capabilities": list(self.config.capabilities),
            }))
            async for raw in ws:
                await self._dispatch(conn_id, raw)
        except websockets.ConnectionClosed:
            pass
        finally:
            self.hub.unregister(conn_id)

    # ---------- диспетчер ----------

    async def _dispatch(self, conn_id: int, raw: str | bytes):
        try:
            frame = parse_client_frame(raw)
        except BadFrame as e:
            # Диагностика рассинхрона версий: старый клиент шлёт снятые типы
            # (напр. set_skills) → тут видно, что именно прилетело.
            log.warning("frame.bad", err=str(e), raw=str(raw)[:200])
            await self.hub.send_global(conn_id, make_error(Err.BAD_FRAME, str(e)))
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
            await self.hub.send_global(conn_id, make_frame("pong", {}))
            return
        if ftype == "auth_start":
            await self.auth.start()
            return
        if ftype == "auth_code":
            if not await self.auth.submit_code(p.code):
                # Единый путь у клиента: неуспех — тоже auth_result.
                await self.hub.send_global(conn_id, make_frame(
                    "auth_result",
                    {"ok": False, "error": "no auth flow in progress"}))
            return
        if ftype == "logout":
            # §13: разлогин. /logout в SDK не работает (интерактивная
            # команда), поэтому удаляем сохранённый OAuth-токен и пересоздаём
            # claude-сессии. Следующий user_msg → AUTH_REQUIRED → auth-флоу.
            try:
                self.config.oauth_token_file.unlink(missing_ok=True)
            except OSError as e:
                log.warning("auth.logout_unlink_failed", err=str(e))
            for chat_id, session in list(self.sessions.items()):
                if isinstance(session, ClaudeSession):
                    await self._stop_session(chat_id)
            log.info("auth.logout")
            return
        if ftype == "client_log":
            self._append_client_log(p.text)
            return
        if ftype == "update_self":
            # §15: git pull своего исходника + перезапуск. Авторизация — тем же
            # токеном, что и WS (SSH не нужен). Работает для серверов,
            # добавленных только по порту Ёжика.
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
                async def _restart():
                    await asyncio.sleep(1.0)  # дать update_result долететь
                    log.info("update.restart", to=result.new)
                    updater.restart_in_place()
                asyncio.create_task(_restart())
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
            meta = self.store.create(
                p.name, p.addressee, p.cwd,
                mcp=p.mcp, permission_mode=p.permission_mode,
                log_kb=p.log_kb, skills=seed_skills,
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
            # Сессия закрывается всегда; рабочая папка (cwd) — по флагу.
            await self._stop_session(frame.chatId)
            self.store.delete(frame.chatId, delete_cwd=p.delete_cwd,
                              projects_base=self.config.default_cwd)
            log.info("chat.deleted", chat=frame.chatId, delete_cwd=p.delete_cwd)
            await self.hub.broadcast_global(
                make_frame("chat_deleted", {"chatId": frame.chatId}))
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
            # Для shell-чата поднимаем bash сразу — клиент увидит prompt.
            if meta.addressee == "broker_shell":
                await self._ensure_session(meta)
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
            return

        if ftype == "resume":
            events, full_replay = self.store.events_after(frame.chatId, p.last_seen_id)
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
            # Эхо (§4.15): в чат пишут несколько писателей (устройства
            # пользователя, менеджер-агент, cron) — журналим и рассылаем
            # входящее ДО исполнения, чтобы все клиенты видели полную ленту.
            # Вложения (§7.3): эхо несёт их для чипов в ленте; агенту в промпт
            # дописываем абсолютные пути (Claude читает их Read'ом). Без
            # вложений поведение идентично прежнему.
            session = await self._ensure_session(meta)
            # /btw: очередь не пуста (сессия занята) → сообщение вольётся в
            # текущий ход, а не встанет новым. Помечаем эхо флагом btw, чтобы
            # все клиенты показали реплику как «дослано».
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

        if ftype in ("permission_response", "picker_response"):
            session = self.sessions.get(frame.chatId)
            resolved = False
            if isinstance(session, ClaudeSession):
                if ftype == "permission_response":
                    resolved = session.resolve_permission(p.related, p.decision)
                else:
                    resolved = session.resolve_picker(p.related, p.option_id)
            if not resolved:
                await self.hub.send_global(conn_id, make_error(
                    Err.BAD_FRAME, f"no pending request {p.related}",
                    chat_id=frame.chatId, related=frame.id))
            return

        raise AssertionError(f"unrouted frame type {ftype}")  # защита от рассинхрона с protocol.py

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
        await self.hub.broadcast_global(make_frame(ftype, payload))
        if ftype == "auth_result" and payload.get("ok"):
            # Новый OAuth-токен: пересоздаём claude-сессии, чтобы SDK
            # подхватил env CLAUDE_CODE_OAUTH_TOKEN на следующем user_msg.
            for chat_id, session in list(self.sessions.items()):
                if isinstance(session, ClaudeSession):
                    await self._stop_session(chat_id)

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
            await self.hub.broadcast_global(make_frame(
                "chat_status", {"chatId": chat_id, "status": status}))
            # TODO(push): триггер push-уведомления на переходе busy→idle.
        return notify

    # ---------- сессии ----------

    async def _ensure_session(self, meta: ChatMeta) -> ClaudeSession | PtySession:
        session = self.sessions.get(meta.chatId)
        if session is not None:
            return session

        async def publish(ftype: str, payload: dict) -> dict:
            return await self.hub.publish(meta.chatId, ftype, payload)

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
                                    on_status=self._chat_status_notifier(meta.chatId))
        else:
            session = PtySession(meta, publish, self.config)
        self.sessions[meta.chatId] = session
        await session.start()
        return session

    async def _stop_session(self, chat_id: str):
        session = self.sessions.pop(chat_id, None)
        if session is not None:
            await session.stop()
