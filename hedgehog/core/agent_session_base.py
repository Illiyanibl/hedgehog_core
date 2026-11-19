"""§multi-cli: общая база сессий агентов, работающих через внешний процесс по
JSON-RPC (Antigravity — ACP, Codex — app-server). Всё, что не зависит от
протокола конкретного CLI: очередь user_msg, воркер «один ход за раз»,
прерывание, round-trip запросов к клиенту (permission/picker/ui), перенос
очереди при set_cli, статус busy/idle, stdio-мост встроенных MCP-тулов Ёжика.

Подкласс задаёт: CLI_TYPE, `_ensure_client()`, `_turn()` и `_classify_error()`.
"""

from __future__ import annotations

import asyncio
import secrets
import sys
from pathlib import Path
from typing import Any

import structlog

from ..config import Config
from ..ids import new_ulid
from ..protocol import Err
from ..store.chats import ChatMeta
from . import cli_install, cli_registry, ctl_server, secrets_redact
from .acp_client import AcpClient
from .hedgehog_mcp import BUILTIN_MCP_NAME, build_hedgehog_mcp
from .permissions import Decision, PermissionPolicy, ToolRequest
from .session_base import PublishFn, SessionClosed
from .tool_host import HedgehogToolHost

log = structlog.get_logger("agent_session")

BUILTIN_SERVERS = (BUILTIN_MCP_NAME,)
MCP_BRIDGE = str(Path(__file__).resolve().parent / "mcp_bridge.py")


class AgentSessionBase(HedgehogToolHost):
    CLI_TYPE = ""
    # сколько ждём реакции CLI на отмену/interrupt, прежде чем бросить процесс
    INTERRUPT_TIMEOUT = 15.0

    def __init__(self, meta: ChatMeta, publish: PublishFn, send_chat_error,
                 config: Config, *, argv: list[str] | None = None,
                 env: dict[str, str] | None = None,
                 mcp_servers: dict[str, dict] | None = None,
                 on_auth_required=None, on_session_id=None, on_status=None,
                 scheduler=None, roster=None):
        self.meta = meta
        # Опоры встроенных MCP-тулов (core/hedgehog_mcp.py, как у ClaudeSession).
        self._scheduler = scheduler
        self._roster = roster
        self._cc_sends: list[float] = []
        self._neko_proxy = None
        self._ctl_tools: dict = {}
        self._ctl_meta: dict = {}
        self._ctl_token: str | None = None
        self._publish = publish
        self._send_chat_error = send_chat_error
        self._config = config
        self._argv = argv
        self._env = env
        self._mcp_servers = mcp_servers or {}
        self._on_auth_required = on_auth_required
        self._on_session_id = on_session_id
        self._on_status = on_status
        self._client: Any = None
        self._session_id: str | None = None
        self._queue: asyncio.Queue = asyncio.Queue()
        self._worker: asyncio.Task | None = None
        # H1: задачи хука on_auth_required (сильные ссылки до завершения)
        self._auth_hook_tasks: set[asyncio.Task] = set()
        self._busy = False
        self._last_status = "idle"
        self._interrupt_evt = asyncio.Event()
        self._stderr_tail: list[str] = []
        self._mcp_grants: dict[str, int] = {}   # разрешённые через ACP MCP-вызовы
        self._mcp_proxies: dict[str, Any] = {}  # server -> McpProxy (пользовательские)
        self._pending: dict[str, asyncio.Future] = {}
        self._early_answers: dict[str, str] = {}
        self._policy = PermissionPolicy(lambda: self.meta.permission_mode,
                                        meta.cwd)
        self._agent_msg_id = new_ulid()
        self._turn_text: list[str] = []
        self._stream_red = secrets_redact.StreamRedactor()   # дельты ACP/Codex
        self._stream_red_id = self._agent_msg_id
        self._seen_tools: set[str] = set()
        self._done_tools: set[str] = set()
        build_hedgehog_mcp(self)         # наполняет _ctl_tools/_ctl_meta (мост)

    async def _emit_delta(self, text: str, msg_id: str) -> None:
        """text_delta через потоковую редакцию (ключ на границе чанков не утечёт)."""
        if msg_id != self._stream_red_id:          # новое сообщение — хвост прошлого уходит к нему
            await self._flush_delta()
        self._stream_red_id = msg_id
        out = self._stream_red.feed(text)
        if out:
            await self._publish("text_delta", {"delta": out, "agent_msg_id": msg_id})

    async def _flush_delta(self) -> None:
        out = self._stream_red.flush()
        if out:
            await self._publish("text_delta", {
                "delta": out, "agent_msg_id": self._stream_red_id})

    # ---------- подкласс ----------

    def _spawn_extra_env(self) -> dict[str, str]:
        """Доп. переменные окружения процесса CLI (подклассы переопределяют)."""
        return {}

    def _server_args(self) -> tuple[str, ...]:
        """Аргументы CLI после бинаря (подклассы дополняют в альт-режимах)."""
        return self.SERVER_ARGS

    SERVER_ARGS: tuple[str, ...] = ()      # argv после бинаря CLI (acp / app-server)

    async def _ensure_client(self):
        """Шаблон: живой клиент → он же; иначе процесс + `_open_session`
        (initialize/resume/new). При сбое открытия процесс закрывается."""
        tag = self.CLI_TYPE
        if self._client is not None and not self._client.alive:
            log.warning(f"{tag}.client_dead_reset", chat=self.meta.chatId)
            await self._drop_client()
        if self._client is not None:
            return self._client
        argv, env = self._argv, self._env
        if argv is None:
            # §cli-pins: CLI ставится фоном (set_cli на неустановленный) —
            # ход ждёт установку здесь, в воркере сессии: очередь сообщений
            # сохраняется, цикл кадров соединения не блокируется.
            await cli_install.wait_pending(self.CLI_TYPE)
            binary = cli_registry.find_binary(self.CLI_TYPE)
            if binary is None:
                raise cli_registry.CliUnavailable(f"{tag} binary not found")
            argv = [binary, *self._server_args()]
            if env is None:
                env = cli_registry.spawn_env(self.CLI_TYPE, binary,
                                             self._spawn_extra_env())
        self._stderr_tail.clear()
        client = AcpClient(argv, cwd=self.meta.cwd, env=env,
                           on_notification=self._on_notification,
                           on_request=self._on_request,
                           stderr_tail=self._stderr_tail)
        await client.start()
        try:
            await self._open_session(client)
        except BaseException:
            await client.close()
            raise
        self._client = client
        return client

    async def _open_session(self, client) -> None:
        raise NotImplementedError

    async def _turn(self, prompt: str) -> tuple[str, bool]:
        raise NotImplementedError

    def _classify_error(self, text: str) -> tuple[str, str]:
        return Err.AGENT_CRASH, f"{self.CLI_TYPE} failed: {text[:300]}"

    # ---------- контракт AgentSession ----------

    async def start(self) -> None:
        if self._worker is not None and self._worker.done():
            self._worker = None
        if self._worker is None:
            self._worker = asyncio.create_task(
                self._run(), name=f"{self.CLI_TYPE}:{self.meta.chatId}")

    async def stop(self) -> None:
        worker, self._worker = self._worker, None
        # H1: stop() из собственного воркера (через хук/колбэк) — await самого
        # себя повис бы; чистим ресурсы и отменяем воркер в самом конце.
        own = worker is not None and worker is asyncio.current_task()
        if worker is not None and not own:
            worker.cancel()
            try:
                await worker
            except (asyncio.CancelledError, Exception):
                pass
        try:
            await self._stop_resources()
        finally:
            if own:
                worker.cancel()

    async def _stop_resources(self) -> None:
        # LOW-2: незавершённый хук on_auth_required после stop не должен
        # стартовать вход. Текущую задачу (stop() вызван из самого хука) не
        # трогаем — иначе хук отменил бы сам себя посреди работы.
        cur = asyncio.current_task()
        for t in list(self._auth_hook_tasks):
            if t is not cur and not t.done():
                t.cancel()
        await self._drop_client()
        if self._neko_proxy is not None:
            await self._neko_proxy.aclose()
            self._neko_proxy = None
        for proxy in self._mcp_proxies.values():
            await proxy.aclose()
        self._mcp_proxies.clear()
        ctl_server.unregister(self._ctl_token)
        self._ctl_token = None
        for fut in self._pending.values():
            if not fut.done():
                fut.cancel()
        self._pending.clear()

    async def handle_user_msg(self, content: str, interrupt: bool = True,
                              on_result=None) -> bool:
        if self._intake_closed:
            raise SessionClosed(f"{self.CLI_TYPE} session is closed")
        await self.start()
        await self._queue.put((content, on_result))
        if interrupt and self._busy:
            self._interrupt_evt.set()
        await self._emit_status()
        return False

    def resolve(self, related: str, value: str) -> bool:
        fut = self._pending.pop(related, None)
        if fut is None:
            if len(self._early_answers) > 256:
                self._early_answers.clear()
            self._early_answers[related] = value
            return True
        if not fut.done():
            fut.set_result(value)
        return True

    @property
    def status(self) -> str:
        return "busy" if self._busy or not self._queue.empty() else "idle"

    async def _emit_status(self) -> None:
        s = self.status
        if s == self._last_status:
            return
        self._last_status = s
        if self._on_status is not None:
            try:
                await self._on_status(s)
            except Exception as e:  # noqa: BLE001
                log.warning("agent.status_failed", chat=self.meta.chatId,
                            cli=self.CLI_TYPE, err=repr(e))

    # ---------- round-trip к клиенту (permission_request и т.п.) ----------

    async def request(self, frame_type: str, payload: dict[str, Any], *,
                      timeout: float | None = None) -> str:
        frame = await self._publish(frame_type, payload)
        return await self._wait_answer(frame["id"], timeout=timeout)

    async def _wait_answer(self, related: str, *,
                           timeout: float | None = None) -> str:
        early = self._early_answers.pop(related, None)
        if early is not None:
            return early
        fut: asyncio.Future = asyncio.get_running_loop().create_future()
        self._pending[related] = fut
        to = timeout if timeout is not None else self._config.permission_timeout
        try:
            return await asyncio.wait_for(fut, timeout=to)
        finally:
            self._pending.pop(related, None)

    # ---------- процесс CLI ----------

    def _servers(self) -> list[str]:
        return list(self._mcp_servers) + list(BUILTIN_SERVERS)

    async def _drop_client(self) -> None:
        client, self._client = self._client, None
        if client is not None:
            await client.close()

    def _bridge_env(self) -> dict[str, str]:
        """Окружение stdio-моста к встроенным тулам Ёжика (§ctl): сокет и
        per-session токен; регистрирует сессию в ctl_server."""
        if self._ctl_token is None:
            self._ctl_token = secrets.token_urlsafe(18)
        ctl_server.register(self._ctl_token, self)
        return {"HEDGEHOG_CTL_SOCK": str(self._config.data_dir / "ctl.sock"),
                "HEDGEHOG_CTL_TOKEN": self._ctl_token,
                "HEDGEHOG_CTL_TIMEOUT": str(int(self._config.ui_timeout + 120))}

    def _bridge_entry(self, server: str | None = None) -> dict:
        """mcpServers-запись моста в формате ACP (список name/value для env).
        server — проксируемый через ctl_server сервер (neko_browser), иначе
        встроенный hedgehog."""
        env = self._bridge_env()
        return {"name": server or BUILTIN_MCP_NAME, "command": sys.executable,
                "args": [MCP_BRIDGE, *(["--server", server] if server else [])],
                "env": [{"name": k, "value": v} for k, v in env.items()]}

    def ensure_mcp_proxy(self, server: str):
        """Прокси Ёжика к MCP-серверу этой сессии (лениво; None — сервера нет или
        он не http/sse/stdio). Через него CLI без собственного гейта (§H1)
        вызывает сервер только после проверки прав в ctl_server."""
        if server == "neko_browser":
            return self.ensure_neko_proxy()
        proxy = self._mcp_proxies.get(server)
        if proxy is None:
            cfg = self._mcp_servers.get(server)
            if isinstance(cfg, dict) and (cfg.get("url") or cfg.get("command")):
                try:
                    from .mcp_proxy import McpProxy
                    proxy = self._mcp_proxies[server] = McpProxy(cfg, server)
                except Exception as e:  # noqa: BLE001 — нет пакета mcp и т.п.
                    log.warning("mcp.proxy_unavailable", server=server, err=repr(e))
        return proxy

    def ensure_neko_proxy(self):
        """Прокси к neko-браузеру этой сессии (создаётся лениво; None — neko нет)."""
        if self._neko_proxy is None:
            cfg = self._mcp_servers.get("neko_browser")
            if isinstance(cfg, dict) and cfg.get("url"):
                try:
                    from .neko_proxy import NekoProxy
                    self._neko_proxy = NekoProxy(cfg["url"])
                except Exception as e:  # noqa: BLE001 — нет пакета mcp и т.п.
                    log.warning("neko.proxy_unavailable", err=repr(e))
        return self._neko_proxy

    def _state(self) -> dict:
        """Запись cliSessions активного типа CLI (initialized/session_id/model/effort)."""
        return self.meta.cliSessions.get(self.CLI_TYPE) or {}

    def _saved_session_id(self) -> str | None:
        return (self.meta.cliSessions.get(self.CLI_TYPE) or {}).get("session_id")

    # ---------- воркер и ход ----------

    async def _run(self) -> None:
        while True:
            prompt, on_result = await self._queue.get()
            self._busy = True
            reply_text, reply_ok = "", False
            try:
                reply_text, reply_ok = await self._turn(prompt)
            except asyncio.CancelledError:
                on_result = None
                raise
            except Exception as e:  # noqa: BLE001
                await self._handle_turn_error(e)
            finally:
                self._busy = False
                try:
                    await self._emit_status()
                except asyncio.CancelledError:
                    raise
                except Exception:  # noqa: BLE001
                    pass
                if on_result is not None:
                    try:
                        await on_result(reply_text, reply_ok)
                    except asyncio.CancelledError:
                        raise
                    except Exception as e5:  # noqa: BLE001
                        log.warning("reply.on_result_failed",
                                    chat=self.meta.chatId, err=repr(e5))

    async def _decide(self, req: ToolRequest) -> str:
        """allow | allow_always | deny | cancel — через политику Ёжика
        (общий путь для всех не-Claude CLI)."""
        decision = self._policy.decide(req)
        if decision is Decision.ALLOW:
            return "allow"
        if decision is Decision.DENY:
            return "deny"
        try:
            answer = await self.request("permission_request", {
                "tool": req.name, "input": req.input or {}})
        except asyncio.TimeoutError:
            await self._send_chat_error(
                Err.PERMISSION_TIMEOUT,
                f"No user response for {req.name} within "
                f"{int(self._config.permission_timeout)}s")
            return "cancel"
        log.info("permission.decision", chat=self.meta.chatId, tool=req.name,
                 decision=answer)
        if answer == "allow_always":
            self._policy.always_allowed.add(req.name)
            return "allow_always"
        return "allow" if answer == "allow" else "deny"

    # CLI, который НЕ спрашивает разрешение на MCP-тулы Ёжика сам (Antigravity):
    # ctl_server гейтит вызов через политику. У Codex гейт — elicitation, у
    # Claude — can_use_tool, поэтому там False (иначе двойной запрос).
    CTL_GATE = False

    async def ctl_gate(self, tool: str, args: dict,
                       server: str = BUILTIN_MCP_NAME) -> bool:
        """Разрешён ли вызов инструмента MCP-сервера, обслуживаемого ctl_server
        (встроенный hedgehog или проксируемый neko_browser)."""
        if not self.CTL_GATE:
            return True
        name = f"mcp__{server}__{tool}"
        if self._mcp_grants.get(name, 0) > 0:
            # CLI уже спросил про этот вызов сам (ACP request_permission) и
            # получил «да» — не переспрашиваем пользователя второй раз
            self._mcp_grants[name] -= 1
            return True
        ans = await self._decide(ToolRequest(
            name=name, kind="other",
            input=args if isinstance(args, dict) else {}))
        return ans in ("allow", "allow_always")

    def _fire_auth_required(self) -> None:
        """H1: хук on_auth_required — отдельной задачей, НЕ await'ом из воркера:
        хук может остановить/перезапустить сессии CLI (в т.ч. эту), а stop()
        не должен исполняться внутри собственного воркера."""
        if self._on_auth_required is None:
            return
        # LOW-3: дедуп — N 401 подряд, пока хук ещё в работе, = один вызов.
        if any(not t.done() for t in self._auth_hook_tasks):
            return
        task = asyncio.create_task(self._on_auth_required(),
                                   name=f"{self.CLI_TYPE}-auth-hook:{self.meta.chatId}")
        self._auth_hook_tasks.add(task)
        task.add_done_callback(self._auth_hook_done)

    def _auth_hook_done(self, task: asyncio.Task) -> None:
        self._auth_hook_tasks.discard(task)
        if task.cancelled():
            return
        exc = task.exception()
        if exc is not None:
            log.error("agent.auth_hook_failed", chat=self.meta.chatId,
                      cli=self.CLI_TYPE,
                      err=secrets_redact.redact(repr(exc)))

    async def _handle_turn_error(self, e: Exception) -> None:
        tail = " ".join(self._stderr_tail[-5:])
        text = secrets_redact.redact(f"{e} {tail}".strip())
        if isinstance(e, cli_registry.CliUnavailable):
            code, message = Err.CLI_UNAVAILABLE, f"{self.CLI_TYPE} CLI is not installed"
        else:
            code, message = self._classify_error(text)
        log.warning("agent.turn_error", chat=self.meta.chatId,
                    cli=self.CLI_TYPE, code=code, err=text[-300:])
        try:
            await self._send_chat_error(code, message)
            if code == Err.AUTH_REQUIRED:
                self._fire_auth_required()
        except asyncio.CancelledError:
            raise
        except Exception as e2:  # noqa: BLE001
            log.error("agent.error_handler_failed", chat=self.meta.chatId,
                      err=repr(e2))
        finally:
            await self._drop_client()       # свежий процесс на следующий ход
