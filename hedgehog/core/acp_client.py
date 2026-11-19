"""§multi-cli: минимальный клиент Agent Client Protocol (JSON-RPC 2.0 по stdio).

Запускает CLI-агента подпроцессом (`agy acp`), даёт `request()` с ожиданием
ответа, `notify()`, и доставляет входящее от агента: уведомления
(`session/update`) — по порядку, входящие запросы (`session/request_permission`)
— в отдельных задачах (ответ пользователя может занять минуты и не должен
блокировать чтение потока). Без зависимостей от остального ядра.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, Awaitable, Callable

import structlog

log = structlog.get_logger("acp")

NotificationHandler = Callable[[str, dict], Awaitable[None]]
RequestHandler = Callable[[str, dict], Awaitable[Any]]


class AcpClosed(ConnectionError):
    """Подпроцесс агента завершился / труба закрыта."""


class AcpRpcError(Exception):
    """JSON-RPC error в ответе агента."""

    def __init__(self, code: int, message: str, data: Any = None):
        super().__init__(f"{code}: {message}")
        self.code, self.message, self.data = code, message, data


class AcpClient:
    def __init__(self, argv: list[str], *, cwd: str | None = None,
                 env: dict[str, str] | None = None,
                 on_notification: NotificationHandler | None = None,
                 on_request: RequestHandler | None = None,
                 stderr_tail: list[str] | None = None,
                 limit: int = 32 * 1024 * 1024):
        self._argv, self._cwd, self._env = argv, cwd, env
        self._on_notification, self._on_request = on_notification, on_request
        self._stderr_tail = stderr_tail if stderr_tail is not None else []
        self._limit = limit
        self._proc: asyncio.subprocess.Process | None = None
        self._next_id = 1
        self._pending: dict[int, asyncio.Future] = {}
        self._send_lock = asyncio.Lock()
        self._reader: asyncio.Task | None = None
        self._err_reader: asyncio.Task | None = None
        self._req_tasks: set[asyncio.Task] = set()
        self._closed = False
        self._closed_evt = asyncio.Event()    # процесс/поток закрыт (для ожидающих ход)

    # ---------- lifecycle ----------

    async def start(self) -> None:
        self._proc = await asyncio.create_subprocess_exec(
            *self._argv, stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            cwd=self._cwd, env=self._env, limit=self._limit)
        self._reader = asyncio.create_task(self._read_loop(), name="acp-read")
        self._err_reader = asyncio.create_task(self._drain_stderr(),
                                               name="acp-stderr")

    async def wait_closed(self) -> None:
        """Вернуться, когда процесс агента завершился / труба закрыта."""
        await self._closed_evt.wait()

    @property
    def alive(self) -> bool:
        return (not self._closed and self._proc is not None
                and self._proc.returncode is None)

    async def close(self) -> None:
        self._closed = True
        self._closed_evt.set()
        for t in list(self._req_tasks):
            t.cancel()
        proc = self._proc
        if proc is not None and proc.returncode is None:
            try:
                if proc.stdin is not None:
                    proc.stdin.close()
            except Exception:  # noqa: BLE001
                pass
            try:
                proc.terminate()
                await asyncio.wait_for(proc.wait(), 3)
            except (asyncio.TimeoutError, ProcessLookupError):
                try:
                    proc.kill()
                    await proc.wait()
                except ProcessLookupError:
                    pass
        for t in (self._reader, self._err_reader):
            if t is not None:
                t.cancel()
                try:
                    await t
                except (asyncio.CancelledError, Exception):
                    pass
        self._fail_pending(AcpClosed("client closed"))

    # ---------- исходящее ----------

    async def _send(self, obj: dict) -> None:
        if self._closed or self._proc is None or self._proc.stdin is None:
            raise AcpClosed("acp process is not running")
        data = (json.dumps(obj, ensure_ascii=False) + "\n").encode()
        async with self._send_lock:
            try:
                self._proc.stdin.write(data)
                await self._proc.stdin.drain()
            except (BrokenPipeError, ConnectionResetError) as e:
                raise AcpClosed(str(e)) from e

    async def request(self, method: str, params: dict | None = None,
                      timeout: float | None = None) -> Any:
        rid = self._next_id
        self._next_id += 1
        fut: asyncio.Future = asyncio.get_running_loop().create_future()
        self._pending[rid] = fut
        try:
            await self._send({"jsonrpc": "2.0", "id": rid, "method": method,
                              "params": params or {}})
            return await asyncio.wait_for(fut, timeout)
        finally:
            self._pending.pop(rid, None)

    async def notify(self, method: str, params: dict | None = None) -> None:
        msg: dict = {"jsonrpc": "2.0", "method": method}
        if params is not None:           # Codex: `initialized` — без params
            msg["params"] = params
        await self._send(msg)

    # ---------- входящее ----------

    def _fail_pending(self, exc: BaseException) -> None:
        for fut in list(self._pending.values()):
            if not fut.done():
                fut.set_exception(exc)

    async def _drain_stderr(self) -> None:
        assert self._proc is not None and self._proc.stderr is not None
        try:
            async for line in self._proc.stderr:
                self._stderr_tail.append(line.decode(errors="replace").rstrip())
                del self._stderr_tail[:-30]
        except (asyncio.CancelledError, Exception):  # noqa: BLE001
            pass

    async def _read_loop(self) -> None:
        assert self._proc is not None and self._proc.stdout is not None
        try:
            while True:
                line = await self._proc.stdout.readline()
                if not line:
                    break
                try:
                    msg = json.loads(line)
                except ValueError:
                    log.warning("acp.bad_json", line=line[:200])
                    continue
                if not isinstance(msg, dict):
                    continue
                await self._dispatch(msg)
        except asyncio.CancelledError:
            raise
        except Exception as e:  # noqa: BLE001
            log.warning("acp.reader_error", err=repr(e))
        finally:
            self._closed = True
            self._closed_evt.set()
            self._fail_pending(AcpClosed("acp stream closed"))

    async def _dispatch(self, msg: dict) -> None:
        method = msg.get("method")
        if method is not None and "id" in msg:            # запрос от агента
            task = asyncio.create_task(self._handle_request(msg))
            self._req_tasks.add(task)
            task.add_done_callback(self._req_tasks.discard)
        elif method is not None:                           # уведомление
            if self._on_notification is not None:
                try:
                    await self._on_notification(method, msg.get("params") or {})
                except asyncio.CancelledError:
                    raise
                except Exception as e:  # noqa: BLE001 — не рвём чтение потока
                    log.warning("acp.notification_failed", method=method,
                                err=repr(e))
        elif "id" in msg:                                  # ответ на наш запрос
            rid = msg["id"]
            if isinstance(rid, (list, dict)):              # нехешируемый id
                log.warning("acp.bad_response_id")
                return
            fut = self._pending.get(rid)
            if fut is None or fut.done():
                return
            err = msg.get("error")
            if err is not None:
                fut.set_exception(self._parse_error(err))
            else:
                fut.set_result(msg.get("result"))

    @staticmethod
    def _parse_error(err: Any) -> "AcpRpcError":
        """Устойчиво к кривому `error` (строка/список/нечисловой code)."""
        if not isinstance(err, dict):
            return AcpRpcError(-32000, str(err)[:500], None)
        try:
            code = int(err.get("code", -32000))
        except (TypeError, ValueError):
            code = -32000
        return AcpRpcError(code, str(err.get("message", ""))[:500],
                           err.get("data"))

    async def _handle_request(self, msg: dict) -> None:
        rid, method = msg["id"], msg["method"]
        try:
            if self._on_request is None:
                raise AcpRpcError(-32601, f"method not found: {method}")
            result = await self._on_request(method, msg.get("params") or {})
            await self._send({"jsonrpc": "2.0", "id": rid, "result": result})
        except asyncio.CancelledError:
            raise
        except AcpRpcError as e:
            await self._safe_send_error(rid, e.code, e.message)
        except AcpClosed:
            pass
        except Exception as e:  # noqa: BLE001
            log.warning("acp.request_failed", method=method, err=repr(e))
            await self._safe_send_error(rid, -32603, "internal error")

    async def _safe_send_error(self, rid: Any, code: int, message: str) -> None:
        try:
            await self._send({"jsonrpc": "2.0", "id": rid,
                              "error": {"code": code, "message": message}})
        except AcpClosed:
            pass
