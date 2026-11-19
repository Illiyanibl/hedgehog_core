"""§multi-cli: общий каркас менеджера входа в CLI через дочерний процесс
(agy_auth, codex_auth): запуск, таймаут, остановка, единый формат ошибок.
Подкласс задаёт CLI/TAG/default_argv/STDIN и реализует `_reset` и `_pump`."""

from __future__ import annotations

import asyncio
import re
from typing import Awaitable, Callable

import structlog

from ..config import Config
from . import cli_registry, secrets_redact

BroadcastFn = Callable[[str, dict], Awaitable[None]]

ANSI_RE = re.compile(r"\x1b(?:\[[0-9:;<=>?]*[ -/]*[@-~]|\][^\x07\x1b]*"
                     r"(?:\x07|\x1b\\)|[()][0-9A-B]|[a-zA-Z0-9=<>78])")
URL_RE = re.compile(r"https://\S+")


class SubprocessAuthFlow:
    CLI = ""                                   # имя CLI в cli_registry
    TAG = "auth"                               # имя задачи/логов
    STDIN = asyncio.subprocess.DEVNULL

    def __init__(self, config: Config, broadcast: BroadcastFn,
                 argv: list[str] | None = None):
        self._config = config
        self._broadcast = broadcast
        self._argv = argv
        self._task: asyncio.Task | None = None
        self._proc: asyncio.subprocess.Process | None = None
        self._tail: list[str] = []
        self._log = structlog.get_logger(f"{self.CLI}_auth")

    # --- для подклассов ---
    def default_argv(self, binary: str) -> list[str]:
        raise NotImplementedError

    def _reset(self) -> None:
        self._tail = []

    def _spawn_extra_env(self) -> dict[str, str]:
        """Доп. env процесса входа (подклассы)."""
        return {}

    async def _pump(self) -> None:
        raise NotImplementedError

    def _note(self, line: str) -> None:
        """Хвост последних строк вывода — для сообщения об ошибке."""
        if line.strip():
            self._tail.append(secrets_redact.redact(line.strip()))
            del self._tail[:-12]

    # --- общее ---
    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
            self._task = None
        await self._kill()

    async def _kill(self) -> None:
        proc, self._proc = self._proc, None
        if proc is not None and proc.returncode is None:
            try:
                proc.kill()
                await proc.wait()
            except ProcessLookupError:
                pass

    async def _fail(self, error: str) -> None:
        await self._broadcast("auth_result", {"ok": False, "error": error})

    async def _flow(self) -> None:
        self._reset()
        argv, env = self._argv, None      # свой argv (тесты) — окружение как есть
        if argv is None:
            binary = cli_registry.find_binary(self.CLI)
            if binary is None:
                return await self._fail(f"{self.CLI} CLI is not installed")
            argv = self.default_argv(binary)
            env = cli_registry.spawn_env(self.CLI, binary,
                                         self._spawn_extra_env())
        try:
            self._proc = await asyncio.create_subprocess_exec(
                *argv, stdin=self.STDIN, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT, start_new_session=True,
                env=env)
        except OSError as e:
            return await self._fail(f"failed to run {self.CLI}: {e}")
        self._log.info(f"{self.TAG}.started", pid=self._proc.pid)
        try:
            await asyncio.wait_for(self._pump(), self._config.auth_timeout)
        except asyncio.TimeoutError:
            await self._fail(f"authorization timed out after "
                             f"{int(self._config.auth_timeout)}s")
        except Exception as e:  # noqa: BLE001 — CancelledError пролетает выше
            self._log.error(f"{self.TAG}.crashed", err=repr(e))
            await self._fail(f"auth flow crashed: {e}")
        finally:
            await self._kill()
