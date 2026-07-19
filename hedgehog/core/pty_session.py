"""PtySession — bash в PTY, вывод → ScreenGrid → screen_snapshot.

Pipeline (docs/broker-audit.md, «ScreenGrid как PTY-to-plain-text труба»):
    bash PTY → feed() → grid → render_plain() → WS {type:"screen_snapshot"}

Снапшоты агрегируются: при бурном выводе клиент получает не каждый чанк,
а состояние экрана раз в snapshot_interval (паттерн _maybe_flush_overflow
из broker.py — инцидент 74 GiB, 2026-05-06). Параллельно сырые байты
пишутся в plain-text транскрипт HistoryWriter'ом.

Auto-suspend из broker'а (SIGSTOP без клиентов) в Phase 1a не переносим:
на тестовом стенде одна сессия, экономить нечего. Отметка в HISTORY.md.
"""

from __future__ import annotations

import asyncio
import fcntl
import os
import signal
import struct
import termios
from pathlib import Path

import structlog

from ..adapters.screen_grid import ScreenGrid
from ..config import Config
from ..store.chats import ChatMeta
from ..store.history import HistoryWriter
from .session_base import PublishFn

log = structlog.get_logger("pty_session")

_READ_CHUNK = 65536


class PtySession:
    def __init__(self, meta: ChatMeta, publish: PublishFn, config: Config):
        self.meta = meta
        self._publish = publish
        self._config = config

        self._grid = ScreenGrid(rows=24, cols=80)
        self._history: HistoryWriter | None = None
        self._master_fd: int | None = None
        self._proc: asyncio.subprocess.Process | None = None
        self._dirty = asyncio.Event()
        self._flusher: asyncio.Task | None = None
        self._eof = False

    # ---------- lifecycle ----------

    async def start(self):
        if self._proc is not None:
            return
        self._history = HistoryWriter(Path(self.meta.cwd) / "transcript.log")

        master, slave = os.openpty()
        self._master_fd = master
        os.set_blocking(master, False)
        self._set_winsize(24, 80)

        env = dict(os.environ)
        env["TERM"] = "xterm-256color"

        def _child_setup():
            # Новая сессия + PTY становится controlling terminal: иначе
            # ^C (0x03 в pty_write) не доставит SIGINT foreground-группе.
            os.setsid()
            fcntl.ioctl(0, termios.TIOCSCTTY, 0)

        self._proc = await asyncio.create_subprocess_exec(
            "bash", "-i",
            stdin=slave, stdout=slave, stderr=slave,
            cwd=self.meta.cwd, env=env,
            preexec_fn=_child_setup,
        )
        os.close(slave)

        loop = asyncio.get_running_loop()
        loop.add_reader(master, self._on_readable)
        self._flusher = asyncio.create_task(
            self._flush_loop(), name=f"pty-flush:{self.meta.chatId}")
        log.info("pty.started", chat=self.meta.chatId, pid=self._proc.pid)

    async def stop(self):
        if self._flusher:
            self._flusher.cancel()
            try:
                await self._flusher
            except (asyncio.CancelledError, Exception):
                pass
            self._flusher = None
        self._detach_reader()
        if self._proc is not None and self._proc.returncode is None:
            try:
                os.killpg(self._proc.pid, signal.SIGHUP)
            except (ProcessLookupError, PermissionError):
                pass
            try:
                await asyncio.wait_for(self._proc.wait(), timeout=3)
            except asyncio.TimeoutError:
                try:
                    os.killpg(self._proc.pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
        self._proc = None
        if self._master_fd is not None:
            try:
                os.close(self._master_fd)
            except OSError:
                pass
            self._master_fd = None
        if self._history:
            self._history.close()  # добивает carry даже при аварии (broker §5)
            self._history = None
        log.info("pty.stopped", chat=self.meta.chatId)

    # ---------- входящие фреймы ----------

    async def handle_user_msg(self, content: str):
        """user_msg в shell-чате = команда + Enter."""
        await self.write(content + "\n")

    async def write(self, data: str):
        if self._eof:
            # bash умер (exit/kill) — следующий ввод лениво поднимает свежий.
            await self._restart()
        await self.start()
        if self._master_fd is None:
            return
        try:
            os.write(self._master_fd, data.encode())
        except OSError as e:
            log.warning("pty.write_failed", chat=self.meta.chatId, err=str(e))

    async def _restart(self):
        log.info("pty.restart", chat=self.meta.chatId)
        rows, cols = self._grid.rows, self._grid.cols
        await self.stop()
        self._eof = False
        self._grid = ScreenGrid(rows=rows, cols=cols)  # чистый экран

    async def resize(self, rows: int, cols: int):
        await self.start()
        self._grid.resize(rows, cols)
        self._set_winsize(rows, cols)
        self._dirty.set()

    # ---------- PTY → grid ----------

    def _on_readable(self):
        try:
            data = os.read(self._master_fd, _READ_CHUNK)
        except BlockingIOError:
            return
        except OSError:
            data = b""
        if not data:
            # EOF: bash умер (exit / kill). Последний снапшот и отцепляемся.
            self._detach_reader()
            self._eof = True
            self._dirty.set()
            return
        self._grid.feed(data)
        if self._history:
            self._history.write(data)
        self._dirty.set()

    def _detach_reader(self):
        if self._master_fd is not None:
            try:
                asyncio.get_running_loop().remove_reader(self._master_fd)
            except (RuntimeError, OSError):
                pass

    async def _flush_loop(self):
        """Агрегатор: не чаще одного screen_snapshot в snapshot_interval."""
        while True:
            await self._dirty.wait()
            await asyncio.sleep(self._config.snapshot_interval)
            self._dirty.clear()
            await self._publish("screen_snapshot", {
                "text": self._grid.render_plain(),
                "cursor_row": self._grid.cursor_row,
                "cursor_col": self._grid.cursor_col,
            })
            if self._eof:
                await self._publish("text_delta", {
                    "delta": "[shell exited]",
                    "agent_msg_id": "",
                })
                return

    def _set_winsize(self, rows: int, cols: int):
        if self._master_fd is None:
            return
        try:
            fcntl.ioctl(self._master_fd, termios.TIOCSWINSZ,
                        struct.pack("HHHH", rows, cols, 0, 0))
        except OSError:
            pass
