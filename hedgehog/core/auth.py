"""AuthManager — авторизация Claude Code на сервере из чата (§13 протокола).

`claude setup-token` — интерактивный OAuth-флоу CLI: печатает ссылку,
пользователь открывает её в браузере, авторизуется и присылает обратно
код, CLI обменивает код на долгоживущий OAuth-токен. Ёжик гоняет процесс
в PTY, вылавливает из вывода ссылку → `auth_link`, вводит код из
`auth_code`, из финального вывода забирает токен и сохраняет в
`data/oauth_token`. ClaudeSession подкладывает его SDK через env
`CLAUDE_CODE_OAUTH_TOKEN` — setup-token печатает токен для внешнего
использования, а не пишет ~/.claude/.credentials.json.

Авторизация общая на сервер → один флоу одновременно. Повторный
`auth_start` при живом флоу пере-шлёт текущую ссылку (`already_running`).
Фреймы auth_* глобальные (без chatId) и в журналы чатов не пишутся —
доезжают только до подключённых в момент отправки клиентов.

CLI рендерит вывод через ink: слова позиционируются CSI-кодами движения
курсора вместо пробелов, URL переносится по ширине терминала. Поэтому
PTY открывается широким (_PTY_COLS), а парсер терпит и ANSI-мусор, и
переносы (см. extract_oauth_url).
"""

from __future__ import annotations

import asyncio
import fcntl
import os
import re
import signal
import struct
import termios
from typing import Awaitable, Callable

import structlog

from ..adapters.screen_grid import ScreenGrid
from ..config import Config

log = structlog.get_logger("auth")

BroadcastFn = Callable[[str, dict], Awaitable[None]]

_READ_CHUNK = 65536
# Широкий PTY — чтобы OAuth-URL не заворачивался по строкам.
_PTY_ROWS, _PTY_COLS = 50, 1000

_ANSI_RE = re.compile(
    r"\x1b(?:\[[0-9;?>=]*[A-Za-z@]"      # CSI (цвет, курсор, приватные ?…h)
    r"|\][^\x07\x1b]*(?:\x07|\x1b\\)"    # OSC (заголовок окна и т.п.)
    r"|[()][0-9A-B]"                     # выбор charset
    r"|[a-zA-Z0-9=<>78])")               # одиночные ESC (save/restore cursor…)

_URL_CHARS = r"[A-Za-z0-9\-._~:/?#@!$&'()*+,;=%]"
_URL_RE = re.compile(r"https://" + _URL_CHARS + r"+")
_URL_LINE_RE = re.compile(r"^" + _URL_CHARS + r"+$")
_TOKEN_RE = re.compile(r"sk-ant-oat[0-9A-Za-z_\-]+")
# Неверный код: CLI печатает «OAuth error: … Press Enter to retry.» и ждёт.
# После Enter генерируется НОВАЯ ссылка (новый PKCE state) — старая мертва.
_OAUTH_ERR_RE = re.compile(r"OAuth error:\s*(.{0,160}?)(?:Press Enter|\n|$)")


def strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


def extract_oauth_url(raw: str) -> str | None:
    """OAuth-ссылка из сырого PTY-вывода setup-token.

    Если терминал оказался узким, URL приходит несколькими строками подряд
    (фрагменты состоят только из URL-символов) — склеиваем продолжения,
    пока строка целиком URL-ная; пустая строка или обычный текст = конец.
    """
    # CR — возврат каретки (в PTY строки кончаются \r\r\n): просто выкидываем,
    # иначе между завёрнутыми фрагментами URL появляются пустые «строки».
    text = strip_ansi(raw).replace("\r", "")
    lines = text.split("\n")
    for i, line in enumerate(lines):
        m = _URL_RE.search(line)
        if m is None:
            continue
        url = m.group(0)
        if m.end() == len(line.rstrip()):  # URL обрывается краем строки
            for cont in lines[i + 1:]:
                cont = cont.strip()
                if not cont or not _URL_LINE_RE.match(cont):
                    break
                url += cont
        return url
    return None


def extract_token(raw: bytes) -> str | None:
    """Долгоживущий OAuth-токен из PTY-потока setup-token.

    ТОЛЬКО через эмуляцию экрана (ScreenGrid): ink перерисовывает строку
    токена диффом с прыжками курсора ([NG]) поверх прошлого кадра — тупой
    ANSI-strip склеивает битый токен с пропущенными символами
    (e2e 2026-07-12). Кормить надо весь поток с начала процесса.
    """
    grid = ScreenGrid(rows=_PTY_ROWS, cols=_PTY_COLS)
    grid.feed(raw)
    matches = _TOKEN_RE.findall(grid.render_plain())
    return matches[-1] if matches else None


class AuthManager:
    def __init__(self, config: Config, broadcast: BroadcastFn):
        self._config = config
        self._broadcast = broadcast
        self._task: asyncio.Task | None = None
        self._proc: asyncio.subprocess.Process | None = None
        self._master_fd: int | None = None
        self._buf = ""         # текст для парса ссылки/ошибок
        self._raw = b""        # сырой поток целиком — для ScreenGrid (токен)
        self._url: str | None = None
        self._parse_from = 0   # ссылку ищем только в выводе после этой позиции
        self._errs_seen = 0    # сколько «OAuth error» уже отработано

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    # ---------- входящие фреймы ----------

    async def start(self):
        """auth_start (§13.1). Идемпотентен: живой флоу → повтор ссылки."""
        if self.running:
            log.info("auth.already_running")
            if self._url:
                await self._broadcast("auth_link", {
                    "url": self._url, "already_running": True})
            return
        self._task = asyncio.create_task(self._flow(), name="auth-flow")

    async def submit_code(self, code: str) -> bool:
        """auth_code (§13.3) → ввод в PTY. False, если флоу не запущен.

        Enter уходит ОТДЕЛЬНЫМ write с паузой: длинный код ink-CLI считает
        вставкой, и \\r в том же чанке становится частью «вставленного
        текста», а не отправкой — код зависает в поле ввода (e2e 2026-07-12).
        """
        if not self.running or self._master_fd is None:
            return False
        try:
            os.write(self._master_fd, code.strip().encode())
            await asyncio.sleep(0.5)
            os.write(self._master_fd, b"\r")
            log.info("auth.code_submitted")
            return True
        except OSError as e:
            log.warning("auth.code_write_failed", err=str(e))
            return False

    async def stop(self):
        """Останов при shutdown сервера (auth_result не шлём)."""
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
            self._task = None

    # ---------- флоу ----------

    async def _flow(self):
        self._buf, self._raw, self._url = "", b"", None
        self._parse_from, self._errs_seen = 0, 0
        loop = asyncio.get_running_loop()
        master, slave = os.openpty()
        self._master_fd = master
        os.set_blocking(master, False)
        fcntl.ioctl(master, termios.TIOCSWINSZ,
                    struct.pack("HHHH", _PTY_ROWS, _PTY_COLS, 0, 0))
        env = dict(os.environ)
        env["TERM"] = "xterm-256color"
        try:
            self._proc = await asyncio.create_subprocess_exec(
                "claude", "setup-token",
                stdin=slave, stdout=slave, stderr=slave,
                env=env, preexec_fn=os.setsid,
            )
        except OSError as e:
            os.close(slave)
            await self._broadcast("auth_result", {
                "ok": False, "error": f"failed to run claude CLI: {e}"})
            self._cleanup()
            return
        os.close(slave)
        log.info("auth.started", pid=self._proc.pid,
                 timeout=self._config.auth_timeout)

        readable = asyncio.Event()
        loop.add_reader(master, readable.set)
        try:
            await asyncio.wait_for(self._pump(readable),
                                   timeout=self._config.auth_timeout)
        except asyncio.TimeoutError:
            log.warning("auth.timeout")
            await self._broadcast("auth_result", {
                "ok": False,
                "error": f"authorization timed out after "
                         f"{int(self._config.auth_timeout)}s"})
        except Exception as e:  # CancelledError (BaseException) пролетает выше
            log.error("auth.flow_crashed", err=repr(e))
            await self._broadcast("auth_result", {
                "ok": False, "error": f"auth flow crashed: {e}"})
        finally:
            try:
                loop.remove_reader(master)
            except (RuntimeError, OSError):
                pass
            self._cleanup()

    async def _pump(self, readable: asyncio.Event):
        """PTY → буфер; первая найденная ссылка → auth_link; EOF → итог."""
        eof = False
        while not eof:
            await readable.wait()
            readable.clear()
            while True:
                try:
                    data = os.read(self._master_fd, _READ_CHUNK)
                except BlockingIOError:
                    break
                except OSError:
                    data = b""
                if not data:
                    eof = True
                    break
                self._raw += data
                self._buf += data.decode("utf-8", "replace")
            if self._url is None:
                url = extract_oauth_url(self._buf[self._parse_from:])
                if url:
                    self._url = url
                    log.info("auth.link_found")
                    await self._broadcast("auth_link", {"url": url})
            # Неверный код → промежуточный auth_result {retry: true},
            # жмём Enter (CLI выдаст новую ссылку — уйдёт как auth_link).
            errs = _OAUTH_ERR_RE.findall(strip_ansi(self._buf))
            if len(errs) > self._errs_seen:
                for msg in errs[self._errs_seen:]:
                    log.warning("auth.code_rejected", err=msg.strip())
                    await self._broadcast("auth_result", {
                        "ok": False, "retry": True,
                        "error": f"код не принят: {msg.strip()}"})
                self._errs_seen = len(errs)
                self._url, self._parse_from = None, len(self._buf)
                try:
                    os.write(self._master_fd, b"\r")
                except OSError:
                    pass

        rc = await self._proc.wait()
        token = extract_token(self._raw)
        if rc == 0 and token:
            self._save_token(token)
            log.info("auth.success")
            await self._broadcast("auth_result", {"ok": True})
        else:
            tail = strip_ansi(self._buf).strip()[-400:]
            log.warning("auth.failed", rc=rc, token_found=bool(token))
            await self._broadcast("auth_result", {
                "ok": False,
                "error": f"setup-token exited rc={rc}, "
                         f"token {'found' if token else 'not found'}; "
                         f"tail: {tail}"})

    def _save_token(self, token: str):
        path = self._config.oauth_token_file
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(token + "\n")
        path.chmod(0o600)

    def _cleanup(self):
        if self._proc is not None and self._proc.returncode is None:
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
