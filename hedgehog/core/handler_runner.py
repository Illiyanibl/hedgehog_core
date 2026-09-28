"""§handlers Ф-2: исполнение «ручки» подпроцессом-на-вызов.

Контракт ручки: скрипт в cwd чата, читает JSON-аргументы из stdin, пишет
JSON-результат в stdout. Ёжик запускает его коротким подпроцессом на каждый
hedgehog.call — изоляция, таймаут-килл, свежий код без хот-релоада. Тёплый
пул к БД — это уже эскалация в контейнер (не здесь).

Интерпретатор: venv проекта (<cwd>/.venv/bin/python), иначе python3.
Безопасность: путь скрипта строго ВНУТРИ cwd чата (guard от traversal),
таймаут, кап размера ответа. Модель доверия = как у agent bash.
"""
from __future__ import annotations

import asyncio
import json
import os
import signal
from pathlib import Path

import structlog

log = structlog.get_logger("handlers")

DEFAULT_TIMEOUT = 15.0
MAX_OUTPUT = 1 * 1024 * 1024      # 1 МБ на ответ (stdout)
MAX_STDERR = 256 * 1024          # S5-M5: stderr тоже ограничен (иначе OOM спамом)


def _kill_group(proc: asyncio.subprocess.Process) -> None:
    """S5-M5: убить ВСю группу процессов ручки (внуков тоже). Ручка стартует в
    своей сессии (start_new_session), поэтому pgid == pid."""
    if proc.returncode is not None:
        return                    # L1: уже завершён/reaped — не бьём чужой pid
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            proc.kill()
        except (ProcessLookupError, OSError):
            pass


async def _read_capped(stream: asyncio.StreamReader, limit: int) -> tuple[bytes, bool]:
    """Читать поток инкрементально до limit+ (не тянем гигабайты в память как
    communicate()). Возврат (данные≤limit, truncated?)."""
    buf = bytearray()
    while True:
        chunk = await stream.read(65536)
        if not chunk:
            return bytes(buf), False
        buf += chunk
        if len(buf) > limit:
            return bytes(buf[:limit]), True


async def _drain_capped(stream: asyncio.StreamReader, limit: int) -> bytes:
    """Читать поток ДО EOF, но держать в памяти ≤limit (остальное вычитываем и
    отбрасываем). M2: для stderr — не роняем успешную ручку и не блокируем пайп
    из-за спама в stderr, но и не копим его в память."""
    buf = bytearray()
    while True:
        chunk = await stream.read(65536)
        if not chunk:
            return bytes(buf)
        if len(buf) < limit:
            buf += chunk[:limit - len(buf)]   # остальное просто дренируем


def _resolve_interpreter(cwd: Path) -> str:
    venv = cwd / ".venv" / "bin" / "python"
    return str(venv) if venv.is_file() else "python3"


def _resolve_script(cwd: Path, script: str) -> Path | None:
    """Путь скрипта строго внутри cwd чата (иначе None)."""
    try:
        cwd_r = cwd.resolve()
        p = (cwd_r / script).resolve()
    except OSError:
        return None
    if p != cwd_r and cwd_r not in p.parents:
        return None            # вышли за пределы cwd (../, symlink наружу)
    return p if p.is_file() else None


async def run(cwd: str, script: str, args: object,
              timeout: float = DEFAULT_TIMEOUT) -> dict:
    """Выполнить ручку. Возврат: {ok:True, data:<parsed>} |
    {ok:False, error:str}."""
    cwd_path = Path(cwd)
    script_path = _resolve_script(cwd_path, script)
    if script_path is None:
        return {"ok": False, "error": f"script not found or outside cwd: {script}"}
    interp = _resolve_interpreter(cwd_path)
    payload = json.dumps(args if args is not None else {}, ensure_ascii=False)
    try:
        proc = await asyncio.create_subprocess_exec(
            interp, str(script_path),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(cwd_path),
            start_new_session=True,     # S5-M5: своя группа → killpg бьёт внуков
        )
    except OSError as e:
        return {"ok": False, "error": f"failed to start handler: {e}"}

    async def _feed() -> None:
        try:
            proc.stdin.write(payload.encode())
            await proc.stdin.drain()
        except (OSError, ConnectionError):   # ручка не читает stdin → broken pipe
            pass
        finally:
            try:
                proc.stdin.close()
            except OSError:
                pass

    async def _stdout_capped():
        # stdout: при переполнении капа СРАЗУ бьём группу — ручка блокируется на
        # write в полный пайп, иначе truncation «висит» до общего таймаута; kill
        # разблокирует остальные потоки → gather завершится.
        data, trunc = await _read_capped(proc.stdout, MAX_OUTPUT)
        if trunc:
            _kill_group(proc)
        return data, trunc

    async def _drive():
        # S5-M5: stdin + stdout/stderr КОНКУРЕНТНО (иначе дедлок на полном пайпе),
        # раздельные капы, без communicate()-загрузки всего в память. stderr
        # дренируем-с-отбросом (M2: спам в stderr не роняет успешную ручку).
        _, out_res, err = await asyncio.gather(
            _feed(),
            _stdout_capped(),
            _drain_capped(proc.stderr, MAX_STDERR))
        return out_res, err

    try:
        try:
            (out, out_trunc), err = await asyncio.wait_for(
                _drive(), timeout=timeout)
        except asyncio.TimeoutError:
            _kill_group(proc)
            await proc.wait()
            log.warning("handler.timeout", script=script, timeout=timeout)
            return {"ok": False, "error": f"timeout {timeout}s"}
        if out_trunc:
            _kill_group(proc)            # ручка могла зависнуть на write в полный пайп
            await proc.wait()
            return {"ok": False, "error": f"output larger than {MAX_OUTPUT} bytes"}
        # оба потока закрылись → процесс завершается; дожинаем с грацией
        try:
            await asyncio.wait_for(proc.wait(), timeout=5)
        except asyncio.TimeoutError:
            _kill_group(proc)
            await proc.wait()
        if proc.returncode != 0:
            msg = err.decode(errors="replace").strip()[:500] or f"exit code {proc.returncode}"
            return {"ok": False, "error": msg}
        text = out.decode(errors="replace").strip()
        if not text:
            return {"ok": True, "data": None}
        try:
            return {"ok": True, "data": json.loads(text)}
        except ValueError:
            return {"ok": False, "error": "handler returned non-JSON on stdout"}
    finally:
        # M1: отмена хода / любой неожиданный выход → не оставляем осиротевшую
        # группу процессов ручки (killpg no-op, если уже завершилась) и дожинаем
        # ребёнка (shield: reap проходит даже под отменой → нет висячего транспорта).
        _kill_group(proc)
        if proc.returncode is None:
            try:
                await asyncio.shield(proc.wait())
            except BaseException:
                pass
