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
from pathlib import Path

import structlog

log = structlog.get_logger("handlers")

DEFAULT_TIMEOUT = 15.0
MAX_OUTPUT = 1 * 1024 * 1024   # 1 МБ на ответ


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
        return {"ok": False, "error": f"скрипт не найден или вне cwd: {script}"}
    interp = _resolve_interpreter(cwd_path)
    payload = json.dumps(args if args is not None else {}, ensure_ascii=False)
    try:
        proc = await asyncio.create_subprocess_exec(
            interp, str(script_path),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(cwd_path),
        )
    except OSError as e:
        return {"ok": False, "error": f"не запустить ручку: {e}"}
    try:
        out, err = await asyncio.wait_for(
            proc.communicate(payload.encode()), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        log.warning("handler.timeout", script=script, timeout=timeout)
        return {"ok": False, "error": f"таймаут {timeout}с"}
    if len(out) > MAX_OUTPUT:
        return {"ok": False, "error": f"ответ больше {MAX_OUTPUT} байт"}
    if proc.returncode != 0:
        msg = err.decode(errors="replace").strip()[:500] or f"код {proc.returncode}"
        return {"ok": False, "error": msg}
    text = out.decode(errors="replace").strip()
    if not text:
        return {"ok": True, "data": None}
    try:
        return {"ok": True, "data": json.loads(text)}
    except ValueError:
        return {"ok": False, "error": "ручка вернула не-JSON в stdout"}
