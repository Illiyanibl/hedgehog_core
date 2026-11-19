"""Редакция секретов в текстах, уходящих клиенту, в журнал и логи (§auth).

Ключи API и токены попадают в stderr CLI, URL ошибок (Gemini: `?key=`), вывод
команд агента (`env`). Редактируем (а) точные значения действующих секретов —
их поставляют зарегистрированные источники — и (б) типовые форматы ключей."""

from __future__ import annotations

import re
import time
from typing import Callable, Iterable

from ..i18n import Msg

MASK = "***"
_MIN_SECRET_LEN = 8

# форматы ключей разных вендоров — один объединённый паттерн (один проход по тексту);
# регистронезависимость задана локально (?i:...), а не глобально
_PATTERN = re.compile("|".join((
    r"sk-ant-[A-Za-z0-9_\-]{10,}",          # Anthropic (в т.ч. oat-токены)
    r"sk-[A-Za-z0-9_\-]{20,}",              # OpenAI и совместимые
    r"xai-[A-Za-z0-9]{20,}",                # xAI
    r"AIza[0-9A-Za-z_\-]{30,}",             # Google AI Studio
    r"AQ\.[A-Za-z0-9_\-]{30,}",             # Google API keys нового формата
    r"(?i:(?<=bearer ))[A-Za-z0-9._~+/=\-]{20,}",
    r"(?i:(?<=[?&]key=))[^&\s\"']+",
    r"(?i:(?<=api[_-]key[=:] ))[^\s\"']{8,}",
)))
_MIN_TEXT = 8          # короче любого секрета/формата — быстрый выход
_MAX_DEPTH = 6
_TTL = 5.0             # страховка на случай, если invalidate() не позвали

_sources: list[Callable[[], Iterable[str]]] = []


# Кэш (gen, monotonic, список). Запись — атомарная замена целого кортежа
# (присваивание глобала в CPython атомарно), читатель берёт кортеж одним
# чтением, поэтому замок не нужен: в худшем случае два потока посчитают список
# дважды. invalidate() увеличивает _gen — кэш с другим gen считается устаревшим.
_gen = 0
_cache: tuple[int, float, list[str]] = (-1, 0.0, [])


def invalidate() -> None:
    """Сбросить кэш действующих секретов (после смены/сброса ключей)."""
    global _gen
    _gen += 1


def add_source(fn: Callable[[], Iterable[str]]) -> None:
    """Зарегистрировать поставщика действующих секретов (вызывается на каждый redact)."""
    if fn not in _sources:
        _sources.append(fn)
    invalidate()


def clear_sources() -> None:
    _sources.clear()
    invalidate()


def _compute() -> list[str]:
    out: list[str] = []
    for fn in list(_sources):
        try:
            out += [s for s in fn() if isinstance(s, str) and len(s) >= _MIN_SECRET_LEN]
        except Exception:  # noqa: BLE001 — редакция не должна ронять вызывающего
            continue
    return sorted(set(out), key=len, reverse=True)       # длинные первыми


def active_secrets() -> list[str]:
    global _cache
    gen, ts, val = _cache
    now = time.monotonic()
    if gen == _gen and now - ts < _TTL:
        return val
    gen = _gen                       # читаем до вычисления: гонка с invalidate → пересчёт позже
    val = _compute()
    _cache = (gen, now, val)
    return val


def redact(text):
    """Строка без секретов; не-строки возвращаются как есть."""
    if not isinstance(text, str) or len(text) < _MIN_TEXT:
        return text
    for s in active_secrets():
        if s in text:
            text = text.replace(s, MASK)
    return _PATTERN.sub(MASK, text)


def redact_payload(obj, depth: int = 0):
    """Рекурсивно редактирует str внутри dict/list (глубина ≤ 6); прочее как есть.
    Msg остаётся Msg (ключ для локализации), редактируются его аргументы."""
    if isinstance(obj, Msg):
        args = redact_payload(obj.args, depth + 1)
        return obj if args == obj.args else Msg(obj.key, **args)
    if isinstance(obj, str):
        return redact(obj)
    if depth >= _MAX_DEPTH:
        return obj
    if isinstance(obj, dict):
        return {k: redact_payload(v, depth + 1) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact_payload(v, depth + 1) for v in obj]
    return obj


# ---------- потоковая редакция ----------
# «Затравки» форматов: начало ключа/контекста. Токенные — за затравкой идёт
# растущий токен; контекстные — значение после «bearer »/«key=»/«api_key: ».
_TOKEN_SEEDS = ("sk-", "xai-", "AIza", "AQ.")
_TOKEN_REST = re.compile(r"[A-Za-z0-9_\-.]*\Z")
_CTX_SEEDS = (          # (затравка в нижнем регистре, допустимые символы значения)
    ("bearer ", re.compile(r"[A-Za-z0-9._~+/=\-]*\Z")),
    ("key=", re.compile(r"[^&\s\"'*]*\Z")),
    ("api_key= ", re.compile(r"[^\s\"'*]*\Z")),
    ("api_key: ", re.compile(r"[^\s\"'*]*\Z")),
    ("api-key= ", re.compile(r"[^\s\"'*]*\Z")),
    ("api-key: ", re.compile(r"[^\s\"'*]*\Z")),
)
_MIN_TAIL = 128      # ключ Anthropic ~108 символов; спека — не меньше 64


class StreamRedactor:
    """Редакция потока дельт одной сессии: ключ, разрезанный границей чанков,
    не должен утечь половинками. feed() отдаёт безопасную часть, хвост
    (≤ max(длина самого длинного активного секрета, 64)), который может
    оказаться началом секрета или затравки формата, придерживается до
    следующего чанка/flush(). Обычный текст задерживается не дольше такого
    хвоста (на деле — на пару символов)."""

    def __init__(self) -> None:
        self._buf = ""

    def reset(self) -> None:
        self._buf = ""

    @staticmethod
    def _could_start_secret(cand: str, secrets: list[str]) -> bool:
        for s in secrets:
            if len(cand) < len(s) and s.startswith(cand):
                return True
        low = cand.lower()
        for seed in _TOKEN_SEEDS:
            if len(cand) < len(seed):
                if seed.startswith(cand) or seed.lower().startswith(low):
                    return True
            elif cand.startswith(seed) and _TOKEN_REST.match(cand, len(seed)):
                return True
        for seed, rest in _CTX_SEEDS:
            if len(low) < len(seed):
                if seed.startswith(low):
                    return True
            elif low.startswith(seed) and rest.match(cand, len(seed)):
                return True
        return False

    def feed(self, chunk: str) -> str:
        if not chunk:
            return ""
        raw = self._buf + chunk
        secrets = active_secrets()
        limit = max(max((len(x) for x in secrets), default=0), _MIN_TAIL)
        # хвост ищем в СЫРОМ тексте: токен «sk-…» уже подходит под паттерн, но
        # ещё растёт — пока за ним нет разделителя, держим его целиком
        for i in range(max(0, len(raw) - limit), len(raw)):
            if self._could_start_secret(raw[i:], secrets):
                i = max(0, i - 1)      # +1 символ слева: lookbehind «[?&]key=» не теряем
                self._buf = raw[i:]
                return redact(raw[:i])
        self._buf = ""
        return redact(raw)

    def flush(self) -> str:
        out, self._buf = redact(self._buf), ""
        return out
