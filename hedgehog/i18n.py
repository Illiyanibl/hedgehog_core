"""§i18n: локализация пользовательских сообщений сервера по языку клиента.

Клиент сообщает язык в `client_hello.lang` и меняет его фреймом `set_language`
(protocol/messages.md §19). Язык хранится per-connection (Hub); сообщения для
пользователя создаются как `Msg(key, **args)` — это `str` (английский текст по
умолчанию), который несёт ключ и аргументы. Hub на отправке подставляет язык
соединения (`localize_frame`) и добавляет поля `<field>_key` / `<field>_args`,
чтобы клиент мог локализовать сам. Каталоги — `locales/<lang>.json`; цепочка
резервов: язык → en → ключ.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

SUPPORTED = ("bg", "de", "el", "en", "es", "fr", "id", "it", "ja", "pt-BR",
             "ru", "zh-Hans")
DEFAULT_LANG = "en"
_LOCALES = Path(__file__).resolve().parent / "locales"
_FILE = {lang: _LOCALES / f"{lang}.json" for lang in SUPPORTED}
_SUPPORTED_LOWER = {s.lower(): s for s in SUPPORTED}
_TAG_RE = re.compile(r"[^A-Za-z0-9_-]")


def normalize_lang(raw: Any) -> str:
    """Любой BCP-47-подобный тег клиента → поддерживаемый язык или `en`.

    pt/pt_BR/pt-PT → pt-BR; zh/zh-CN/zh-Hans-* → zh-Hans (традиционный
    zh-Hant/TW/HK не поддержан → en); остальные — по основному подтегу."""
    if not isinstance(raw, str):
        return DEFAULT_LANG
    tag = _TAG_RE.sub("", raw.strip()).replace("_", "-").lower()
    if not tag:
        return DEFAULT_LANG
    if tag in _SUPPORTED_LOWER:
        return _SUPPORTED_LOWER[tag]
    parts = tag.split("-")
    base = parts[0]
    if base == "pt":
        return "pt-BR"
    if base == "zh":
        rest = set(parts[1:])
        if "hans" in rest:                       # явно упрощённый (zh-Hans-HK)
            return "zh-Hans"
        if "hant" in rest or rest & {"tw", "hk", "mo"}:
            return DEFAULT_LANG
        return "zh-Hans"
    return base if base in _SUPPORTED_LOWER else DEFAULT_LANG


@lru_cache(maxsize=None)
def _catalog(lang: str) -> dict[str, str]:
    path = _FILE.get(lang)
    if path is None or not path.is_file():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    return {k: v for k, v in data.items() if isinstance(v, str)}


class _SafeDict(dict):
    def __missing__(self, key: str) -> str:      # неизвестный плейсхолдер не падает
        return "{" + key + "}"


def t(key: str, lang: str = DEFAULT_LANG, /, **args: Any) -> str:
    """Текст по ключу на языке lang (резерв: en → сам ключ), с подстановкой."""
    text = _catalog(lang).get(key)
    if text is None:
        text = _catalog(DEFAULT_LANG).get(key, key)
    try:
        return text.format_map(_SafeDict(args))
    except (ValueError, IndexError, KeyError, AttributeError, TypeError):
        return text                              # битый шаблон/странные args


def has_key(key: str) -> bool:
    return key in _catalog(DEFAULT_LANG)


class Msg(str):
    """Пользовательское сообщение: ведёт себя как `str` (английский текст), но
    помнит ключ/аргументы — Hub локализует его под язык соединения."""

    key: str
    args: dict

    def __new__(cls, key: str, /, **args: Any):
        obj = super().__new__(cls, t(key, DEFAULT_LANG, **args))
        obj.key = key
        obj.args = args
        return obj

    def render(self, lang: str) -> str:
        return t(self.key, lang, **self.args)

    def __reduce__(self):                # deepcopy/pickle (dataclasses.asdict)
        return (_rebuild_msg, (self.key, self.args))


def _rebuild_msg(key: str, args: dict) -> "Msg":
    return Msg(key, **args)


def msg_of(exc: BaseException) -> str:
    """Сообщение исключения с сохранением Msg (str(exc) его бы обезличил)."""
    if exc.args and isinstance(exc.args[0], Msg):
        return exc.args[0]
    return str(exc)


# Поля payload верхнего уровня, которые могут быть локализованы.
LOCALIZABLE_FIELDS = ("message", "error", "title", "body")


def expand_msgs(payload: dict) -> dict:
    """Msg-значения → английский текст + `<f>_key`/`<f>_args` (форма для
    журнала: ключ переживает запись на диск). Не-Msg payload возвращается как есть."""
    if not any(isinstance(v, Msg) for v in payload.values()):
        return payload
    out = dict(payload)
    for k, v in payload.items():
        if isinstance(v, Msg):
            out[k] = str.__str__(v)
            out[k + "_key"] = v.key
            out[k + "_args"] = v.args
    return out


def localize_payload(payload: dict, lang: str) -> dict:
    """Подставить язык: Msg-значения и поля с `<f>_key` рендерятся на lang."""
    changes: dict[str, Any] = {}
    for k, v in payload.items():
        if isinstance(v, Msg):
            changes[k] = v.render(lang)
            changes[k + "_key"] = v.key
            changes[k + "_args"] = v.args
    for f in LOCALIZABLE_FIELDS:
        key = payload.get(f + "_key")
        if isinstance(key, str) and f not in changes and has_key(key):
            args = payload.get(f + "_args")
            safe = ({str(k): v for k, v in args.items()}
                    if isinstance(args, dict) else {})
            changes[f] = t(key, lang, **safe)
    if not changes:
        return payload
    return {**payload, **changes}


def localize_frame(frame: dict, lang: str) -> dict:
    """Копия фрейма с локализованным payload (оригинал не меняется).

    Горячий путь отправки: ЛЮБАЯ ошибка локализации (битые данные журнала,
    странные args) → отдаём исходный фрейм, а не роняем рассылку."""
    try:
        payload = frame.get("payload")
        if not isinstance(payload, dict):
            return frame
        new = localize_payload(payload, lang)
        if new is payload:
            return frame
        return {**frame, "payload": new}
    except Exception:  # noqa: BLE001
        return frame
