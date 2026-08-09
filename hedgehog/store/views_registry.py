"""§views: реестр GUI-окон (view) по чатам.

Держит на СЕРВЕРЕ (источник правды) то, какое интерактивное окно сейчас
запущено в каждом чате (`current`) и историю ЯВНО закрытых (`history`).
Нужен для двух вещей:

  • детерминированный «пушер» переоткрытия — сервер сам повторно шлёт
    сохранённый `ui_request` в чат БЕЗ хода агента (ноль токенов);
  • интроспекция агентом — инструмент `ui_current` читает этот же реестр.

Файл `data_dir/views.json`:
    { chatId: {"current": rec|null, "history": [rec, ...]} }
rec = {id, title, html, persistent, allow_external, opened_at, closed_at?}.

Один процесс Ёжика, async single-thread → read-modify-write без гонок
(как kv.json). История дедуплится по (title, html) и ограничена HISTORY_CAP.
В историю попадают ТОЛЬКО явные закрытия (крестик юзера / ui_close); замена
текущего окна новым `ui_open` вытесняет прежнее без архивации.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

from ..ids import new_ulid

HISTORY_CAP = 20


def _path(data_dir: Path) -> Path:
    return data_dir / "views.json"


def _load(data_dir: Path) -> dict:
    try:
        data = json.loads(_path(data_dir).read_text())
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save(data_dir: Path, data: dict) -> None:
    data_dir.mkdir(parents=True, exist_ok=True)
    tmp = _path(data_dir).with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False))
    tmp.replace(_path(data_dir))


def _chat(data: dict, chat_id: str) -> dict:
    entry = data.get(chat_id)
    if not isinstance(entry, dict):
        entry = {}
        data[chat_id] = entry
    if not isinstance(entry.get("current"), (dict, type(None))):
        entry["current"] = None
    entry.setdefault("current", None)
    if not isinstance(entry.get("history"), list):
        entry["history"] = []
    return entry


def record_open(data_dir: Path, chat_id: str, *, title: str, html: str,
                persistent: bool, allow_external: bool) -> dict:
    """Новое окно стало текущим. Прежний `current` вытесняется без архивации
    (в историю копятся только явные закрытия). Возвращает созданную запись."""
    data = _load(data_dir)
    entry = _chat(data, chat_id)
    rec = {
        "id": new_ulid(),
        "title": title or "Интерактив",
        "html": html or "",
        "persistent": bool(persistent),
        "allow_external": bool(allow_external),
        "opened_at": time.time(),
    }
    entry["current"] = rec
    _save(data_dir, data)
    return rec


def record_update(data_dir: Path, chat_id: str, html: str) -> None:
    """ui_update — правит HTML текущего окна (если оно есть)."""
    data = _load(data_dir)
    entry = _chat(data, chat_id)
    if isinstance(entry.get("current"), dict):
        entry["current"]["html"] = html or ""
        _save(data_dir, data)


def record_close(data_dir: Path, chat_id: str) -> dict | None:
    """Явное закрытие текущего окна → уходит в историю (с closed_at).
    Дедуп по (title, html), кап HISTORY_CAP. Возвращает закрытую запись."""
    data = _load(data_dir)
    entry = _chat(data, chat_id)
    cur = entry.get("current")
    entry["current"] = None
    if not isinstance(cur, dict):
        _save(data_dir, data)
        return None
    cur["closed_at"] = time.time()
    hist = [h for h in entry["history"]
            if not (isinstance(h, dict)
                    and h.get("title") == cur.get("title")
                    and h.get("html") == cur.get("html"))]
    hist.insert(0, cur)
    entry["history"] = hist[:HISTORY_CAP]
    _save(data_dir, data)
    return cur


def get(data_dir: Path, chat_id: str) -> dict:
    """Снимок реестра чата: {current, history} (копии списка)."""
    data = _load(data_dir)
    entry = _chat(data, chat_id)
    return {"current": entry.get("current"),
            "history": list(entry.get("history", []))}


_SUMMARY_KEYS = ("id", "title", "persistent", "allow_external",
                 "opened_at", "closed_at")


def _light(rec: object) -> dict | None:
    """Запись без тяжёлого `html` — для списка на клиенте (переоткрытие идёт
    по id на сервере, HTML клиенту не нужен)."""
    if not isinstance(rec, dict):
        return None
    return {k: rec[k] for k in _SUMMARY_KEYS if k in rec}


def summary(data_dir: Path, chat_id: str) -> dict:
    """{current, history} с записями БЕЗ html — компактный ответ ui_list."""
    snap = get(data_dir, chat_id)
    return {
        "current": _light(snap.get("current")),
        "history": [lt for h in snap.get("history", [])
                    if (lt := _light(h)) is not None],
    }


def reopen(data_dir: Path, chat_id: str, view_id: str) -> dict | None:
    """Сделать запись (из истории или уже текущую) текущей и вернуть её для
    повторного пуша `ui_request`. Прежнее текущее вытесняется без архивации.
    None — если id не найден."""
    data = _load(data_dir)
    entry = _chat(data, chat_id)
    cur = entry.get("current")
    if isinstance(cur, dict) and cur.get("id") == view_id:
        return cur  # уже открыта — просто отдать для повторного пуша
    found = None
    rest = []
    for h in entry.get("history", []):
        if found is None and isinstance(h, dict) and h.get("id") == view_id:
            found = h
        else:
            rest.append(h)
    if found is None:
        return None
    reopened = dict(found)
    reopened.pop("closed_at", None)
    reopened["opened_at"] = time.time()
    entry["current"] = reopened
    entry["history"] = rest
    _save(data_dir, data)
    return reopened


def forget(data_dir: Path, chat_id: str, view_id: str) -> bool:
    """Удалить запись из истории. True — если что-то удалили."""
    data = _load(data_dir)
    entry = _chat(data, chat_id)
    hist = entry.get("history", [])
    kept = [h for h in hist
            if not (isinstance(h, dict) and h.get("id") == view_id)]
    if len(kept) == len(hist):
        return False
    entry["history"] = kept
    _save(data_dir, data)
    return True


def clear_chat(data_dir: Path, chat_id: str) -> None:
    """Чат удалён — снять все его записи."""
    data = _load(data_dir)
    if chat_id in data:
        del data[chat_id]
        _save(data_dir, data)
