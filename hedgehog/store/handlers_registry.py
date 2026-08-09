"""§handlers (Ф-2): реестр серверных «ручек», привязанных к чату/вью.

Ручка — маленький скрипт в cwd чата (контракт: stdin=JSON-аргументы →
stdout=JSON-результат). Реестр держит, какие ручки есть у чата, чтобы:
  • вью звало их по ИМЕНИ (не по пути) — hedgehog.call(name, args);
  • Claude мог их перечислить (ui_current / handler_list);
  • при удалении вью (корзина §views) ручки этого вью стирались.

Файл data_dir/handlers.json: { chatId: { name: {script, view_id?, registered_at} } }.
Один процесс Ёжика, async single-thread → read-modify-write без гонок (как kv).
Исполнение здесь НЕ живёт — этим занят core/handler_runner (подпроцесс-на-вызов).
"""
from __future__ import annotations

import json
import time
from pathlib import Path


def _path(data_dir: Path) -> Path:
    return data_dir / "handlers.json"


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
    return entry


def register(data_dir: Path, chat_id: str, name: str, script: str,
             view_id: str | None = None) -> dict:
    """Зарегистрировать/перезаписать ручку чата. script — путь скрипта
    (обычно относительный от cwd чата). Возвращает запись."""
    data = _load(data_dir)
    entry = _chat(data, chat_id)
    rec = {
        "name": name,
        "script": script,
        "view_id": view_id,
        "registered_at": time.time(),
    }
    entry[name] = rec
    _save(data_dir, data)
    return rec


def get(data_dir: Path, chat_id: str, name: str) -> dict | None:
    rec = _load(data_dir).get(chat_id, {}).get(name)
    return rec if isinstance(rec, dict) else None


def list_(data_dir: Path, chat_id: str) -> list[dict]:
    """Все ручки чата (с полем name), отсортированы по имени."""
    entry = _load(data_dir).get(chat_id, {})
    if not isinstance(entry, dict):
        return []
    out = []
    for name in sorted(entry):
        rec = entry[name]
        if isinstance(rec, dict):
            out.append({**rec, "name": name})
    return out


def unregister(data_dir: Path, chat_id: str, name: str) -> bool:
    data = _load(data_dir)
    entry = data.get(chat_id, {})
    if isinstance(entry, dict) and name in entry:
        del entry[name]
        _save(data_dir, data)
        return True
    return False


def unregister_by_view(data_dir: Path, chat_id: str, view_id: str) -> int:
    """Стереть все ручки, привязанные к данному вью (удаление вью §views).
    Возвращает число удалённых."""
    data = _load(data_dir)
    entry = data.get(chat_id, {})
    if not isinstance(entry, dict):
        return 0
    doomed = [n for n, r in entry.items()
              if isinstance(r, dict) and r.get("view_id") == view_id]
    for n in doomed:
        del entry[n]
    if doomed:
        _save(data_dir, data)
    return len(doomed)


def clear_chat(data_dir: Path, chat_id: str) -> None:
    """Чат удалён — снять все его ручки."""
    data = _load(data_dir)
    if chat_id in data:
        del data[chat_id]
        _save(data_dir, data)
