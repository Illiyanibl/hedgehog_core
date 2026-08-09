"""Перечисление скиллов Agent SDK через скан файловой системы.

Скилл SDK — папка со `SKILL.md`, у которого в начале YAML-frontmatter
(`name`, `description`). CLI ищет их в `~/.claude/skills` (source=user) и
`<cwd чата>/.claude/skills` (source=project). Мы перечисляем те же папки
сами — БЕЗ похода к модели и без запуска SDK: список нужен клиенту для
графических тумблеров (§skills). Гейт применяет claude_session через
ClaudeAgentOptions.skills (allowlist).

Разбор frontmatter — минимальный (без PyYAML): нужны только `name` и
`description` в виде `key: value`. Скилл без валидного `name` пропускаем —
такой SDK всё равно не зарегистрирует.
"""
from __future__ import annotations

from pathlib import Path

# §gui-skill: встроенный скилл «GUI» — поставляется по умолчанию (кладётся в
# ~/.claude/skills при первом discover), поэтому виден в списке SKL без
# установки. Включённый, он говорит Claude отвечать интерактивным окном
# (ask_ui/ui_open) вместо простого текста.
_BUILTIN_GUI_NAME = "hedgehog-gui"
_BUILTIN_GUI_SKILL = """\
---
name: hedgehog-gui
description: Отвечай ИНТЕРАКТИВНЫМ окном в чате (кнопки, игры, тренажёры, формы, опросы, дашборды, рисунки), а не только текстом. Используй, когда пользователь хочет что-то визуальное, кликабельное или пошаговое.
---

# Интерактивный GUI прямо в чате

У тебя есть MCP-инструменты сервера `hedgehog`, которые рисуют интерактивное
окно (WebView) на телефоне пользователя. Телефон рендерит HTML локально.

## Когда использовать
Когда пользователь просит что-то визуальное / кликабельное / пошаговое (игра,
тренажёр, викторина, форма, опрос, дашборд, кнопки, «нарисуй…», «сделай
кнопку») — отвечай ОКНОМ, а не длинным текстом.

## Инструменты
- `ask_ui(html, title)` — БЛОКИРУЮЩЕЕ окно: показал → ждёшь ОДИН ответ
  (`hedgehog.submit(data)`) → продолжаешь. Для одноразовых форм/викторин.
- `ui_open(html, title, allow_external)` — ПОСТОЯННОЕ окно, ход НЕ блокирует.
  События приходят асинхронно (см. SDK), меняй окно `ui_update(html)`,
  закрывай `ui_close()`.
- `kv_set(key, value)` / `kv_get(key)` — общее состояние между окнами и чатами
  (счётчики и т.п.).

## SDK внутри окна (вызывай эти JS-функции в HTML)
- `hedgehog.notify(data)` — событие → прилетает тебе как обычное сообщение
  (полноценный ход: пиши в чат, запускай bash, любой инструмент, и/или
  `ui_update`).
- `hedgehog.action(id, data)` — именованное действие (роутишь по id).
- `hedgehog.chat(text)` — текст прямо в чат.
- `hedgehog.open(url)` — открыть ссылку в системном браузере.
- `allow_external=true` → окну разрешена сеть (встроить YouTube/сайт в iframe).

## Правила хорошего окна
- HTML — ПОЛНЫЙ самодостаточный документ (inline CSS/JS), тёмная тема, крупные
  тач-цели, без внешних ресурсов (если не нужен allow_external).
- Локальную логику (цвет, счётчики, анимации, матчинг) делай в JS страницы —
  БЕЗ обращения к себе. К себе (`notify`) — только когда нужен твой ум/действие.
- Живой цикл: на каждое действие можешь показывать новый экран (`ui_update`).

## Пример
«Сделай тренажёр пар слов» → `ui_open` с игрой: две колонки, матчинг и счётчик
в JS; двойной тап по слову → `hedgehog.notify('пример со словом X')` → ты
отвечаешь примером в чате.
"""


def _user_skills_dir() -> Path:
    return Path.home() / ".claude" / "skills"


def ensure_builtin() -> None:
    """Положить встроенный скилл GUI в ~/.claude/skills, если его там нет.
    Идемпотентно; вызывается из discover(), чтобы скилл был виден по умолчанию.
    """
    try:
        path = _user_skills_dir() / _BUILTIN_GUI_NAME / "SKILL.md"
        if path.exists():
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(_BUILTIN_GUI_SKILL, encoding="utf-8")
    except OSError:
        pass  # не критично — просто не покажем встроенный скилл


def _parse_frontmatter(text: str) -> dict[str, str] | None:
    """Вернуть словарь ключей frontmatter или None, если его нет.

    Формат: первый блок между строками-делимитерами `---`. Значения —
    однострочные `key: value`; снимаем обрамляющие кавычки.
    """
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return None
    fields: dict[str, str] = {}
    for line in lines[1:]:
        if line.strip() == "---":
            return fields
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] in "\"'" and value[-1] == value[0]:
            value = value[1:-1]
        if key:
            fields[key] = value
    return None  # нет закрывающего делимитера — считаем невалидным


def _scan_dir(base: Path, source: str) -> dict[str, dict]:
    """{name: {name, description, source}} по одной базовой папке скиллов."""
    out: dict[str, dict] = {}
    if not base.is_dir():
        return out
    for entry in sorted(base.iterdir()):
        skill_md = entry / "SKILL.md"
        if not (entry.is_dir() and skill_md.is_file()):
            continue
        try:
            fm = _parse_frontmatter(skill_md.read_text(encoding="utf-8"))
        except OSError:
            continue
        if not fm:
            continue
        name = fm.get("name", "").strip()
        if not name:
            continue  # без name SDK скилл не грузит — не показываем
        out[name] = {
            "name": name,
            "description": fm.get("description", "").strip(),
            "source": source,
        }
    return out


def discover(cwd: str | None) -> list[dict]:
    """Все скиллы, видимые чату с данным cwd.

    Порядок как у SDK: project (<cwd>/.claude/skills), затем user
    (~/.claude/skills) перекрывает совпадающие имена. Возврат
    отсортирован по имени: [{name, description, source}].
    """
    ensure_builtin()  # встроенный GUI-скилл виден по умолчанию
    merged: dict[str, dict] = {}
    if cwd:
        merged.update(_scan_dir(Path(cwd) / ".claude" / "skills", "project"))
    merged.update(_scan_dir(_user_skills_dir(), "user"))
    return [merged[name] for name in sorted(merged)]
