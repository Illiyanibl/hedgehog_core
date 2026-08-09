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
description: Reply with an INTERACTIVE window in the chat (buttons, games, trainers, forms, polls, dashboards, drawings) instead of plain text. Use whenever the user wants something visual, clickable, step-by-step, or data-backed (e.g. a scrollable dashboard from a database).
---

# Interactive GUI right in the chat

You have MCP tools from the `hedgehog` server that render an interactive window
(a WebView) on the user's phone. The phone renders your HTML locally in an
OFFLINE sandbox (no network unless `allow_external`).

## When to use
Whenever the user asks for something visual / clickable / step-by-step (game,
trainer, quiz, form, poll, dashboard, buttons, "draw…", "make a button",
"make a scrollable dashboard from the DB") — reply with a WINDOW, not a wall
of text.

## Window tools
- `ask_ui(html, title)` — BLOCKING window: show → wait for ONE reply
  (`hedgehog.submit(data)`) → continue. For one-shot forms/quizzes.
- `ui_open(html, title, allow_external)` — PERSISTENT window; does NOT block your
  turn. Events arrive asynchronously (see SDK below); change it with
  `ui_update(html)`, close it with `ui_close()`.
- `kv_set(key, value)` / `kv_get(key)` — shared state across windows and chats.

## In-window JS SDK (call these from your HTML)
- `hedgehog.call(name, args)` → **Promise** — call a SERVER HANDLER you registered
  (see below). DETERMINISTIC, no agent turn, zero tokens — this is how a window
  reads/writes REAL data (e.g. a database). Contract (STABLE):
    * resolves with `{ ok: true, data: <the JSON your handler printed, parsed> }`
    * or `{ ok: false, error: "<message>" }`  (it NEVER rejects)
    * Usage:
        const r = await hedgehog.call('day', { date: '2026-08-09' });
        if (r.ok) render(r.data); else showError(r.error);
- `hedgehog.notify(data)` — event → arrives to you as a normal message (a full
  turn: write to chat, run bash, any tool, and/or `ui_update`). Use only when you
  need YOUR intelligence/action. Do NOT use it for plain data fetches — use
  `hedgehog.call` for that (instant, no tokens).
- `hedgehog.action(id, data)` — named event (route by id).
- `hedgehog.chat(text)` — text straight into the chat.
- `hedgehog.open(url)` — open a link in the system browser.
- `allow_external=true` → the window may use the network (embed YouTube/site).

## Server handlers ("ручки") — the data plane for windows
A handler is a small script in the chat's cwd. Contract: it reads JSON args from
STDIN and prints a JSON result to STDOUT. Register it once, then the window calls
it instantly via `hedgehog.call` with NO agent turn. Perfect for scrollable
dashboards backed by a DB.

Handler tools:
- `handler_register(name, script, view_id?)` — register `name` → `script`
  (a path INSIDE the chat cwd). Call it right AFTER `ui_open`: if you omit
  `view_id` it AUTO-BINDS to the current window (so the handler is erased when
  that window is deleted). Or pass the `view_id` that `ui_open` returned.
- `handler_list` — list this chat's handlers.
- `handler_unregister(name)` — remove one.
- `handler_call(name, args)` — run it yourself to test (`args` is a JSON string).
- `ui_current` — which window is running + registered handlers.

Handler script example (`day.py` in the chat cwd):
    import sys, json, sqlite3
    args = json.loads(sys.stdin.read() or "{}")
    date = args.get("date")
    # ... query your DB ...
    print(json.dumps({"date": date, "kcal": 1234}))   # JSON -> stdout

Execution: one subprocess per call, project venv (`<cwd>/.venv/bin/python`) if
present else `python3`; timeout + output cap; script path must stay inside cwd.
A lightweight LOCAL data plane — for real scale move it into a container (not
needed here).

## Canonical pattern: scrollable DB dashboard
1. Write handler `day.py` in the chat cwd: `{date}` in → JSON out.
2. `handler_register("day", "day.py", view_id)`.
3. `ui_open(html, "Diary")` whose HTML has ‹ › buttons and:
       async function go(date){
         const r = await hedgehog.call('day', { date });
         if (r.ok) render(r.data);            // draw the day's data
         else console.error('handler:', r.error);
       }
   Each ‹ › tap calls `go(newDate)` → data straight from the DB, instantly, with
   no agent turn. (Bake the FIRST day's data into the HTML so it shows before the
   first call returns; every navigation goes through `hedgehog.call`.)

## Rules for a good window
- HTML is a FULL self-contained document (inline CSS/JS), dark theme, big touch
  targets, no external resources (unless `allow_external`).
- Do local/presentational logic in page JS. Use `hedgehog.call` for DATA;
  use `hedgehog.notify` only when you genuinely need your intelligence/action.
- One window per chat is "current". To CHANGE a live window use `ui_update`
  (don't spam new `ui_open`s). Calling `ui_open` again with the SAME `title`
  also updates that same window (stable id — handlers stay bound) instead of
  piling up duplicates in history.

## Example
"Make a word-pair trainer" → `ui_open` with the game: two columns, matching +
score in JS; double-tap a word → `hedgehog.notify('example with word X')` → you
reply with an example in the chat.
"""


def _user_skills_dir() -> Path:
    return Path.home() / ".claude" / "skills"


def ensure_builtin() -> None:
    """Положить/ОБНОВИТЬ встроенный скилл GUI в ~/.claude/skills.
    Перезаписываем при изменении контента (наш built-in — источник правды),
    чтобы обновления документации доезжали до уже установленных копий.
    Идемпотентно; вызывается из discover(), чтобы скилл был виден по умолчанию.
    """
    try:
        path = _user_skills_dir() / _BUILTIN_GUI_NAME / "SKILL.md"
        if (path.exists()
                and path.read_text(encoding="utf-8") == _BUILTIN_GUI_SKILL):
            return  # уже актуально
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
