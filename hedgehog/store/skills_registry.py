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


def _user_skills_dir() -> Path:
    return Path.home() / ".claude" / "skills"


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
    merged: dict[str, dict] = {}
    if cwd:
        merged.update(_scan_dir(Path(cwd) / ".claude" / "skills", "project"))
    merged.update(_scan_dir(_user_skills_dir(), "user"))
    return [merged[name] for name in sorted(merged)]
