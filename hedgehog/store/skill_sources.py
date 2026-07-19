"""Источники скиллов: установка по URL + группировка + дефолты новых чатов.

Модель (§skills v2): источник (git-репозиторий) = группа. Установка тянет
zip репозитория (БЕЗ git — на стендах его может не быть), кладёт все
найденные папки со `SKILL.md` в ~/.claude/skills и запоминает маппинг
`источник → [скиллы]` в data/skill_sources.json.

Плагины Claude Code (репо с каталогом `skills/`, напр. obra/superpowers)
ставятся «флэттеном»: берём все SKILL.md-папки как обычные user-скиллы;
хуки/команды плагина НЕ ставим (вне модели «только скиллы»).

Групповое вкл/выкл — операция над `meta.skills` конкретного чата (делает
wss). Здесь только реестр источников и флаг default_for_new (сидирование
новых чатов).
"""
from __future__ import annotations

import io
import json
import re
import shutil
import tempfile
import urllib.request
import zipfile
from pathlib import Path

import structlog

from . import skills_registry

log = structlog.get_logger("skills")

_SAFE_NAME = re.compile(r"^[A-Za-z0-9._-]+$")
_GH_RE = re.compile(r"^https?://github\.com/([^/]+)/([^/#?]+)")


def _user_skills_dir() -> Path:
    return Path.home() / ".claude" / "skills"


class SkillInstallError(Exception):
    """Понятная пользователю ошибка установки (уходит в install_skill_result)."""


class SkillSources:
    def __init__(self, path: Path):
        self.path = path  # data/skill_sources.json

    # ---------- реестр ----------

    def _load(self) -> dict:
        if not self.path.exists():
            return {}
        try:
            data = json.loads(self.path.read_text())
            return data if isinstance(data, dict) else {}
        except (ValueError, OSError) as e:
            log.warning("skills.sources_unreadable", err=str(e))
            return {}

    def _save(self, data: dict):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(data, ensure_ascii=False, indent=1))

    def sources(self) -> dict:
        """{source: {url, skills:[names], default_for_new:bool}}."""
        return self._load()

    def set_default_for_new(self, source: str, on: bool) -> bool:
        data = self._load()
        if source not in data:
            return False
        data[source]["default_for_new"] = bool(on)
        self._save(data)
        return True

    def new_chat_skill_names(self) -> list[str]:
        """Имена скиллов групп с default_for_new — для сидирования новых чатов."""
        names: list[str] = []
        for meta in self._load().values():
            if meta.get("default_for_new"):
                names += meta.get("skills", [])
        return list(dict.fromkeys(names))

    def remove(self, source: str) -> list[str]:
        """Снести источник и папки его скиллов. Возврат — удалённые имена."""
        data = self._load()
        meta = data.pop(source, None)
        if meta is None:
            return []
        removed = meta.get("skills", [])
        for name in removed:
            if _SAFE_NAME.match(name):
                shutil.rmtree(_user_skills_dir() / name, ignore_errors=True)
        self._save(data)
        return removed

    # ---------- установка ----------

    def install(self, url: str, default_for_new: bool = False) -> dict:
        """Скачать репо по URL, поставить скиллы, записать источник.

        Возврат: {source, skills:[names], default_for_new}. Кидает
        SkillInstallError с понятным текстом при любой проблеме.
        """
        owner, repo = _parse_github(url)
        raw = _download_zip(owner, repo)
        dest_base = _user_skills_dir()
        dest_base.mkdir(parents=True, exist_ok=True)
        names: list[str] = []
        with tempfile.TemporaryDirectory(prefix="skillsrc-") as tmp:
            try:
                with zipfile.ZipFile(io.BytesIO(raw)) as z:
                    z.extractall(tmp)
            except zipfile.BadZipFile:
                raise SkillInstallError("скачанный архив повреждён/не zip")
            seen: set[str] = set()
            for skill_md in sorted(Path(tmp).rglob("SKILL.md")):
                fm = _read_frontmatter(skill_md)
                if not fm:
                    continue
                name = (fm.get("name") or "").strip()
                if not name or not _SAFE_NAME.match(name) or name in seen:
                    continue
                seen.add(name)
                dst = dest_base / name
                if dst.exists():
                    shutil.rmtree(dst)
                shutil.copytree(skill_md.parent, dst)
                names.append(name)
        if not names:
            raise SkillInstallError(
                "в репозитории не найдено валидных скиллов "
                "(нужен SKILL.md с frontmatter name)")
        source = repo
        data = self._load()
        data[source] = {
            "url": url,
            "skills": names,
            "default_for_new": bool(default_for_new),
        }
        self._save(data)
        log.info("skills.installed", source=source, count=len(names),
                 default_for_new=default_for_new)
        return {"source": source, "skills": names,
                "default_for_new": bool(default_for_new)}


def _read_frontmatter(skill_md: Path) -> dict | None:
    try:
        return skills_registry._parse_frontmatter(
            skill_md.read_text(encoding="utf-8"))
    except OSError:
        return None


def _parse_github(url: str) -> tuple[str, str]:
    m = _GH_RE.match(url.strip())
    if not m:
        raise SkillInstallError("нужна ссылка на github.com/<owner>/<repo>")
    owner, repo = m.group(1), m.group(2)
    return owner, repo.removesuffix(".git")


def _default_branches(owner: str, repo: str) -> list[str]:
    """Ветки-кандидаты: default_branch из API, затем main/master."""
    try:
        api = f"https://api.github.com/repos/{owner}/{repo}"
        req = urllib.request.Request(api, headers={"User-Agent": "hedgehog"})
        with urllib.request.urlopen(req, timeout=20) as r:
            br = json.load(r).get("default_branch")
    except Exception:
        br = None
    order = [br] if br else []
    for b in ("main", "master"):
        if b not in order:
            order.append(b)
    return order


def _download_zip(owner: str, repo: str) -> bytes:
    last: Exception | None = None
    for br in _default_branches(owner, repo):
        url = f"https://codeload.github.com/{owner}/{repo}/zip/refs/heads/{br}"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "hedgehog"})
            with urllib.request.urlopen(req, timeout=90) as r:
                return r.read()
        except Exception as e:  # noqa: BLE001 — покажем пользователю причину
            last = e
    raise SkillInstallError(f"не удалось скачать архив репозитория: {last}")
