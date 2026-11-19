"""Чаты на диске: /data/chats/<chatId>/ + журнал недоставленных событий.

Раскладка каталога чата (protocol/messages.md §6, CLAUDE.md):
    /data/chats/<chatId>/
    ├── meta.json        # {chatId, name, addressee, cwd, created_at}
    ├── pending.jsonl    # append-only журнал недоставленных фреймов
    ├── transcript.log   # plain-text транскрипт PTY (только broker_shell)
    └── ...              # рабочие файлы самого чата (cwd по умолчанию)

Retention MVP: события удаляются только по ack (§6.2). Отклонение от
спецификации в сторону простоты: вместо периодического prefix-truncate
журнал переписывается на каждом ack — при живом клиенте файл маленький,
цена копейки, а код очевиден. Размерная страховка 100 MiB с дропом
text_delta — как в §6.2.
"""

from __future__ import annotations

import json
import shutil
import time
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path

import re

from ..ids import new_ulid


def slug_name(name: str) -> str:
    """Имя чата → безопасное имя папки. Юникод-буквы сохраняются (папки на
    Linux это позволяют), опасные для пути символы и пробелы → дефисы.

    «New Chat» → «new-chat», «Логи» → «логи», «../etc» → «etc»."""
    # Выкидываем разделители пути, управляющие и точки-в-начале.
    cleaned = re.sub(r"[/\\\0\.\s]+", "-", name.strip().lower())
    slug = re.sub(r"-{2,}", "-", cleaned).strip("-")
    return slug or "chat"


PENDING_HARD_CAP = 100 * 1024 * 1024  # §6.2: размерная страховка
# При переполнении первыми дропаются события "болтливых" типов.
DROP_FIRST_TYPES = ("text_delta", "screen_snapshot")
# Постоянный транскрипт: хвост при переполнении (амортизация гистерезисом).
# Лимит настраивается per-chat через meta.log_kb (§3.7): None → дефолт,
# 0 → транскрипт не пишется. Гистерезис — 10% лимита, но не меньше 4 КиБ.
TRANSCRIPT_DEFAULT_BYTES = 10 * 1024 * 1024


@dataclass
class ChatMeta:
    chatId: str
    name: str
    addressee: str  # "claude" | "broker_shell"
    cwd: str
    created_at: float
    # Поля с дефолтами — добавлены 2026-07-05; старые meta.json без них
    # читаются корректно (get() отбрасывает лишние ключи, дефолты подставит).
    mcp: list[str] = field(default_factory=list)
    permission_mode: str = "default"
    # §3.7 log_kb: размер транскрипта в КиБ; None → дефолт, 0 → выкл.
    log_kb: int | None = None
    # id сессии Claude CLI (~/.claude/projects/...) — для resume контекста
    # после рестарта Ёжика/set_mode. Обновляется после каждого хода агента.
    claude_session_id: str | None = None
    # Гейт скиллов (§skills): None/[] — скиллы выключены (дефолт, поведение
    # как раньше), список имён — allowlist включённых. Прокидывается в
    # ClaudeAgentOptions.skills. Имена сверяются со skills_registry.discover.
    skills: list[str] | None = None
    # §models: выбранная в чате модель (алиас CLI или полный id) — уходит в
    # opts["model"] и перекрывает дефолт тира. None → дефолт CLI. Меняется
    # фреймом set_model; переживает рестарт/set_mode (persist в meta.json).
    model: str | None = None
    # §cli-types: тип CLI-агента чата (claude сейчас; задел под codex и др.).
    # Для broker_shell не используется. Старые meta.json без поля → "claude".
    cliType: str = "claude"
    # §multi-cli: состояние КАЖДОГО CLI в этом чате (cliType → запись
    # {initialized, session_id, model}); активный CLI = cliType. Плоские
    # claude_session_id/model — зеркала на один релиз (откат сервера без
    # амнезии чатов, протокол §18.2). Пусто у старых meta.json — мигрирует
    # лениво на чтении (ChatStore.get).
    cliSessions: dict[str, dict] = field(default_factory=dict)


def new_cli_entry() -> dict:
    """Пустая запись состояния CLI в чате (§multi-cli)."""
    return {"initialized": False, "session_id": None, "model": None,
            "effort": None}


def _clean_cli_sessions(raw: object) -> dict[str, dict]:
    """Нормализовать cliSessions из meta.json: только {str: dict}, каждая запись
    с полными полями. Битая/ручная правка не должна ронять list_chats всем."""
    if not isinstance(raw, dict):
        return {}
    out: dict[str, dict] = {}
    for cli, entry in raw.items():
        if not isinstance(cli, str) or not isinstance(entry, dict):
            continue
        clean = new_cli_entry()
        clean.update({k: entry[k] for k in clean if k in entry})
        out[cli] = clean
    return out


def migrate_cli_sessions(meta: ChatMeta) -> None:
    """Ленивая миграция §multi-cli: старый meta.json (без cliSessions) →
    запись активного CLI из плоских claude_session_id/model. Идемпотентна;
    для broker_shell (нет CLI-агента) ничего не делает."""
    if meta.cliSessions or meta.addressee != "claude":
        return
    entry = new_cli_entry()
    entry["model"] = meta.model
    if meta.cliType == "claude":
        entry["session_id"] = meta.claude_session_id
        entry["initialized"] = bool(meta.claude_session_id)
    meta.cliSessions = {meta.cliType: entry}


def public_meta(meta: ChatMeta, include_cli_sessions: bool = False) -> dict:
    """Мета чата для клиента (chat_created/chat_updated/chat_list).

    Заменяет прежний vars(meta). По умолчанию wire-формат ИДЕНТИЧЕН
    доязычному: без cliSessions (§18.3 гейт multi_cli). С include_cli_sessions
    — cliSessions в публичном виде: БЕЗ session_id (серверная кухня,
    §18.2)."""
    out = dict(vars(meta))
    sessions = out.pop("cliSessions", None)
    sessions = sessions if isinstance(sessions, dict) else {}
    if include_cli_sessions:
        out["cliSessions"] = {
            cli: {"initialized": bool(e.get("initialized")),
                  "model": e.get("model"), "effort": e.get("effort")}
            for cli, e in sessions.items() if isinstance(e, dict)}
    return out


class ChatStore:
    def __init__(self, chats_dir: Path):
        self.chats_dir = chats_dir
        self.chats_dir.mkdir(parents=True, exist_ok=True)
        # chat_id → лимит транскрипта в байтах (0 = выкл). Кэш, чтобы не
        # читать meta.json на каждом событии; инвалидация в update_meta/delete.
        self._log_limits: dict[str, int] = {}
        # §6.2: чаты, где pending переполнился и был подрезан (_shed_pending) —
        # клиент получит маркер «дыры». Инициализируем ЗДЕСЬ (а не ленивым
        # getattr): _shed_pending теперь бежит в потоке (hub journal to_thread),
        # и ленивая RMW-инициализация гонялась бы между чатами, теряя флаг.
        self._partial_loss: set[str] = set()

    # ---------- meta ----------

    def _chat_dir(self, chat_id: str) -> Path:
        # ULID — [0-9A-Z]{26}; защита от path traversal на всякий случай.
        if not chat_id.isalnum():
            raise ValueError(f"bad chatId: {chat_id!r}")
        return self.chats_dir / chat_id

    def create(self, name: str, addressee: str, cwd: str | None,
               mcp: list[str] | None = None,
               permission_mode: str = "default",
               log_kb: int | None = None,
               skills: list[str] | None = None,
               cli_type: str = "claude",
               projects_base: str | None = None) -> ChatMeta:
        chat_id = new_ulid()
        chat_dir = self._chat_dir(chat_id)
        chat_dir.mkdir(parents=True)
        if cwd is None:
            if projects_base:
                # Папка под чат по имени: <projects_base>/<slug> (§3.7).
                cwd = str(Path(projects_base) / slug_name(name))
                Path(cwd).mkdir(parents=True, exist_ok=True)
            else:
                cwd = str(chat_dir)  # изоляция: своя папка в data/chats/<id>
        else:
            Path(cwd).mkdir(parents=True, exist_ok=True)
        meta = ChatMeta(chatId=chat_id, name=name, addressee=addressee,
                        cwd=cwd, created_at=time.time(),
                        mcp=mcp or [], permission_mode=permission_mode,
                        log_kb=log_kb, skills=skills, cliType=cli_type)
        self._write_meta(chat_dir / "meta.json", meta)
        return meta

    @staticmethod
    def _write_meta(meta_path: Path, meta: ChatMeta) -> None:
        """M1: атомарная запись meta.json (tmp+replace). Прямой write_text на
        crash/диск-фулл оставлял бы полузаписанный битый JSON → get() ловит
        ValueError → None → чат «исчезает». replace атомарен на POSIX; при сбое
        записи tmp прежний meta.json остаётся целым."""
        tmp = meta_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(asdict(meta), ensure_ascii=False, indent=1))
        tmp.replace(meta_path)

    def get(self, chat_id: str) -> ChatMeta | None:
        try:
            meta_path = self._chat_dir(chat_id) / "meta.json"
        except ValueError:
            return None
        if not meta_path.exists():
            return None
        try:
            data = json.loads(meta_path.read_text())
            # Отбрасываем неизвестные ключи (forward-compat со старыми/новыми
            # версиями meta.json), недостающие поля добираются дефолтами.
            known = {f.name for f in fields(ChatMeta)}
            meta = ChatMeta(**{k: v for k, v in data.items() if k in known})
            meta.cliSessions = _clean_cli_sessions(meta.cliSessions)
            migrate_cli_sessions(meta)                   # §multi-cli
            return meta
        except (ValueError, TypeError):
            return None

    def update_meta(self, chat_id: str, **changes) -> ChatMeta | None:
        """Изменить поля meta.json существующего чата (напр. permission_mode).

        Возвращает обновлённый ChatMeta или None, если чата нет. Вызывающий
        сам перезапускает сессию, чтобы изменения вступили в силу.
        """
        meta = self.get(chat_id)
        if meta is None:
            return None
        for k, v in changes.items():
            if hasattr(meta, k):
                setattr(meta, k, v)
        self._sync_cli_mirrors(meta, changes)
        self._write_meta(self._chat_dir(chat_id) / "meta.json", meta)
        self._log_limits.pop(chat_id, None)
        return meta

    @staticmethod
    def _sync_cli_mirrors(meta: ChatMeta, changes: dict) -> None:
        """§multi-cli: двойная запись плоских полей в cliSessions.
        claude_session_id → cliSessions.claude; model → запись АКТИВНОГО CLI.
        Явная правка самого cliSessions зеркал не трогает (её делают
        set_active_cli/set_cli_state)."""
        if "cliSessions" in changes or meta.addressee != "claude":
            return
        if "claude_session_id" in changes:
            e = meta.cliSessions.setdefault("claude", new_cli_entry())
            e["session_id"] = changes["claude_session_id"]
            e["initialized"] = bool(changes["claude_session_id"])
        if "model" in changes:
            e = meta.cliSessions.setdefault(meta.cliType, new_cli_entry())
            e["model"] = changes["model"]

    def set_active_cli(self, chat_id: str, cli_type: str
                       ) -> tuple[ChatMeta, bool] | None:
        """§multi-cli: сделать cli_type активным. Возвращает (meta, first_init),
        first_init — у этого CLI ещё не было сессии в чате (initialized=False НА
        МОМЕНТ переключения). Плоское model следует за моделью нового CLI;
        claude_session_id остаётся зеркалом именно claude-сессии."""
        meta = self.get(chat_id)
        if meta is None:
            return None
        entry = meta.cliSessions.setdefault(cli_type, new_cli_entry())
        first_init = not entry.get("initialized")
        meta.cliType = cli_type
        meta.model = entry.get("model")
        meta.claude_session_id = (
            meta.cliSessions.get("claude", {}).get("session_id"))
        self._write_meta(self._chat_dir(chat_id) / "meta.json", meta)
        return meta, first_init

    def set_cli_state(self, chat_id: str, cli_type: str,
                      **fields_: object) -> ChatMeta | None:
        """§multi-cli: правка записи состояния ОДНОГО CLI (initialized/
        session_id/model). Для claude зеркалит плоские claude_session_id;
        для активного CLI — плоское model."""
        meta = self.get(chat_id)
        if meta is None:
            return None
        allowed = {"initialized", "session_id", "model", "effort"}
        bad = set(fields_) - allowed
        if bad:
            raise ValueError(f"unknown cli state fields: {sorted(bad)}")
        e = meta.cliSessions.setdefault(cli_type, new_cli_entry())
        e.update(fields_)
        if cli_type == "claude" and "session_id" in fields_:
            meta.claude_session_id = fields_["session_id"]
        if cli_type == meta.cliType and "model" in fields_:
            meta.model = fields_["model"]
        self._write_meta(self._chat_dir(chat_id) / "meta.json", meta)
        return meta

    def list(self) -> list[ChatMeta]:
        out = []
        for d in sorted(self.chats_dir.iterdir()):
            if d.is_dir():
                meta = self.get(d.name)
                if meta:
                    out.append(meta)
        return out

    def delete(self, chat_id: str, delete_cwd: bool = False,
               projects_base: str | None = None) -> bool:
        """Снос каталога чата (§6.3). Процессы останавливает вызывающий.

        `delete_cwd` — дополнительно удалить рабочую папку чата (cwd), но
        ТОЛЬКО если она лежит внутри projects_base и это не сам base
        (иначе снесли бы общий каталог проектов)."""
        try:
            chat_dir = self._chat_dir(chat_id)
        except ValueError:
            return False
        if not chat_dir.exists():
            return False
        if delete_cwd and projects_base:
            meta = self.get(chat_id)
            # M6: при slug-коллизии имён два чата делят один cwd
            # (<projects_base>/<slug>). Не удаляем папку, которую ещё использует
            # другой чат — иначе снесли бы его живые данные.
            if meta is not None and not self._cwd_shared(chat_id, meta.cwd):
                self._rm_cwd_if_safe(meta.cwd, projects_base)
        shutil.rmtree(chat_dir, ignore_errors=True)
        self._log_limits.pop(chat_id, None)
        return True

    def _cwd_shared(self, chat_id: str, cwd: str) -> bool:
        """M6: cwd используется ДРУГИМ чатом (slug-коллизия) → удалять нельзя."""
        try:
            target = Path(cwd).resolve()
        except OSError:
            return True                      # не смогли проверить — не рискуем
        for other in self.list():
            if other.chatId == chat_id:
                continue
            try:
                if Path(other.cwd).resolve() == target:
                    return True
            except OSError:
                continue
        return False

    @staticmethod
    def _rm_cwd_if_safe(cwd: str, projects_base: str):
        try:
            base = Path(projects_base).resolve()
            target = Path(cwd).resolve()
        except OSError:
            return
        # Внутри base и глубже минимум на один уровень.
        if target != base and base in target.parents:
            shutil.rmtree(target, ignore_errors=True)

    # ---------- transcript.jsonl (постоянная история, НЕ труncается по ack) ----------
    #
    # В отличие от pending.jsonl (буфер недоставленного, чистится ack'ом),
    # транскрипт — append-only лог всех событий чата для наблюдения задним
    # числом (hedgehog log, менеджер-агент). Ограничен по размеру: при
    # превышении per-chat лимита (transcript_limit) хранится хвост.

    def _transcript_path(self, chat_id: str) -> Path:
        return self._chat_dir(chat_id) / "transcript.jsonl"

    def transcript_limit(self, chat_id: str) -> int:
        """Лимит транскрипта чата в байтах (0 = транскрипт отключён)."""
        limit = self._log_limits.get(chat_id)
        if limit is None:
            meta = self.get(chat_id)
            if meta is None or meta.log_kb is None:
                limit = TRANSCRIPT_DEFAULT_BYTES
            else:
                limit = meta.log_kb * 1024
            self._log_limits[chat_id] = limit
        return limit

    def transcript_mtime(self, chat_id: str) -> float | None:
        """Время последнего события чата (mtime транскрипта)."""
        try:
            return self._transcript_path(chat_id).stat().st_mtime
        except (OSError, ValueError):
            return None

    def append_transcript(self, chat_id: str, frame: dict):
        limit = self.transcript_limit(chat_id)
        if limit <= 0:
            return  # log_kb=0 — чат живёт без транскрипта
        path = self._transcript_path(chat_id)
        line = json.dumps(frame, ensure_ascii=False) + "\n"
        hysteresis = max(limit // 10, 4096)
        try:
            with path.open("a", encoding="utf-8") as fh:
                fh.write(line)
            if path.stat().st_size > limit + hysteresis:
                self._truncate_transcript(chat_id, limit)
        except OSError:
            pass  # чат мог быть удалён под ногами — история не критична

    def transcript_last_id(self, chat_id: str) -> str | None:
        """id последнего события транскрипта — дешёвым чтением хвоста файла
        (без парсинга всего лога). Для short-circuit в events_after.

        M7: окно растёт, пока не выделит ПОЛНУЮ последнюю запись — большой
        ui_request мог быть > стартовых 4КБ, и тогда хвост не содержал целой
        строки → возвращался id предыдущей записи → short-circuit промахивался
        и падал в полный разбор лога."""
        path = self._transcript_path(chat_id)
        try:
            with path.open("rb") as fh:
                fh.seek(0, 2)
                size = fh.tell()
                if size == 0:
                    return None
                window = 4096
                while True:
                    start = max(0, size - window)
                    fh.seek(start)
                    chunk = fh.read().rstrip(b"\n")
                    nl = chunk.rfind(b"\n")
                    if nl != -1:               # после последнего \n — целая запись
                        last = chunk[nl + 1:]
                        break
                    if start == 0:             # весь файл — одна строка
                        last = chunk
                        break
                    window *= 4                # запись больше окна — растём
        except OSError:
            return None
        try:
            return json.loads(last).get("id")
        except ValueError:
            return None

    def read_transcript_tail(self, chat_id: str, n: int) -> list[dict]:
        path = self._transcript_path(chat_id)
        if not path.exists():
            return []
        events: list[dict] = []
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except ValueError:
                    continue
        return events[-n:] if n > 0 else events

    def _truncate_transcript(self, chat_id: str, limit: int):
        """Оставить хвост limit байт — амортизирует I/O гистерезисом."""
        path = self._transcript_path(chat_id)
        try:
            with path.open("rb") as src:
                src.seek(-limit, 2)
                tail = src.read()
            # Отрезаем первую (возможно оборванную) строку.
            nl = tail.find(b"\n")
            if nl != -1:
                trimmed = tail[nl + 1:]
                # F4: если после отрезания ничего не осталось — единственная запись
                # длиннее limit; НЕ обнуляем транскрипт (потеряли бы всю историю),
                # оставляем файл как есть (временно > limit, срежется на след. записи).
                if not trimmed:
                    return
                tail = trimmed
            tmp = path.with_suffix(".jsonl.tmp")
            tmp.write_bytes(tail)
            tmp.replace(path)
        except OSError:
            pass

    # ---------- pending.jsonl (§5.1, §6) ----------

    def _pending_path(self, chat_id: str) -> Path:
        return self._chat_dir(chat_id) / "pending.jsonl"

    def append_pending(self, chat_id: str, frame: dict):
        """Append полного фрейма — до отправки по WS (§5.1 шаг 2)."""
        path = self._pending_path(chat_id)
        line = json.dumps(frame, ensure_ascii=False) + "\n"
        try:
            # F11a: cap — в БАЙТАХ (ensure_ascii=False → кириллица крупнее символа);
            # раньше len(line) в символах занижал размер и кап превышался.
            if path.stat().st_size + len(line.encode("utf-8")) > PENDING_HARD_CAP:
                self._shed_pending(chat_id)
        except OSError:
            pass  # файла ещё нет — нечего проверять
        with path.open("a", encoding="utf-8") as fh:
            fh.write(line)

    def read_pending(self, chat_id: str) -> list[dict]:
        path = self._pending_path(chat_id)
        if not path.exists():
            return []
        events = []
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except ValueError:
                    continue  # оборванная последняя строка после падения
        return events

    def ack(self, chat_id: str, last_seen_id: str):
        """Удалить события до last_seen_id включительно (§5.1 шаг 6).

        Порядок определяется позицией в журнале (append-order), а не
        сравнением строк: если last_seen_id в журнале не найден, fallback —
        лексикографический (ULID сортируются по времени).
        """
        events = self.read_pending(chat_id)
        if not events:
            return
        cut = None
        for i, ev in enumerate(events):
            if ev.get("id") == last_seen_id:
                cut = i + 1
                break
        if cut is None:
            keep = [ev for ev in events if str(ev.get("id", "")) > last_seen_id]
        else:
            keep = events[cut:]
        self._rewrite_pending(chat_id, keep)

    def events_after(self, chat_id: str, last_seen_id: str | None) -> tuple[list[dict], bool]:
        """(события для resume_response, full_replay) — §5.3.

        §multi-device: pending чистится ack'ом ЛЮБОГО клиента, поэтому второй
        девайс с более старым курсором не найдёт свои недостающие события в
        pending. Тогда добираем их из ВЕЧНОГО транскрипта (не труncается по ack)
        — так сообщения, отправленные с другого устройства, видны везде.
        """
        events = self.read_pending(chat_id)
        if last_seen_id is None:
            return events, True
        # 1) курсор в pending → всё после него (быстрый путь).
        for i, ev in enumerate(events):
            if ev.get("id") == last_seen_id:
                return events[i + 1:], False
        # 2) курсор не в pending, но pending начинается ПОСЛЕ курсора → pending и
        #    есть новое (заакан ровно до курсора). Быстро, без чтения транскрипта.
        #    F3: только когда транскрипта НЕТ (limit<=0) — иначе допущение «заакан
        #    ровно до курсора» ломается при мульти-девайсе (ack другого устройства
        #    мог срезать pending дальше курсора), и события в дыре терялись бы;
        #    при живом транскрипте проваливаемся в ветку 4 и добираем их оттуда.
        if (events and str(events[0].get("id", "")) > last_seen_id
                and self.transcript_limit(chat_id) <= 0):
            return events, False
        # 3) pending пуст ИЛИ его первый ≤ курсора (курсор в «дыре» — типично при
        #    мульти-девайсе). Дешёвый short-circuit: курсор == последнему в
        #    транскрипте → девайс актуален, ничего не читаем целиком.
        if last_seen_id == self.transcript_last_id(chat_id):
            return [], False
        # 4) Девайс реально отстал → добираем всё новее курсора из вечного
        #    транскрипта (ULID сортируется по времени, клиент дедуплицирует).
        #    M7: читаем С КОНЦА блоками и останавливаемся, дойдя до курсора —
        #    не тянем весь лог (до 10 МБ) в память ради пары кадров.
        return self._transcript_after(chat_id, last_seen_id), False

    def _transcript_after(self, chat_id: str, last_seen_id: str) -> list[dict]:
        """Записи транскрипта с id > last_seen_id, читая файл С КОНЦА блоками.
        ULID отсортированы по времени, поэтому как только встречаем id ≤ курсора
        — дальше только старее, останавливаемся. Возврат — в хронологическом
        порядке. Эквивалентно фильтру полного чтения, но без загрузки всего лога.
        """
        path = self._transcript_path(chat_id)
        if not path.exists():
            return []
        block = 65536
        collected: list[dict] = []
        carry = b""            # неполная первая строка блока (продолжается ранее)
        try:
            with path.open("rb") as fh:
                fh.seek(0, 2)
                pos = fh.tell()
                done = False
                while pos > 0 and not done:
                    start = max(0, pos - block)
                    fh.seek(start)
                    data = fh.read(pos - start) + carry
                    pos = start
                    parts = data.split(b"\n")
                    # у не-начального блока первый фрагмент неполон → в carry
                    carry = parts[0] if start > 0 else b""
                    body = parts[1:] if start > 0 else parts
                    for raw in reversed(body):
                        raw = raw.strip()
                        if not raw:
                            continue
                        try:
                            ev = json.loads(raw)
                        except ValueError:
                            continue
                        if str(ev.get("id", "")) > last_seen_id:
                            collected.append(ev)
                        else:
                            # ULID монотонны → дальше только старее. (Оговорка:
                            # монотонность per-process; редкий clock-rewind через
                            # рестарт мог бы оставить чуть более старые id новее —
                            # это лишь пропуск реплея уже старых кадров, клиент
                            # дедуплицирует.)
                            done = True
                            break
        except OSError:
            return []
        collected.reverse()                    # хронологический порядок
        return collected

    def _rewrite_pending(self, chat_id: str, events: list[dict]):
        path = self._pending_path(chat_id)
        tmp = path.with_suffix(".jsonl.tmp")
        with tmp.open("w", encoding="utf-8") as fh:
            for ev in events:
                fh.write(json.dumps(ev, ensure_ascii=False) + "\n")
        tmp.replace(path)

    def _shed_pending(self, chat_id: str):
        """Страховка §6.2: дроп болтливых типов, важные события остаются.

        F6: если после дропа болтливых типов размер всё ещё выше cap — режем
        старейшие события ЛЮБЫХ типов до cap/2. Иначе при потоке важных событий
        (напр. долгий scheduled-прогон без клиента) cap не держался: файл рос без
        потолка, а _shed на каждом append перечитывал/переписывал весь 100+ МиБ
        (квадратичный I/O). Размер считаем в БАЙТАХ (ensure_ascii=False → кириллица)."""
        events = self.read_pending(chat_id)
        kept = [ev for ev in events if ev.get("type") not in DROP_FIRST_TYPES]
        sizes = [len(json.dumps(ev, ensure_ascii=False).encode()) + 1 for ev in kept]
        total = sum(sizes)
        if total > PENDING_HARD_CAP // 2:
            cut = 0                      # сколько старейших выкинуть (срез с начала)
            while cut < len(kept) and total > PENDING_HARD_CAP // 2:
                total -= sizes[cut]
                cut += 1
            kept = kept[cut:]
        # Пометка дыры для следующего resume (§6.2: partial_loss). set.add —
        # атомарен под GIL, безопасен из потока (инициализация в __init__).
        self._partial_loss.add(chat_id)
        self._rewrite_pending(chat_id, kept)

    def had_partial_loss(self, chat_id: str) -> bool:
        return chat_id in self._partial_loss

    def clear_partial_loss(self, chat_id: str):
        self._partial_loss.discard(chat_id)
