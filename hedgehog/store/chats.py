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


class ChatStore:
    def __init__(self, chats_dir: Path):
        self.chats_dir = chats_dir
        self.chats_dir.mkdir(parents=True, exist_ok=True)
        # chat_id → лимит транскрипта в байтах (0 = выкл). Кэш, чтобы не
        # читать meta.json на каждом событии; инвалидация в update_meta/delete.
        self._log_limits: dict[str, int] = {}

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
                        log_kb=log_kb, skills=skills)
        (chat_dir / "meta.json").write_text(
            json.dumps(asdict(meta), ensure_ascii=False, indent=1))
        return meta

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
            return ChatMeta(**{k: v for k, v in data.items() if k in known})
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
        (self._chat_dir(chat_id) / "meta.json").write_text(
            json.dumps(asdict(meta), ensure_ascii=False, indent=1))
        self._log_limits.pop(chat_id, None)
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
            if meta is not None:
                self._rm_cwd_if_safe(meta.cwd, projects_base)
        shutil.rmtree(chat_dir, ignore_errors=True)
        self._log_limits.pop(chat_id, None)
        return True

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
                tail = tail[nl + 1:]
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
            if path.stat().st_size + len(line) > PENDING_HARD_CAP:
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
        """(события для resume_response, full_replay) — §5.3."""
        events = self.read_pending(chat_id)
        if last_seen_id is None:
            return events, True
        if not events:
            # Всё ack'нуто: новых событий нет, история клиента актуальна.
            return [], False
        for i, ev in enumerate(events):
            if ev.get("id") == last_seen_id:
                return events[i + 1:], False
        # last_seen_id не в журнале: либо уже ack'нут (норма — отдаём всё,
        # клиент дедуплицирует по id, §5.4), либо это дыра. Если журнал
        # начинается с события старше курсора — норма; иначе full replay.
        if events and str(events[0].get("id", "")) > last_seen_id:
            return events, False
        return events, True

    def _rewrite_pending(self, chat_id: str, events: list[dict]):
        path = self._pending_path(chat_id)
        tmp = path.with_suffix(".jsonl.tmp")
        with tmp.open("w", encoding="utf-8") as fh:
            for ev in events:
                fh.write(json.dumps(ev, ensure_ascii=False) + "\n")
        tmp.replace(path)

    def _shed_pending(self, chat_id: str):
        """Страховка §6.2: дроп болтливых типов, важные события остаются."""
        events = self.read_pending(chat_id)
        kept = [ev for ev in events if ev.get("type") not in DROP_FIRST_TYPES]
        # Пометка дыры для следующего resume (§6.2: partial_loss).
        self._partial_loss = getattr(self, "_partial_loss", set())
        self._partial_loss.add(chat_id)
        self._rewrite_pending(chat_id, kept)

    def had_partial_loss(self, chat_id: str) -> bool:
        return chat_id in getattr(self, "_partial_loss", set())

    def clear_partial_loss(self, chat_id: str):
        getattr(self, "_partial_loss", set()).discard(chat_id)
