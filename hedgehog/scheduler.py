"""§sched: планировщик задач + блэкборд артефактов (SQLite).

Один сервис на процесс Ёжика. Держит SQLite (jobs / job_runs / artifacts) и
фоновую петлю, которая по расписанию выполняет действия:
  - inject_text — послать текст в чат (агент отвечает штатно);
  - notify      — уведомление (баннер/инбокс).

Блэкборд `artifacts` — склад КРУПНЫХ/durable/переиспользуемых результатов
агентов (одна таблица, кросс-чат по chat_id; большие блобы кладём файлом, в БД
только ссылка). Мелкие кросс-чат значения остаются на kv_set/kv_get, мелкие
результаты саб-агентов — на нативном возврате Task (в БД не тащим).

Действия исполняются через колбэки сервера (inject_cb / notify_cb) — модуль не
знает про сессии/hub напрямую (слабая связанность).

Типы расписания (kind):
  - cron     — 5-полей "m h dom month dow" (dow 0-6, 0=вс; 7 тоже вс), локальное время;
  - interval — spec = секунды (float), для суб-минутных «каждые N сек»;
  - once     — spec = epoch-время (float); сработал → выключается.

Пропущенные запуски (Ёжик лежал): catch_up=1 → сработать ОДИН раз на старте и
поехать дальше; catch_up=0 → перемотать next_run в будущее без выполнения.
"""

from __future__ import annotations

import asyncio
import json
import math
import shutil
import sqlite3
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Awaitable, Callable

import structlog

from .ids import new_ulid

log = structlog.get_logger("scheduler")

# Порог инлайна артефакта: больше — пишем файлом, в БД только путь (ref).
_INLINE_MAX = 8 * 1024
# Потолок задач на чат — защита от заглючившего агента, плодящего расписания.
_MAX_JOBS_PER_CHAT = 100
# M4: сколько последних запусков хранить на задачу (job_runs растут бесконечно).
_JOB_RUNS_KEEP = 50
# M5: нижняя граница interval. spec=0/отрицательный давал next_run в прошлом →
# next_run не продвигался → срабатывание на КАЖДОМ тике петли (busy-loop). Петля
# тикает раз в 1с, поэтому < 1с бессмысленно (всё равно не чаще тика); 1с —
# документированный «суб-минутный» минимум. Блокируем именно 0/отрицательные.
_MIN_INTERVAL_SEC = 1.0

_SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY,
    chat_id TEXT NOT NULL,
    created_by TEXT,
    created_at REAL,
    kind TEXT NOT NULL,            -- 'cron' | 'interval' | 'once'
    spec TEXT NOT NULL,            -- cron-строка | секунды | epoch
    action TEXT NOT NULL,          -- 'inject_text' | 'notify'
    payload TEXT,                  -- JSON
    enabled INTEGER DEFAULT 1,
    catch_up INTEGER DEFAULT 1,
    next_run REAL,
    last_run REAL
);
CREATE INDEX IF NOT EXISTS ix_jobs_due ON jobs(enabled, next_run);
CREATE INDEX IF NOT EXISTS ix_jobs_chat ON jobs(chat_id);

CREATE TABLE IF NOT EXISTS job_runs (
    id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL,
    ts REAL,
    status TEXT,                   -- 'ok' | 'error'
    detail TEXT
);
CREATE INDEX IF NOT EXISTS ix_runs_job ON job_runs(job_id, ts);

CREATE TABLE IF NOT EXISTS artifacts (
    id TEXT PRIMARY KEY,
    chat_id TEXT NOT NULL,
    agent_id TEXT,
    task_id TEXT,
    kind TEXT,                     -- 'result' | 'note' | 'intermediate'
    summary TEXT,                  -- короткое, его тянет главный агент
    ref TEXT,                      -- путь к файлу для БОЛЬШИХ данных
    data TEXT,                     -- инлайн для мелких (иначе ref)
    status TEXT,
    ts REAL
);
CREATE INDEX IF NOT EXISTS ix_art_chat ON artifacts(chat_id, ts);
CREATE INDEX IF NOT EXISTS ix_art_task ON artifacts(task_id);
CREATE INDEX IF NOT EXISTS ix_art_agent ON artifacts(agent_id);
"""


# ---------------------------------------------------------------- cron -------

def _parse_field(expr: str, lo: int, hi: int) -> set[int]:
    """Одно поле cron → множество допустимых значений. Поддержка *, */n, a-b, a,b."""
    vals: set[int] = set()
    for part in expr.split(","):
        part = part.strip()
        step = 1
        if "/" in part:
            part, s = part.split("/", 1)
            step = int(s)
        if part in ("*", ""):
            a, b = lo, hi
        elif "-" in part:
            x, y = part.split("-", 1)
            a, b = int(x), int(y)
        else:
            a = b = int(part)
        for v in range(a, b + 1, max(1, step)):
            if lo <= v <= hi:
                vals.add(v)
    return vals


def _cron_next(expr: str, after: datetime) -> datetime:
    """Ближайший момент ПОСЛЕ `after`, подходящий под 5-полей cron (локальное время)."""
    parts = expr.split()
    if len(parts) != 5:
        raise ValueError("cron must have 5 fields: m h dom month dow")
    minutes = _parse_field(parts[0], 0, 59)
    hours = _parse_field(parts[1], 0, 23)
    doms = _parse_field(parts[2], 1, 31)
    months = _parse_field(parts[3], 1, 12)
    dows = {0 if d == 7 else d for d in _parse_field(parts[4], 0, 7)}
    dom_restricted = parts[2].strip() != "*"
    dow_restricted = parts[4].strip() != "*"

    t = after.replace(second=0, microsecond=0) + timedelta(minutes=1)
    for _ in range(366 * 24 * 60):     # потолок поиска — год
        if t.minute in minutes and t.hour in hours and t.month in months:
            # cron dow: вс=0..сб=6; python weekday(): пн=0..вс=6 → сдвиг.
            cron_dow = (t.weekday() + 1) % 7
            dom_ok = t.day in doms
            dow_ok = cron_dow in dows
            # Стандартная семантика: если ограничены ОБА (dom и dow) — matched по
            # ЛЮБОМУ; иначе по заданному.
            if dom_restricted and dow_restricted:
                if dom_ok or dow_ok:
                    return t
            elif dom_restricted:
                if dom_ok:
                    return t
            elif dow_restricted:
                if dow_ok:
                    return t
            else:
                return t
        t += timedelta(minutes=1)
    raise ValueError("no cron match within a year")


def _compute_next(kind: str, spec: str, after_ts: float) -> float | None:
    """Следующий next_run (epoch) для расписания. None → расписание исчерпано (once)."""
    if kind == "cron":
        return _cron_next(spec, datetime.fromtimestamp(after_ts)).timestamp()
    if kind == "interval":
        secs = float(spec)
        if not math.isfinite(secs):    # nan/inf → пусть _claim_due отключит задачу
            raise ValueError("interval spec not finite")
        # M5: клампим на случай уже сохранённой в БД слишком малой величины —
        # петля не должна крутить одну задачу каждую секунду.
        return after_ts + max(secs, _MIN_INTERVAL_SEC)
    if kind == "once":
        return None                    # once не повторяется
    raise ValueError(f"unknown kind: {kind}")


def _initial_next(kind: str, spec: str, now_ts: float) -> float:
    """next_run при создании задачи."""
    if kind == "once":
        v = float(spec)                # epoch момента срабатывания
        # S4: nan/inf → next_run никогда не сработает, но займёт слот из лимита
        # на чат (как и interval-ветка ниже, где проверка уже есть).
        if not math.isfinite(v):
            raise ValueError("once timestamp must be a finite number")
        return v
    if kind == "cron":
        return _cron_next(spec, datetime.fromtimestamp(now_ts)).timestamp()
    if kind == "interval":
        secs = float(spec)
        # M5: `not (secs >= MIN)` заодно отсекает nan; отдельно inf (никогда не
        # выстрелит, но займёт слот из лимита на чат).
        if not math.isfinite(secs) or not (secs >= _MIN_INTERVAL_SEC):
            raise ValueError(f"interval must be a finite number ≥ {_MIN_INTERVAL_SEC:g}s")
        return now_ts + secs
    raise ValueError(f"unknown kind: {kind}")


# Планировщик зовёт inject позиционно (chat_id, text); реальный
# server.inject_message принимает ещё sender=/interrupt= (дефолты сохраняют
# cron-поведение) и возвращает (ok, info), который планировщик игнорирует
# (§roster). Аннотация отражает фактический контракт.
InjectCb = Callable[..., Awaitable[Any]]
NotifyCb = Callable[[str, str, str], Awaitable[None]]
# §defer: отложенное сообщение пользователя (chat, text, attachments, job_id).
# job_id уходит в эхо — клиент снимает по нему pending-чип на всех устройствах.
InjectUserCb = Callable[[str, str, list, str], Awaitable[None]]


class DeferPendingExists(Exception):
    """§defer: в чате уже есть отложенное сообщение (лимит 1)."""


class SchedulerService:
    def __init__(self, db_path: Path, artifacts_dir: Path,
                 inject_cb: InjectCb, notify_cb: NotifyCb,
                 inject_user_cb: InjectUserCb | None = None):
        self._db_path = Path(db_path)
        self._artifacts_dir = Path(artifacts_dir)
        self._inject = inject_cb
        self._notify = notify_cb
        self._inject_user = inject_user_cb
        self._conn: sqlite3.Connection | None = None
        self._dblock = threading.Lock()          # сериализуем доступ к соединению
        self._loop_task: asyncio.Task | None = None
        self._running: set[str] = set()          # job_id, чьё действие сейчас идёт
        # L: держим ссылки на fire-and-forget _fire-задачи — иначе GC может
        # собрать их до завершения, а stop() закрыл бы БД под идущим _fire
        # (обращение к закрытому соединению).
        self._fire_tasks: set[asyncio.Task] = set()

    # --- жизненный цикл ---------------------------------------------------

    async def start(self) -> None:
        await asyncio.to_thread(self._init_db)
        await asyncio.to_thread(self._reconcile_on_start)
        self._loop_task = asyncio.create_task(self._run_loop())
        log.info("sched.start", db=str(self._db_path))

    async def stop(self) -> None:
        if self._loop_task:
            self._loop_task.cancel()
            await asyncio.gather(self._loop_task, return_exceptions=True)
            self._loop_task = None
        # Гасим in-flight _fire. ВАЖНО: отмена задачи, висящей на
        # `await asyncio.to_thread(<db op>)`, поднимает CancelledError СРАЗУ, а
        # сама DB-операция продолжает крутиться в потоке detached → gather её НЕ
        # дожидается. Поэтому закрываем БД ПОД _dblock (_close_db): лок держат
        # detached-потоки на время своей операции, close() их дождётся.
        if self._fire_tasks:
            for t in list(self._fire_tasks):
                t.cancel()
            await asyncio.gather(*self._fire_tasks, return_exceptions=True)
        if self._conn is not None:
            await asyncio.to_thread(self._close_db)
            self._conn = None

    def _close_db(self) -> None:
        # Под локом: ждём detached DB-операцию отменённого _fire, потом закрываем
        # (поток, схвативший лок уже ПОСЛЕ close, молча получит ProgrammingError —
        # приемлемо на shutdown).
        with self._dblock:
            self._conn.close()

    def _init_db(self) -> None:
        self._artifacts_dir.mkdir(parents=True, exist_ok=True)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._dblock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    def _reconcile_on_start(self) -> None:
        """Перемотать next_run для catch_up=0 задач, чей срок прошёл, — без запуска.
        Задачи catch_up=1 оставляем: петля выполнит их один раз (догон)."""
        now = time.time()
        with self._dblock:
            rows = self._conn.execute(
                "SELECT * FROM jobs WHERE enabled=1 AND catch_up=0 AND next_run<=?",
                (now,)).fetchall()
            for r in rows:
                try:
                    nxt = _compute_next(r["kind"], r["spec"], now)
                except Exception as e:
                    log.warning("sched.reconcile_bad", job=r["id"], err=str(e))
                    nxt = None
                if nxt is None:
                    self._conn.execute("UPDATE jobs SET enabled=0 WHERE id=?", (r["id"],))
                else:
                    self._conn.execute("UPDATE jobs SET next_run=? WHERE id=?",
                                       (nxt, r["id"]))
            self._conn.commit()

    # --- петля ------------------------------------------------------------

    async def _run_loop(self) -> None:
        while True:
            try:
                jobs = await asyncio.to_thread(self._claim_due, time.time())
                for job in jobs:
                    t = asyncio.create_task(self._fire(job))
                    self._fire_tasks.add(t)          # L: ссылка (GC) + ждём в stop()
                    t.add_done_callback(self._fire_tasks.discard)
            except asyncio.CancelledError:
                raise
            except Exception as e:                # петля не должна умирать
                log.warning("sched.loop_error", err=str(e))
            await asyncio.sleep(1.0)

    def _claim_due(self, now: float) -> list[dict]:
        """Атомарно (под локом) забрать созревшие задачи и СРАЗУ перемотать их
        next_run вперёд (или выключить once) — чтобы следующий тик не сработал
        повторно, даже если действие идёт медленно."""
        claimed: list[dict] = []
        with self._dblock:
            rows = self._conn.execute(
                "SELECT * FROM jobs WHERE enabled=1 AND next_run<=? ORDER BY next_run",
                (now,)).fetchall()
            dirty = False
            for r in rows:
                if r["id"] in self._running:
                    continue             # предыдущий запуск ещё идёт — пропускаем
                bad = False
                try:
                    nxt = _compute_next(r["kind"], r["spec"], now)
                except Exception as e:
                    log.warning("sched.next_bad", job=r["id"], err=str(e))
                    nxt = None
                    bad = True           # S4: невалидный spec (исключение расчёта)
                if nxt is None:
                    self._conn.execute(
                        "UPDATE jobs SET enabled=0, last_run=? WHERE id=?",
                        (now, r["id"]))
                    dirty = True
                    if bad:
                        # S4: recurring с битым spec выключаем и НЕ стреляем (раньше
                        # был один последний запуск с невалидным расписанием). Для
                        # once nxt=None — штатно (bad=False), задача срабатывает.
                        continue
                else:
                    self._conn.execute(
                        "UPDATE jobs SET next_run=?, last_run=? WHERE id=?",
                        (nxt, now, r["id"]))
                    dirty = True
                claimed.append(dict(r))
            if dirty:
                self._conn.commit()
        return claimed

    async def _fire(self, job: dict) -> None:
        jid = job["id"]
        self._running.add(jid)
        try:
            payload = json.loads(job["payload"] or "{}")
            action = job["action"]
            chat_id = job["chat_id"]
            if action == "inject_text":
                # S1: _inject возвращает (ok, info) — раньше игнорировали, и
                # недоставка (чат удалён/сменил addressee/пустой текст) писалась
                # в job_runs как ok. Теперь отражаем реальный исход.
                ok, info = await self._inject(chat_id, str(payload.get("text", "")))
                if not ok:
                    await asyncio.to_thread(self._record_run, jid, "error",
                                            str(info)[:300])
                    log.warning("sched.inject_failed", job=jid, chat=chat_id,
                                reason=str(info)[:120])
                    return
            elif action == "inject_user":
                # §defer: отложенное сообщение пользователя (текст + вложения).
                if self._inject_user is None:
                    raise ValueError("inject_user callback not configured")
                atts = payload.get("attachments") or []
                await self._inject_user(chat_id, str(payload.get("text", "")),
                                        atts if isinstance(atts, list) else [],
                                        jid)
            elif action in ("notify", "remind"):
                ok = await self._notify(chat_id, str(payload.get("title", "")),
                                        str(payload.get("body", "")))
                if ok is False:          # S1: чата нет — не рапортуем успех
                    await asyncio.to_thread(self._record_run, jid, "error",
                                            "chat not found")
                    log.warning("sched.notify_failed", job=jid, chat=chat_id)
                    return
            else:
                raise ValueError(f"unknown action: {action}")
            await asyncio.to_thread(self._record_run, jid, "ok", action)
            log.info("sched.fired", job=jid, action=action, chat=chat_id)
        except Exception as e:
            await asyncio.to_thread(self._record_run, jid, "error", str(e)[:300])
            log.warning("sched.fire_error", job=jid, err=str(e))
        finally:
            self._running.discard(jid)

    def _record_run(self, job_id: str, status: str, detail: str) -> None:
        with self._dblock:
            # S5: пишем историю ТОЛЬКО если задача ещё существует — иначе purge
            # между claim и _record_run оставлял бы сиротскую строку job_runs.
            self._conn.execute(
                "INSERT INTO job_runs(id, job_id, ts, status, detail) "
                "SELECT ?,?,?,?,? WHERE EXISTS (SELECT 1 FROM jobs WHERE id=?)",
                (new_ulid(), job_id, time.time(), status, detail, job_id))
            # M4: retention — держим только последние _JOB_RUNS_KEEP на задачу,
            # иначе история запусков частой interval-задачи растёт неограниченно.
            self._conn.execute(
                "DELETE FROM job_runs WHERE job_id=? AND id NOT IN ("
                "SELECT id FROM job_runs WHERE job_id=? "
                "ORDER BY ts DESC, id DESC LIMIT ?)",
                (job_id, job_id, _JOB_RUNS_KEEP))
            self._conn.commit()

    # --- API расписаний (зовётся из MCP-тулов) ----------------------------

    async def add_job(self, *, chat_id: str, kind: str, spec: str, action: str,
                      payload: dict, catch_up: bool = True,
                      created_by: str = "agent") -> str:
        return await asyncio.to_thread(
            self._add_job_sync, chat_id, kind, spec, action, payload,
            catch_up, created_by)

    def _add_job_sync(self, chat_id, kind, spec, action, payload, catch_up,
                      created_by) -> str:
        if kind not in ("cron", "interval", "once"):
            raise ValueError("kind must be cron|interval|once")
        if action not in ("inject_text", "notify", "remind", "inject_user"):
            raise ValueError("action must be inject_text|notify|remind|inject_user")
        # M5: inject_user — только пользовательский §defer (wss, created_by=user).
        # Иначе агент через MCP schedule_add занял бы единственный defer-слот чата
        # (или впрыснул бы себе сообщение под видом пользователя).
        if action == "inject_user" and created_by != "user":
            raise ValueError("inject_user reserved for user deferred messages")
        now = time.time()
        next_run = _initial_next(kind, spec, now)   # валидирует spec
        jid = new_ulid()
        with self._dblock:
            (cnt,) = self._conn.execute(
                "SELECT COUNT(*) FROM jobs WHERE chat_id=? AND enabled=1",
                (chat_id,)).fetchone()
            if cnt >= _MAX_JOBS_PER_CHAT:
                raise ValueError(f"job limit reached ({_MAX_JOBS_PER_CHAT} per chat)")
            # §defer: лимит 1 отложенное сообщение на чат — проверка ПОД локом
            # (иначе два устройства пролезут одновременно). Спец-исключение —
            # wss-слой маппит его в отдельный ответ клиенту.
            if action == "inject_user":
                (pend,) = self._conn.execute(
                    "SELECT COUNT(*) FROM jobs WHERE chat_id=? AND "
                    "action='inject_user' AND enabled=1", (chat_id,)).fetchone()
                if pend > 0:
                    raise DeferPendingExists(
                        "one deferred message per chat already pending")
            self._conn.execute(
                "INSERT INTO jobs(id, chat_id, created_by, created_at, kind, spec, "
                "action, payload, enabled, catch_up, next_run, last_run) "
                "VALUES(?,?,?,?,?,?,?,?,1,?,?,NULL)",
                (jid, chat_id, created_by, now, kind, str(spec), action,
                 json.dumps(payload), 1 if catch_up else 0, next_run))
            self._conn.commit()
        return jid

    async def list_jobs(self, chat_id: str) -> list[dict]:
        return await asyncio.to_thread(self._list_jobs_sync, chat_id)

    def _list_jobs_sync(self, chat_id: str) -> list[dict]:
        with self._dblock:
            rows = self._conn.execute(
                "SELECT id, kind, spec, action, payload, enabled, next_run, last_run "
                "FROM jobs WHERE chat_id=? ORDER BY next_run", (chat_id,)).fetchall()
        return [dict(r) for r in rows]

    async def cancel_job(self, job_id: str, chat_id: str,
                         action: str | None = None) -> bool:
        return await asyncio.to_thread(
            self._cancel_job_sync, job_id, chat_id, action)

    async def purge_chat(self, chat_id: str) -> int:
        """Удалить ВСЕ задания чата (при delete_chat) — иначе осиротевший job
        выстрелит в несуществующий чат. Возвращает число удалённых."""
        return await asyncio.to_thread(self._purge_chat_sync, chat_id)

    def _purge_chat_sync(self, chat_id: str) -> int:
        with self._dblock:
            # M4: чистим ВСЁ, привязанное к чату — иначе после delete_chat
            # остаются сироты. job_runs (нет FK cascade) удаляем ДО jobs по их id.
            self._conn.execute(
                "DELETE FROM job_runs WHERE job_id IN "
                "(SELECT id FROM jobs WHERE chat_id=?)", (chat_id,))
            cur = self._conn.execute(
                "DELETE FROM jobs WHERE chat_id=?", (chat_id,))
            self._conn.execute(
                "DELETE FROM artifacts WHERE chat_id=?", (chat_id,))
            self._conn.commit()
            removed = cur.rowcount
        # Файлы больших артефактов чата — вне лока (FS-I/O). chat_id = ULID
        # (безопасное имя каталога).
        shutil.rmtree(self._artifacts_dir / chat_id, ignore_errors=True)
        return removed

    def _cancel_job_sync(self, job_id: str, chat_id: str,
                         action: str | None = None) -> bool:
        with self._dblock:
            # §defer гонка D: только ещё НЕ сработавшее (enabled=1). Если
            # планировщик уже заклеймил задание (_claim_due → enabled=0), отмена
            # вернёт False — «поздно, уже отправляется», ход не оборвать.
            # action-фильтр: клиентский cancel_scheduled удаляет ТОЛЬКО свои
            # inject_user-задания, не агентские cron/interval.
            if action is not None:
                cur = self._conn.execute(
                    "DELETE FROM jobs WHERE id=? AND chat_id=? AND enabled=1 "
                    "AND action=?", (job_id, chat_id, action))
            else:
                cur = self._conn.execute(
                    "DELETE FROM jobs WHERE id=? AND chat_id=? AND enabled=1",
                    (job_id, chat_id))
            if cur.rowcount > 0:      # M4: не оставляем историю удалённой задачи
                self._conn.execute(
                    "DELETE FROM job_runs WHERE job_id=?", (job_id,))
            self._conn.commit()
            return cur.rowcount > 0

    # --- API блэкборда (зовётся из MCP-тулов) -----------------------------

    async def put_artifact(self, *, chat_id: str, kind: str, summary: str,
                           data: str = "", agent_id: str = "",
                           task_id: str = "") -> str:
        return await asyncio.to_thread(
            self._put_artifact_sync, chat_id, kind, summary, data, agent_id, task_id)

    def _put_artifact_sync(self, chat_id, kind, summary, data, agent_id,
                           task_id) -> str:
        aid = new_ulid()
        ref = None
        inline = data
        if data and len(data.encode("utf-8")) > _INLINE_MAX:
            # Большие данные — файлом; в БД только путь.
            d = self._artifacts_dir / chat_id
            d.mkdir(parents=True, exist_ok=True)
            fp = d / f"{aid}.txt"
            fp.write_text(data, encoding="utf-8")
            ref = str(fp)
            inline = None
        with self._dblock:
            self._conn.execute(
                "INSERT INTO artifacts(id, chat_id, agent_id, task_id, kind, "
                "summary, ref, data, status, ts) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (aid, chat_id, agent_id or None, task_id or None, kind or "result",
                 summary, ref, inline, "stored", time.time()))
            self._conn.commit()
        return aid

    async def get_artifact(self, artifact_id: str) -> dict | None:
        return await asyncio.to_thread(self._get_artifact_sync, artifact_id)

    def _get_artifact_sync(self, artifact_id: str) -> dict | None:
        with self._dblock:
            r = self._conn.execute(
                "SELECT * FROM artifacts WHERE id=?", (artifact_id,)).fetchone()
        if r is None:
            return None
        out = dict(r)
        if out.get("ref") and not out.get("data"):
            try:
                out["data"] = Path(out["ref"]).read_text(encoding="utf-8")
            except OSError as e:
                out["data"] = f"[ref unreadable: {e}]"
        return out

    async def list_artifacts(self, *, chat_id: str, task_id: str = "",
                             agent_id: str = "", kind: str = "",
                             limit: int = 50) -> list[dict]:
        return await asyncio.to_thread(
            self._list_artifacts_sync, chat_id, task_id, agent_id, kind, limit)

    def _list_artifacts_sync(self, chat_id, task_id, agent_id, kind,
                             limit) -> list[dict]:
        q = "SELECT id, chat_id, agent_id, task_id, kind, summary, ts FROM artifacts WHERE chat_id=?"
        args: list[Any] = [chat_id]
        if task_id:
            q += " AND task_id=?"; args.append(task_id)
        if agent_id:
            q += " AND agent_id=?"; args.append(agent_id)
        if kind:
            q += " AND kind=?"; args.append(kind)
        q += " ORDER BY ts DESC LIMIT ?"; args.append(int(limit))
        with self._dblock:
            rows = self._conn.execute(q, args).fetchall()
        return [dict(r) for r in rows]
