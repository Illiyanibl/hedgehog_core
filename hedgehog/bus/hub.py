"""Hub — шина событий между core-сессиями и WS-соединениями.

Жизненный цикл события server→client (§5.1): сессия зовёт publish() →
append в pending.jsonl → отправка во все подписанные соединения. Если
подписчиков нет, событие просто остаётся в журнале и уедет при resume.

Соединение регистрирует send-callback; подписки — множество chatId на
соединение (§3.6: без подписки события чата по этому соединению не идут,
но в журнал пишутся).
"""

from __future__ import annotations

import asyncio
from typing import Any, Awaitable, Callable

import structlog

from ..protocol import make_frame
from ..store.chats import ChatStore

log = structlog.get_logger("hub")

SendFn = Callable[[dict], Awaitable[None]]
CloseFn = Callable[[], Awaitable[None]]


class Hub:
    def __init__(self, store: ChatStore):
        self._store = store
        # conn_id → (send, множество подписанных chatId)
        self._conns: dict[int, tuple[SendFn, set[str]]] = {}
        # conn_id → deviceId (§push: несекретный id устройства, для per-device
        # маршрутизации пуша). Отдельный dict, чтобы не менять кортеж _conns.
        self._conn_device: dict[int, str] = {}
        # conn_id → close (закрыть WS): backpressure-таймаут не только снимает
        # соединение из шины, но и закрывает сокет — иначе ожившее после столла
        # соединение осталось бы «живым, но глухим» (мы на него не шлём).
        self._conn_close: dict[int, CloseFn] = {}
        self._close_tasks: set[asyncio.Task] = set()   # держим ссылки на fire-and-forget
        self._next_conn_id = 1
        # §publish hot-path: журнальные записи (append pending/transcript, вкл.
        # _shed_pending — перезапись до 100МБ) выносим в поток, чтобы диск-I/O не
        # держал общий event loop. Но порядок записей в ОДИН чат должен
        # сохраняться (resume реплеит по порядку), а в чат параллельно пишут
        # воркер сессии и серверные хендлеры → сериализуем per-chat. asyncio.Lock
        # FIFO + отсутствие await между make_frame и acquire → файл в ULID-порядке.
        self._write_locks: dict[str, asyncio.Lock] = {}

    # ---------- соединения ----------

    def register(self, send: SendFn, close: CloseFn | None = None) -> int:
        conn_id = self._next_conn_id
        self._next_conn_id += 1
        self._conns[conn_id] = (send, set())
        if close is not None:
            self._conn_close[conn_id] = close
        log.info("conn.register", conn_id=conn_id, total=len(self._conns))
        return conn_id

    def unregister(self, conn_id: int):
        self._conns.pop(conn_id, None)
        self._conn_device.pop(conn_id, None)
        self._conn_close.pop(conn_id, None)
        log.info("conn.unregister", conn_id=conn_id, total=len(self._conns))

    def set_device(self, conn_id: int, device_id: str):
        """§push: привязать deviceId к соединению (из фрейма register_push)."""
        if conn_id in self._conns and device_id:
            self._conn_device[conn_id] = device_id

    def subscribe(self, conn_id: int, chat_id: str):
        if conn_id in self._conns:
            self._conns[conn_id][1].add(chat_id)

    def unsubscribe(self, conn_id: int, chat_id: str):
        if conn_id in self._conns:
            self._conns[conn_id][1].discard(chat_id)

    def devices_subscribed(self, chat_id: str) -> set[str]:
        """§push: deviceId устройств с живым соединением, ПОДПИСАННЫМ на этот чат
        (т.е. получат событие напрямую по WS). Соединения без известного deviceId
        не попадают — им пуш не адресуется (у них нет notifyKey в реестре)."""
        out: set[str] = set()
        for conn_id, (_, subs) in self._conns.items():
            if chat_id in subs:
                dev = self._conn_device.get(conn_id)
                if dev:
                    out.add(dev)
        return out

    # ---------- публикация ----------

    # Типы, которые НЕ пишем в постоянный транскрипт: снапшоты экрана
    # перерисовываются десятки раз/сек — это шум для наблюдения задним числом
    # (у shell-чатов уже есть plain-text transcript.log от HistoryWriter).
    _TRANSCRIPT_SKIP = {"screen_snapshot"}
    # S5-H2: screen_snapshot НЕ кладём в pending. Shell гонит до ~12 снапшотов/с;
    # оффлайн-клиент раздул бы pending.jsonl (~90 МБ/час) до hard-cap, после чего
    # каждый append делает shed ~100 МБ синхронно в event loop, а resume реплеит
    # тысячи устаревших кадров. Клиенту нужен только ПОСЛЕДНИЙ экран: живому — по
    # fanout ниже; реконнектнувшемуся сервер шлёт текущий снапшот при subscribe
    # (wss subscribe_chat). transcript и так пропускает snapshot.
    _PENDING_SKIP = {"screen_snapshot"}

    def _write_lock(self, chat_id: str) -> asyncio.Lock:
        lock = self._write_locks.get(chat_id)
        if lock is None:
            lock = asyncio.Lock()
            self._write_locks[chat_id] = lock
        return lock

    def _journal(self, chat_id: str, ftype: str, frame: dict) -> None:
        """Синхронные журнальные записи — исполняются в фоновом потоке (to_thread).
        Порядок per-chat гарантирует lock вызывающего; append в РАЗНЫЕ chat-файлы
        тред-безопасен (отдельные файлы, без общего изменяемого состояния)."""
        if ftype not in self._PENDING_SKIP:
            try:
                self._store.append_pending(chat_id, frame)
            except OSError as e:
                # Чат могли удалить под ногами — событие только в сокеты.
                log.warning("journal.append_failed", chat_id=chat_id, err=str(e))
        if ftype not in self._TRANSCRIPT_SKIP:
            self._store.append_transcript(chat_id, frame)

    async def publish(self, chat_id: str, ftype: str, payload: dict[str, Any],
                      journal: bool = True) -> dict:
        """Событие чата: журнал + постоянный транскрипт + рассылка подписчикам."""
        frame = make_frame(ftype, payload, chat_id)
        # Фреймы, пропускаемые ОБОИМИ журналами (snapshot, ~12/с в shell-чате),
        # не берут lock и не прыгают в поток — у них нет претензии на порядок
        # файлов, иначе они копились бы за идущим _shed_pending (до ~100МБ).
        if journal and (ftype not in self._PENDING_SKIP
                        or ftype not in self._TRANSCRIPT_SKIP):
            # Сериализуем журнал чата и выносим его в поток: _shed_pending и
            # обычный append больше не держат общий loop; порядок — под per-chat
            # lock. fanout — ПОСЛЕ (инвариант §5.1 «журнал до отправки»).
            async with self._write_lock(chat_id):
                await asyncio.to_thread(self._journal, chat_id, ftype, frame)
        delivered = await self._fanout(chat_id, frame)
        # §obs: кадр сгенерён, но подписчиков нет → лёг только в журнал (уедет
        # на resume). Рост таких строк = очередь копится (клиент отвалился/в фоне).
        if journal and delivered == 0 and ftype not in self._TRANSCRIPT_SKIP:
            log.info("publish.journaled_only", chat_id=chat_id, type=ftype,
                     id=frame.get("id", "")[-6:])
        return frame

    async def ack(self, chat_id: str, last_seen_id: str) -> None:
        """§5.1 шаг 6: подрезать pending. ПОД ТЕМ ЖЕ per-chat lock, что и журнал:
        иначе ack-rewrite (read → tmp+replace = НОВЫЙ inode) гонялся бы с append в
        потоке (open("a") держит СТАРЫЙ inode) → добавленная строка ушла бы в
        осиротевший inode и пропала для оффлайн-устройства. Сам rewrite (до ~100МБ)
        — тот же класс loop-блокирующего I/O, тоже в поток."""
        async with self._write_lock(chat_id):
            await asyncio.to_thread(self._store.ack, chat_id, last_seen_id)

    # M(backpressure): медленный/зависший подписчик (полный TCP-буфер, ушёл в
    # фон без чтения) не должен держать publish и блокировать доставку остальным.
    # Каждый send ограничен таймаутом; по нему соединение снимается (его
    # handler-loop доснимет себя сам). Fanout идёт КОНКУРЕНТНО, чтобы один
    # тормозящий сокет не сериализовал доставку всем прочим.
    _SEND_TIMEOUT = 15.0

    async def send_global(self, conn_id: int, frame: dict):
        """Системный фрейм (hello, chat_list, pong, error) одному соединению."""
        entry = self._conns.get(conn_id)
        if entry:
            await self._safe_send(conn_id, entry[0], frame)

    async def broadcast_global(self, frame: dict):
        """Системная нотификация всем соединениям (chat_created и т.п.)."""
        targets = list(self._conns.items())
        if targets:
            await asyncio.gather(*(self._safe_send(cid, send, frame)
                                   for cid, (send, _) in targets))

    async def _fanout(self, chat_id: str, frame: dict) -> int:
        targets = [(cid, send) for cid, (send, subs) in list(self._conns.items())
                   if chat_id in subs]
        if targets:
            # gather: зависший подписчик не задержит доставку остальным (его send
            # отвалится по таймауту в _safe_send). delivered = число адресатов
            # (как и раньше — считали попытки; _safe_send глотает сбои сам).
            await asyncio.gather(*(self._safe_send(cid, send, frame)
                                   for cid, send in targets))
        return len(targets)

    async def _safe_send(self, conn_id: int, send: SendFn, frame: dict):
        try:
            await asyncio.wait_for(send(frame), self._SEND_TIMEOUT)
        except asyncio.CancelledError:
            raise
        except asyncio.TimeoutError:
            # Клиент не вычитывает (завис/полный буфер) — не держим шину, снимаем
            # соединение И закрываем сокет. Без close ожившее после столла
            # соединение остаётся открытым (keepalive доволен), но из шины
            # выкинуто → «живой, но глухой» зомби. close захватываем ДО unregister
            # (он его снимет); закрываем фоном — ws.close сам ограничен таймаутом.
            log.warning("send.timeout", conn_id=conn_id)
            close = self._conn_close.get(conn_id)
            self.unregister(conn_id)
            if close is not None:
                task = asyncio.create_task(self._close_quietly(conn_id, close))
                self._close_tasks.add(task)
                task.add_done_callback(self._close_tasks.discard)
        except Exception as e:
            # Обрыв WS одного подписчика не должен ронять publish()
            # у сессии — соединение снимет себя само в handler'е.
            log.info("send.failed", conn_id=conn_id, err=str(e))

    async def _close_quietly(self, conn_id: int, close: CloseFn):
        try:
            await close()
        except Exception as e:  # noqa: BLE001 — закрытие не должно всплывать
            log.info("close.failed", conn_id=conn_id, err=str(e))

    async def aclose(self):
        """Shutdown: погасить фоновые close-задачи (backpressure-таймаут), иначе
        на выходе возможен «Task was destroyed but it is pending»."""
        if self._close_tasks:
            for t in list(self._close_tasks):
                t.cancel()
            await asyncio.gather(*self._close_tasks, return_exceptions=True)
