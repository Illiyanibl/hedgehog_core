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


class Hub:
    def __init__(self, store: ChatStore):
        self._store = store
        # conn_id → (send, множество подписанных chatId)
        self._conns: dict[int, tuple[SendFn, set[str]]] = {}
        self._next_conn_id = 1

    # ---------- соединения ----------

    def register(self, send: SendFn) -> int:
        conn_id = self._next_conn_id
        self._next_conn_id += 1
        self._conns[conn_id] = (send, set())
        log.info("conn.register", conn_id=conn_id, total=len(self._conns))
        return conn_id

    def unregister(self, conn_id: int):
        self._conns.pop(conn_id, None)
        log.info("conn.unregister", conn_id=conn_id, total=len(self._conns))

    def subscribe(self, conn_id: int, chat_id: str):
        if conn_id in self._conns:
            self._conns[conn_id][1].add(chat_id)

    def unsubscribe(self, conn_id: int, chat_id: str):
        if conn_id in self._conns:
            self._conns[conn_id][1].discard(chat_id)

    def has_subscribers(self, chat_id: str) -> bool:
        return any(chat_id in subs for _, subs in self._conns.values())

    # ---------- публикация ----------

    # Типы, которые НЕ пишем в постоянный транскрипт: снапшоты экрана
    # перерисовываются десятки раз/сек — это шум для наблюдения задним числом
    # (у shell-чатов уже есть plain-text transcript.log от HistoryWriter).
    _TRANSCRIPT_SKIP = {"screen_snapshot"}

    async def publish(self, chat_id: str, ftype: str, payload: dict[str, Any],
                      journal: bool = True) -> dict:
        """Событие чата: журнал + постоянный транскрипт + рассылка подписчикам."""
        frame = make_frame(ftype, payload, chat_id)
        if journal:
            try:
                self._store.append_pending(chat_id, frame)
            except OSError as e:
                # Чат могли удалить под ногами — событие только в сокеты.
                log.warning("journal.append_failed", chat_id=chat_id, err=str(e))
            if ftype not in self._TRANSCRIPT_SKIP:
                self._store.append_transcript(chat_id, frame)
        await self._fanout(chat_id, frame)
        return frame

    async def send_global(self, conn_id: int, frame: dict):
        """Системный фрейм (hello, chat_list, pong, error) одному соединению."""
        entry = self._conns.get(conn_id)
        if entry:
            await self._safe_send(conn_id, entry[0], frame)

    async def broadcast_global(self, frame: dict):
        """Системная нотификация всем соединениям (chat_created и т.п.)."""
        for conn_id, (send, _) in list(self._conns.items()):
            await self._safe_send(conn_id, send, frame)

    async def _fanout(self, chat_id: str, frame: dict):
        for conn_id, (send, subs) in list(self._conns.items()):
            if chat_id in subs:
                await self._safe_send(conn_id, send, frame)

    async def _safe_send(self, conn_id: int, send: SendFn, frame: dict):
        try:
            await send(frame)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            # Обрыв WS одного подписчика не должен ронять publish()
            # у сессии — соединение снимет себя само в handler'е.
            log.info("send.failed", conn_id=conn_id, err=str(e))
