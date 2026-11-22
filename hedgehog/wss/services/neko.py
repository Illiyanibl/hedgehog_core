"""NekoController: install/get/remove neko и neko_open_view (§17).

Вынесено из HedgehogServer (wss/server.py) без изменения поведения и протокола:
фоновые install/remove (single-flight, вне цикла кадров соединения), кадр
neko_result и серверный ленивый NekoProxy для neko_open_view.

Хост (сервер, см. services/base.NekoHost) передаётся в конструктор. Его
методы зовём как ``self.host._x(...)`` в момент вызова; config/hub —
property-прокси на хост. wss.server не импортируем.
"""

from __future__ import annotations

import asyncio

import structlog

from ...protocol import Err, make_error, make_frame
from ... import i18n
from .base import NekoHost

log = structlog.get_logger("wss")


class NekoController:
    def __init__(self, host: NekoHost):
        self.host = host
        # §17: ленивый серверный NekoProxy (MCP-плейн neko) для neko_open_view —
        # создаётся при первом использовании, гасится в shutdown. Глобальный (не
        # per-chat): фрейм без chatId, shared-browser-context терпит неск. сессий.
        self._neko_proxy = None
        # §17/§cancel: install_neko/remove_neko — фоновые задачи (single-flight),
        # НЕ в цикле кадров соединения: иначе provision (pull 15-25 мин) держал
        # бы ping/subscribe/user_msg этого соединения. Ссылки держим (GC).
        self._neko_install_task: asyncio.Task | None = None
        self._neko_remove_task: asyncio.Task | None = None

    # Прокси на хост: перенесённый код обращается к self.config/hub как раньше.
    @property
    def config(self):
        return self.host.config

    @property
    def hub(self):
        return self.host.hub

    def cancel_jobs(self) -> None:
        # §17: фоновые install/remove neko — снимаем задачи (часть
        # HedgehogServer.shutdown). Поток to_thread не отменить, а asyncio.run
        # ждёт его на выходе → идущий docker pull прерываем флагом.
        if self._neko_install_task is not None and not self._neko_install_task.done():
            from ... import neko
            neko.cancel_provision()
        for t in (self._neko_install_task, self._neko_remove_task):
            if t is not None and not t.done():
                t.cancel()

    async def shutdown(self) -> None:
        if self._neko_proxy is not None:   # §17: догасить серверный MCP-проброс neko
            await self._neko_proxy.aclose()

    @staticmethod
    def _neko_frame(result) -> dict:
        return make_frame("neko_result", {
            "ok": result.ok,
            "status": result.status,
            "message": result.message,
            "https_port": result.https_port,
            "user_password": result.user_password,
            "server_ip": result.server_ip,
            "mcp_port": result.mcp_port,
            "ai_control": result.ai_control,
            "stage": result.stage,
        })

    async def _h_install_neko(self, conn_id, frame, p):
        ftype = frame.type
        # §17: Neko-браузер. Авторизация — тем же токеном, что WS (без SSH).
        # install/remove — долгий блокирующий docker I/O → ФОНОВАЯ задача
        # (to_thread внутри), цикл кадров соединения сразу свободен (ping/
        # subscribe/user_msg не ждут pull). Итог install/remove рассылается
        # ВСЕМ соединениям (клиент мог переподключиться за время установки).
        # get_neko — быстрый status() без лока, отвечаем запросившему.
        from ... import neko
        if ftype == "get_neko":
            result = await asyncio.to_thread(neko.status, self.config)
            await self.hub.send_global(conn_id, self._neko_frame(result))
            log.info("neko." + ftype, ok=result.ok, status=result.status)
            return
        install = ftype == "install_neko"
        busy = self._neko_install_task if install else self._neko_remove_task
        if busy is not None and not busy.done():
            # single-flight: повтор (двойной тап/второе устройство) не запускает
            # второй provision/teardown — отвечаем текущим статусом (installing).
            result = await asyncio.to_thread(neko.status, self.config)
            await self.hub.send_global(conn_id, self._neko_frame(result))
            log.info("neko." + ftype + ".already_running", status=result.status)
            return
        # Проверка+взвод атомарны (между ними нет await) — как M4 у update_self.
        task = asyncio.create_task(
            self._neko_job(conn_id, frame.id, ftype,
                           neko.provision if install else neko.teardown),
            name=f"neko-{ftype}")
        if install:
            self._neko_install_task = task
        else:
            self._neko_remove_task = task
        return

    async def _neko_job(self, conn_id, frame_id, ftype, fn):
        """Фон install/remove: поток docker → итог ВСЕМ соединениям."""
        try:
            result = await asyncio.to_thread(fn, self.config)
        except asyncio.CancelledError:
            raise
        except Exception as e:  # noqa: BLE001 — сбой фоновой задачи не теряем
            log.error("neko.job_failed", type=ftype, err=repr(e))
            await self.host._reply_or_broadcast(conn_id, make_error(
                Err.INTERNAL, f"{type(e).__name__}: {e}", related=frame_id))
            return
        await self.hub.broadcast_global(self._neko_frame(result))
        log.info("neko." + ftype, ok=result.ok, status=result.status)

    async def _h_neko_open_view(self, conn_id, frame, p):
        """§17: новая вкладка/окно браузера neko через серверный NekoProxy
        (playwright-mcp `browser_tabs:new`). Если браузер открыт → вкладка в том
        же видимом окне; если был закрыт → held-context мёртв, первый вызов падает,
        ретрай `browser_navigate` поднимает новое окно. Это и есть вся обработка
        open-vs-closed (детекцию не строим — гонка, chromium сам выбирает)."""
        from ... import neko
        url = (p.url or "").strip()
        if url and not url.lower().startswith(("http://", "https://")):
            await self.hub.send_global(conn_id, make_frame(
                "neko_view_result", {"ok": False, "message": "bad url"}))
            return
        # Гейт: контейнер жив И Ёжик подключён к neko-сети (иначе MCP недостижим →
        # иначе 10с handshake-таймаут вместо быстрого отказа).
        if not await asyncio.to_thread(neko.ai_control_available):
            await self.hub.send_global(conn_id, make_frame(
                "neko_view_result", {"ok": False, "message": i18n.Msg("neko.unavailable")}))
            return
        if self._neko_proxy is None:
            from ...core.neko_proxy import NekoProxy
            self._neko_proxy = NekoProxy(
                f"http://{neko.CONTAINER}:{self.config.neko_mcp_port}/mcp")
        def _raise_if_error(res):
            # MCP-ошибки НЕ бросают — приходят CallToolResult(isError=True)
            # (playwright-mcp так рапортует «Target closed» при закрытом окне,
            # ср. ctl_server.py). Трактуем как сбой → уходим в ретрай/отказ.
            if getattr(res, "isError", False):
                txt = "".join(getattr(c, "text", "") or ""
                              for c in (getattr(res, "content", None) or []))
                raise RuntimeError(txt or "neko tool error")
        args = {"action": "new", **({"url": url} if url else {})}
        ok, msg = True, ""
        try:
            _raise_if_error(await self._neko_proxy.call("browser_tabs", args, timeout=20))
        except Exception:   # noqa: BLE001 — окно закрыли (isError) или транспорт
            try:
                _raise_if_error(await self._neko_proxy.call(
                    "browser_navigate", {"url": url or "about:blank"}, timeout=20))
            except Exception as e2:  # noqa: BLE001
                ok, msg = False, f"neko: {e2}"
                log.warning("neko.open_view_failed", err=repr(e2))
        await self.hub.send_global(conn_id, make_frame(
            "neko_view_result", {"ok": ok, "message": msg}))
        log.info("neko.open_view", ok=ok, had_url=bool(url))
        return
