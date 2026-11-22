"""UpdateController: update_self — git pull своего исходника + рестарт (§15).

Вынесено из HedgehogServer (wss/server.py) без изменения поведения и протокола:
single-flight (M4), фоновая задача вне цикла кадров соединения, рестарт с
удержанием ссылки на задачу (L). Здесь же SERVER_COMMIT (сервер реэкспортирует
его для hello).

Хост (сервер, см. services/base.UpdateHost) передаётся в конструктор. Его
методы зовём как ``self.host._x(...)`` в момент вызова; hub — property-прокси
на хост. wss.server не импортируем.
"""

from __future__ import annotations

import asyncio

import structlog

from ...protocol import Err, make_error, make_frame
from ... import i18n
from ... import updater
from .base import UpdateHost

log = structlog.get_logger("wss")

# §update: короткий SHA HEAD этого процесса — клиент сравнивает его с последним
# коммитом репозитория (GitHub) и предлагает «Обновить». Меняется только при
# рестарте после update_self (git reset --hard), поэтому кэшируем один раз.
SERVER_COMMIT = updater.current_sha()


class UpdateController:
    def __init__(self, host: UpdateHost):
        self.host = host
        # L: держим ссылку на задачу рестарта — иначе GC мог бы её собрать до
        # execv (update вернул ok, а рестарта нет).
        self._restart_task: asyncio.Task | None = None
        # M4: update_self в полёте — второй вызов (двойной тап/второе устройство)
        # не должен запустить 2× git reset/pip/execv. Латчится при запланированном
        # рестарте (процесс вот-вот сменится — новых обновлений не начинаем).
        self._updating = False
        # §15: фоновый update_self (тоже вне цикла кадров соединения).
        self._update_task: asyncio.Task | None = None

    # Прокси на хост: перенесённый код обращается к self.hub как раньше.
    @property
    def hub(self):
        return self.host.hub

    def cancel_jobs(self) -> None:
        # §15: фоновый update_self — снимаем задачу (часть HedgehogServer.shutdown).
        t = self._update_task
        if t is not None and not t.done():
            t.cancel()

    async def _h_update_self(self, conn_id, frame, p):
        # §15: git pull своего исходника + перезапуск. Авторизация — тем же
        # токеном, что и WS (SSH не нужен). Работает для серверов,
        # добавленных только по порту Ёжика.
        # M4: single-flight — параллельный вызов не запускает 2× git reset/
        # pip/execv (проверка+взвод атомарны: между ними нет await).
        if self._updating:
            await self.hub.send_global(conn_id, make_frame("update_result", {
                "ok": False, "changed": False, "old": "", "new": "",
                "message": i18n.Msg("update.in_progress")}))
            return
        self._updating = True
        # git pull/pip/рестарт идут до ~15 мин (бюджет pull_latest) → ФОНОВАЯ
        # задача, как install_neko: цикл кадров соединения сразу свободен
        # (ping/user_msg не ждут апдейта). Проверка+взвод без await между ними
        # — single-flight сохраняется.
        self._update_task = asyncio.create_task(
            self._update_job(conn_id, frame.id), name="update-self")
        return

    async def _update_job(self, conn_id, frame_id):
        """Фон update_self: pull_latest в потоке → update_result → рестарт."""
        restarting = False
        try:
            result = await asyncio.to_thread(updater.pull_latest,
                                             SERVER_COMMIT)
            upd_payload = {
                "ok": result.ok,
                "changed": result.changed,
                "old": result.old,
                "new": result.new,
                "message": result.message,
            }
            cli_info = result.cli
            if cli_info:   # манифест совместимого SDK (опционально, §15.2)
                upd_payload["cli"] = cli_info
            await self.host._reply_or_broadcast(conn_id, make_frame(
                "update_result", upd_payload))
            log.info("update.self", ok=result.ok, changed=result.changed,
                     old=result.old, new=result.new)
            if result.ok and result.changed:
                restarting = True   # процесс сменится — флаг НЕ снимаем
                async def _restart():
                    await asyncio.sleep(1.0)  # дать update_result долететь
                    log.info("update.restart", to=result.new)
                    from ... import neko
                    if neko.is_provisioning():
                        # execv не ждёт поток docker: прерываем pull, иначе
                        # он доживёт сиротой, а стадия после рестарта = absent.
                        neko.cancel_provision()
                    try:
                        updater.restart_in_place()   # execv — не возвращается
                    except Exception as e:  # noqa: BLE001
                        # execv упал: диск на новом SHA, но процесс на старом.
                        # Повтор update_self теперь вернёт changed=True (S6-M5:
                        # диск ≠ SHA процесса) и рестарт будет повторён. Без
                        # явного лога это было бы тихим unhandled-task exc.
                        log.error("update.restart_failed", err=repr(e))
                        self._updating = False   # разлатчиваем — рестарт не идёт
                # L: держим ссылку (иначе GC может собрать задачу до execv).
                self._restart_task = asyncio.create_task(_restart())
        except asyncio.CancelledError:
            raise
        except Exception as e:  # noqa: BLE001 — сбой фоновой задачи не теряем
            log.error("update.job_failed", err=repr(e))
            await self.host._reply_or_broadcast(conn_id, make_error(
                Err.INTERNAL, f"{type(e).__name__}: {e}", related=frame_id))
        finally:
            if not restarting:
                self._updating = False
