"""Точка входа Ёжика: python -m hedgehog.main"""

from __future__ import annotations

import asyncio
import logging
import signal
import sys

import structlog

from .config import Config
from .wss.server import HedgehogServer
from .scheduler import SchedulerService
from . import fileserver
from . import tls


def _setup_logging():
    logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.INFO)
    structlog.configure(
        processors=[
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.add_log_level,
            structlog.processors.KeyValueRenderer(key_order=["timestamp", "level", "event"]),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
        logger_factory=structlog.PrintLoggerFactory(),
    )


async def _amain():
    _setup_logging()
    log = structlog.get_logger("main")

    config = Config()
    from .config import ensure_secure_dir
    ensure_secure_dir(config.data_dir)   # M6: 0o700 (внутри секреты 0o600)
    # §tls: серт нужен ОБОИМ портам (8765 WS + 8767 файлы) и одному отпечатку.
    # WS-сервер стартует раньше файл-сервера, поэтому гарантируем серт здесь,
    # до старта приёма соединений (ensure_cert идемпотентна).
    if config.tls_enabled:
        fp = tls.ensure_cert(config.tls_cert_file, config.tls_key_file)
        log.info("tls.cert_ready", fingerprint=fp)
    server = HedgehogServer(config)
    # §sched: планировщик задач + блэкборд. Колбэки замкнуты на сервер (инъекция
    # текста / уведомление в чат). Ставим ДО старта приёма соединений.
    scheduler = SchedulerService(
        db_path=config.data_dir / "scheduler.db",
        artifacts_dir=config.data_dir / "artifacts",
        inject_cb=server.inject_message,
        notify_cb=server.notify_chat,
        inject_user_cb=server.inject_user_message,   # §defer
    )
    server.scheduler = scheduler
    await scheduler.start()
    log.info("hedgehog.start", version=config.server_version,
             data_dir=str(config.data_dir), token_file=str(config.token_file))

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)

    serve_task = asyncio.create_task(server.serve_forever())
    # M: если WS-сервер упал сам (порт занят / битый серт / внезапный exc), а не
    # по сигналу — не зависаем навечно в stop.wait() (зомби: процесс жив, порт не
    # слушается). Пробуждаем shutdown; исключение достаём ниже и пробрасываем.
    serve_task.add_done_callback(lambda _t: stop.set())
    # §7 файл-сервер — отдельный aiohttp-порт, WS-чаты не трогает.
    file_runner, tls_fp = await fileserver.start(config, config.load_token())
    log.info("files.start", port=config.file_port, tls=config.tls_enabled,
             fingerprint=tls_fp)

    await stop.wait()
    log.info("hedgehog.shutdown")
    serve_exc: BaseException | None = None
    if serve_task.done() and not serve_task.cancelled():
        serve_exc = serve_task.exception()   # упал сам — не по нашему cancel
        if serve_exc is not None:
            log.error("serve.crashed", err=repr(serve_exc))
    else:
        serve_task.cancel()
        try:
            await serve_task
        except asyncio.CancelledError:
            pass
    await file_runner.cleanup()
    await server.shutdown()
    if serve_exc is not None:
        raise serve_exc   # ненулевой код выхода → перезапуск супервизором


def main():
    asyncio.run(_amain())


if __name__ == "__main__":
    main()
