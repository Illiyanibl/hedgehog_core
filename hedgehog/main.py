"""Точка входа Ёжика: python -m hedgehog.main"""

from __future__ import annotations

import asyncio
import logging
import signal
import sys

import structlog

from .config import Config
from .wss.server import HedgehogServer
from . import fileserver


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
    config.data_dir.mkdir(parents=True, exist_ok=True)
    server = HedgehogServer(config)
    log.info("hedgehog.start", version=config.server_version,
             data_dir=str(config.data_dir), token_file=str(config.token_file))

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)

    serve_task = asyncio.create_task(server.serve_forever())
    # §7 файл-сервер — отдельный aiohttp-порт, WS-чаты не трогает.
    file_runner, tls_fp = await fileserver.start(config, config.load_token())
    log.info("files.start", port=config.file_port, tls=config.tls_enabled,
             fingerprint=tls_fp)

    await stop.wait()
    log.info("hedgehog.shutdown")
    serve_task.cancel()
    try:
        await serve_task
    except asyncio.CancelledError:
        pass
    await file_runner.cleanup()
    await server.shutdown()


def main():
    asyncio.run(_amain())


if __name__ == "__main__":
    main()
