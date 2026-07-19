"""HTTP-файл-сервер (§7) на aiohttp — ОТДЕЛЬНЫЙ порт от WS-чатов.

WS-слой (`websockets`) не трогается: файлы живут на своём порту
(HEDGEHOG_FILE_PORT), делят с Ёжиком тот же Bearer-токен и тот же
self-signed TLS-серт (пиннинг на клиенте). Агент читает файлы с локальной
ФС (`Read`) — HTTP/токен его не касаются.

Роуты:
  GET  /v1/health                    — liveness (под токеном)
  POST /v1/upload                    — загрузка (headers: chatId/name/mime)
  GET  /v1/file/{chatId}/{fileId}    — скачивание (Range поддержан)
"""
from __future__ import annotations

import re
from pathlib import Path

from aiohttp import web
import structlog

from .config import Config
from .ids import new_ulid
from . import tls

log = structlog.get_logger("files")

CONFIG_KEY: "web.AppKey[Config]" = web.AppKey("config", Config)
TOKEN_KEY: "web.AppKey[str]" = web.AppKey("token", str)

_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


def _safe_name(name: str) -> str:
    base = _SAFE.sub("_", name.strip()) or "file"
    return base[:120]


# ---------- вложения → промпт агенту (§7.3) ----------

def resolve_attachment_paths(chats_dir: Path, chat_id: str,
                             attachments) -> list[dict]:
    """fileId → абсолютный путь файла. Возврат:
    [{path|None, mime, name, fileId}]. fileId не-alnum / не найден → path=None.
    """
    files_dir = chats_dir / chat_id / "files"
    out: list[dict] = []
    for a in attachments:
        fid = a.fileId
        matches = (sorted(files_dir.glob(f"{fid}__*"))
                   if fid.isalnum() and files_dir.exists() else [])
        out.append({"path": str(matches[0]) if matches else None,
                    "mime": a.mime, "name": a.name, "fileId": fid})
    return out


def compose_prompt(content: str, resolved: list[dict]) -> str:
    """Дописать к тексту сообщения пути вложений — чтобы агент прочитал их
    инструментом Read. Без вложений возвращает content без изменений."""
    if not resolved:
        return content
    lines = []
    for r in resolved:
        if r["path"]:
            lines.append(f"- {r['path']} ({r['mime']}) — {r['name']}")
        else:
            lines.append(f"- (файл {r['name']} не найден на сервере)")
    note = ("Прикреплённые файлы (прочитай инструментом Read по абсолютному "
            "пути):\n" + "\n".join(lines))
    return f"{content}\n\n{note}" if content.strip() else note


@web.middleware
async def _auth_mw(request: web.Request, handler):
    if request.headers.get("Authorization", "") != f"Bearer {request.app[TOKEN_KEY]}":
        return web.json_response({"error": "auth failed"}, status=401)
    return await handler(request)


async def _health(request: web.Request) -> web.Response:
    return web.json_response({"ok": True, "service": "files",
                             "version": request.app[CONFIG_KEY].server_version})


async def _upload(request: web.Request) -> web.Response:
    config: Config = request.app[CONFIG_KEY]
    chat_id = request.headers.get("X-Devolution-Chat-Id", "")
    name = request.headers.get("X-Devolution-File-Name", "file")
    mime = request.headers.get("X-Devolution-File-Mime", "application/octet-stream")
    if not chat_id.isalnum():
        return web.json_response({"error": "bad chatId"}, status=400)
    chat_dir = config.chats_dir / chat_id
    if not chat_dir.exists():
        return web.json_response({"error": "chat not found"}, status=404)

    files_dir = chat_dir / "files"
    files_dir.mkdir(parents=True, exist_ok=True)
    file_id = new_ulid()
    safe = _safe_name(name)
    dest = files_dir / f"{file_id}__{safe}"

    size = 0
    limit = config.max_upload_bytes
    with open(dest, "wb") as f:
        async for chunk in request.content.iter_chunked(1 << 16):
            size += len(chunk)
            if size > limit:
                f.close()
                dest.unlink(missing_ok=True)
                return web.json_response({"error": "file too large"}, status=413)
            f.write(chunk)

    log.info("file.uploaded", chat=chat_id, file=file_id, name=safe,
             size=size, mime=mime)
    return web.json_response({
        "fileId": file_id, "name": safe, "path": str(dest),
        "size": size, "mime": mime,
    })


async def _download(request: web.Request) -> web.StreamResponse:
    config: Config = request.app[CONFIG_KEY]
    chat_id = request.match_info["chatId"]
    file_id = request.match_info["fileId"]
    if not (chat_id.isalnum() and file_id.isalnum()):
        raise web.HTTPBadRequest(text="bad id")
    files_dir = config.chats_dir / chat_id / "files"
    matches = sorted(files_dir.glob(f"{file_id}__*")) if files_dir.exists() else []
    if not matches:
        raise web.HTTPNotFound(text="file not found")
    return web.FileResponse(matches[0])  # aiohttp сам обрабатывает Range


def make_app(config: Config, token: str) -> web.Application:
    app = web.Application(
        middlewares=[_auth_mw],
        client_max_size=config.max_upload_bytes + (1 << 16))
    app[CONFIG_KEY] = config
    app[TOKEN_KEY] = token
    app.add_routes([
        web.get("/v1/health", _health),
        web.post("/v1/upload", _upload),
        web.get("/v1/file/{chatId}/{fileId}", _download),
    ])
    return app


async def start(config: Config, token: str) -> tuple[web.AppRunner, str | None]:
    """Поднять файл-сервер. Возврат: (runner для cleanup, отпечаток серта|None)."""
    app = make_app(config, token)
    runner = web.AppRunner(app)
    await runner.setup()

    ssl_ctx = None
    fp: str | None = None
    if config.tls_enabled:
        fp = tls.ensure_cert(config.tls_cert_file, config.tls_key_file)
        ssl_ctx = tls.make_ssl_context(config.tls_cert_file, config.tls_key_file)

    site = web.TCPSite(runner, config.host, config.file_port, ssl_context=ssl_ctx)
    await site.start()
    log.info("files.listening", host=config.host, port=config.file_port,
             tls=config.tls_enabled, fingerprint=fp)
    return runner, fp
