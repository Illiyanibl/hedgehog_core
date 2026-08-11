"""HTTP-файл-сервер (§7) на aiohttp — ОТДЕЛЬНЫЙ порт от WS-чатов.

WS-слой (`websockets`) не трогается: файлы живут на своём порту
(HEDGEHOG_FILE_PORT), делят с Ёжиком тот же Bearer-токен и тот же
self-signed TLS-серт (пиннинг на клиенте). Агент читает файлы с локальной
ФС (`Read`) — HTTP/токен его не касаются.

Роуты (вложения чата, §7):
  GET  /v1/health                    — liveness (под токеном)
  POST /v1/upload                    — загрузка вложения (headers: chatId/name/mime)
  GET  /v1/file/{chatId}/{fileId}    — скачивание вложения (Range поддержан)

Роуты файл-браузера (§16, вкладка Files). Пути — в заголовках, значения
percent-encoded UTF-8 (заголовки HTTP латиница) → сервер делает unquote.
Все пути проходят через _resolve() — потолок config.browse_root, наружу 403.
  GET    /v1/tree    (X-Path)                 — листинг каталога
  GET    /v1/fetch   (X-Path)                 — скачать/предпросмотр (Range)
  POST   /v1/put     (X-Dir,X-Name,X-Overwrite) — загрузка в папку (реальное имя)
  PUT    /v1/write   (X-Path)                 — сохранить текст (body=байты)
  POST   /v1/mkdir   (X-Path)                 — создать папку
  POST   /v1/move    (X-From,X-To,X-Overwrite) — переименовать/переместить
  POST   /v1/copy    (X-From,X-To,X-Overwrite) — скопировать
  DELETE /v1/rm      (X-Path)                 — удалить файл/папку (рекурсивно)
  POST   /v1/attach  (X-Chat-Id,X-Path)       — копия файла во вложения чата
  POST   /v1/zip     (JSON {paths:[...]})     — один zip из нескольких путей
"""
from __future__ import annotations

import io
import mimetypes
import os
import re
import shutil
import urllib.parse
import zipfile
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


def _safe_component(name: str) -> str:
    """Имя файла/папки для файл-браузера (§16): сохраняем Unicode (кириллица
    и пр.), но режем разделители путей и NUL — без слэшей и `..` нет traversal."""
    base = name.strip().replace("\x00", "").replace("/", "_").replace("\\", "_")
    if base in ("", ".", ".."):
        return "file"
    return base[:255]


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
            lines.append(f"- (file {r['name']} not found on the server)")
    note = ("Attached files (read them with the Read tool by absolute "
            "path):\n" + "\n".join(lines))
    return f"{content}\n\n{note}" if content.strip() else note


@web.middleware
async def _auth_mw(request: web.Request, handler):
    if request.headers.get("Authorization", "") != f"Bearer {request.app[TOKEN_KEY]}":
        # IP атакующего из TCP-пира → auth_failures.log для fail2ban (§security).
        from . import authlog
        authlog.record_failure(request.app[CONFIG_KEY], request.remote,
                               "file", request.path)
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


# ---------- файл-браузер (§16, вкладка Files) ----------

MAX_ENTRIES = 2000  # лимит записей на листинг (node_modules/.git и т.п.)


def _dec(request: web.Request, key: str) -> str:
    """Значение заголовка → percent-decoded UTF-8 путь."""
    return urllib.parse.unquote(request.headers.get(key, ""))


def _browse_root(config: Config) -> Path:
    return Path(config.browse_root).resolve()


def _resolve(config: Config, raw: str, *, must_exist: bool = False) -> Path:
    """Абсолютный путь в пределах browse_root. Наружу → 403, пусто → 400.

    resolve() снимает `..` и симлинки ДО проверки префикса — симлинк наружу
    не даёт сбежать. Несуществующий путь допустим (mkdir/put/write создают)."""
    if not raw:
        raise web.HTTPBadRequest(text="path required")
    root = _browse_root(config)
    p = Path(raw)
    if not p.is_absolute():
        p = root / raw
    try:
        p = p.resolve()
    except (OSError, RuntimeError):
        raise web.HTTPBadRequest(text="bad path")
    if p != root and root not in p.parents:
        raise web.HTTPForbidden(text="outside browse root")
    if must_exist and not p.exists():
        raise web.HTTPNotFound(text="not found")
    return p


async def _tree(request: web.Request) -> web.Response:
    config: Config = request.app[CONFIG_KEY]
    p = _resolve(config, _dec(request, "X-Path"), must_exist=True)
    if not p.is_dir():
        raise web.HTTPBadRequest(text="not a directory")
    root = _browse_root(config)
    entries: list[dict] = []
    truncated = False
    try:
        with os.scandir(p) as it:
            for de in it:
                if len(entries) >= MAX_ENTRIES:
                    truncated = True
                    break
                try:
                    st = de.stat(follow_symlinks=False)
                    is_link = de.is_symlink()
                    is_dir = de.is_dir(follow_symlinks=True)
                except OSError:
                    continue
                entries.append({
                    "name": de.name,
                    "type": "dir" if is_dir else "file",
                    "size": st.st_size,
                    "mtime": st.st_mtime,
                    "symlink": is_link,
                })
    except OSError as e:
        raise web.HTTPForbidden(text=str(e))
    # Папки выше файлов, затем по имени без регистра.
    entries.sort(key=lambda e: (e["type"] != "dir", e["name"].lower()))
    return web.json_response({
        "path": str(p),
        "parent": None if p == root else str(p.parent),
        "projectsRoot": str(config.projects_root),
        "browseRoot": str(root),
        "truncated": truncated,
        "entries": entries,
    })


async def _fetch(request: web.Request) -> web.StreamResponse:
    config: Config = request.app[CONFIG_KEY]
    p = _resolve(config, _dec(request, "X-Path"), must_exist=True)
    if not p.is_file():
        raise web.HTTPBadRequest(text="not a file")
    return web.FileResponse(p)  # Range обрабатывает aiohttp


async def _put(request: web.Request) -> web.Response:
    config: Config = request.app[CONFIG_KEY]
    d = _resolve(config, _dec(request, "X-Dir"), must_exist=True)
    if not d.is_dir():
        raise web.HTTPBadRequest(text="not a directory")
    name = _safe_component(_dec(request, "X-Name") or "file")  # без слэшей → без traversal
    overwrite = request.headers.get("X-Overwrite", "") == "1"
    dest = d / name
    if dest.exists() and not overwrite:
        return web.json_response({"error": "exists"}, status=409)

    size = 0
    limit = config.max_upload_bytes
    tmp = d / (name + ".part")
    try:
        with open(tmp, "wb") as f:
            async for chunk in request.content.iter_chunked(1 << 16):
                size += len(chunk)
                if size > limit:
                    f.close()
                    tmp.unlink(missing_ok=True)
                    return web.json_response({"error": "file too large"}, status=413)
                f.write(chunk)
        tmp.replace(dest)  # атомарная подмена
    except OSError as e:
        tmp.unlink(missing_ok=True)
        raise web.HTTPBadRequest(text=str(e))
    log.info("file.put", dir=str(d), name=name, size=size)
    return web.json_response({"name": name, "path": str(dest), "size": size})


async def _write(request: web.Request) -> web.Response:
    config: Config = request.app[CONFIG_KEY]
    p = _resolve(config, _dec(request, "X-Path"))
    if p.exists() and p.is_dir():
        raise web.HTTPBadRequest(text="is a directory")
    data = await request.read()  # ограничен client_max_size
    tmp = p.with_name(p.name + ".part")
    try:
        tmp.write_bytes(data)
        tmp.replace(p)
    except OSError as e:
        tmp.unlink(missing_ok=True)
        raise web.HTTPBadRequest(text=str(e))
    log.info("file.write", path=str(p), size=len(data))
    return web.json_response({"path": str(p), "size": len(data)})


async def _mkdir(request: web.Request) -> web.Response:
    config: Config = request.app[CONFIG_KEY]
    p = _resolve(config, _dec(request, "X-Path"))
    if p.exists():
        return web.json_response({"error": "exists"}, status=409)
    try:
        p.mkdir(parents=True)
    except OSError as e:
        raise web.HTTPBadRequest(text=str(e))
    return web.json_response({"path": str(p)})


def _prepare_dst(dst: Path, overwrite: bool) -> web.Response | None:
    """Общая проверка приёмника для move/copy. None → можно писать."""
    if dst.exists():
        if not overwrite:
            return web.json_response({"error": "exists"}, status=409)
        if dst.is_dir() and not dst.is_symlink():
            shutil.rmtree(dst)
        else:
            dst.unlink()
    return None


async def _move(request: web.Request) -> web.Response:
    config: Config = request.app[CONFIG_KEY]
    src = _resolve(config, _dec(request, "X-From"), must_exist=True)
    dst = _resolve(config, _dec(request, "X-To"))
    if src == _browse_root(config):
        raise web.HTTPForbidden(text="refuse to move root")
    if (resp := _prepare_dst(dst, request.headers.get("X-Overwrite", "") == "1")):
        return resp
    try:
        shutil.move(str(src), str(dst))
    except OSError as e:
        raise web.HTTPBadRequest(text=str(e))
    log.info("file.move", **{"from": str(src), "to": str(dst)})
    return web.json_response({"path": str(dst)})


async def _copy(request: web.Request) -> web.Response:
    config: Config = request.app[CONFIG_KEY]
    src = _resolve(config, _dec(request, "X-From"), must_exist=True)
    dst = _resolve(config, _dec(request, "X-To"))
    if (resp := _prepare_dst(dst, request.headers.get("X-Overwrite", "") == "1")):
        return resp
    try:
        if src.is_dir() and not src.is_symlink():
            shutil.copytree(src, dst)
        else:
            shutil.copy2(src, dst)
    except OSError as e:
        raise web.HTTPBadRequest(text=str(e))
    log.info("file.copy", **{"from": str(src), "to": str(dst)})
    return web.json_response({"path": str(dst)})


async def _rm(request: web.Request) -> web.Response:
    config: Config = request.app[CONFIG_KEY]
    p = _resolve(config, _dec(request, "X-Path"), must_exist=True)
    # Запрет на снос потолка обзора и «домашнего» корня проектов.
    if p == _browse_root(config) or p == config.projects_root:
        raise web.HTTPForbidden(text="refuse to delete root")
    try:
        if p.is_dir() and not p.is_symlink():
            shutil.rmtree(p)
        else:
            p.unlink()
    except OSError as e:
        raise web.HTTPBadRequest(text=str(e))
    log.info("file.rm", path=str(p))
    return web.json_response({"ok": True})


async def _attach(request: web.Request) -> web.Response:
    """Скопировать произвольный файл сервера во вложения чата → Attachment.
    Клиент дальше шлёт обычный user_msg с этим fileId (агент читает Read'ом)."""
    config: Config = request.app[CONFIG_KEY]
    chat_id = request.headers.get("X-Chat-Id", "")
    if not chat_id.isalnum():
        return web.json_response({"error": "bad chatId"}, status=400)
    chat_dir = config.chats_dir / chat_id
    if not chat_dir.exists():
        return web.json_response({"error": "chat not found"}, status=404)
    src = _resolve(config, _dec(request, "X-Path"), must_exist=True)
    if not src.is_file():
        raise web.HTTPBadRequest(text="not a file")

    files_dir = chat_dir / "files"
    files_dir.mkdir(parents=True, exist_ok=True)
    file_id = new_ulid()
    safe = _safe_name(src.name)
    dest = files_dir / f"{file_id}__{safe}"
    try:
        shutil.copy2(src, dest)
    except OSError as e:
        raise web.HTTPBadRequest(text=str(e))
    mime = mimetypes.guess_type(src.name)[0] or "application/octet-stream"
    log.info("file.attach", chat=chat_id, file=file_id, name=safe)
    return web.json_response({
        "fileId": file_id, "name": safe, "path": str(dest),
        "size": dest.stat().st_size, "mime": mime,
    })


MAX_ZIP_BYTES = 512 * 1024 * 1024  # суммарный лимит на архив (защита памяти)


def _zip_items(p: Path) -> list[tuple[Path, str]]:
    """Развернуть путь в список (файл, arcname). Папка → рекурсивно (arcname
    с префиксом её имени). Симлинки пропускаем (не выходим наружу архивом)."""
    if p.is_symlink():
        return []
    if p.is_file():
        return [(p, p.name)]
    if p.is_dir():
        out: list[tuple[Path, str]] = []
        for f in p.rglob("*"):
            if f.is_file() and not f.is_symlink():
                out.append((f, f"{p.name}/{f.relative_to(p).as_posix()}"))
        return out
    return []


async def _zip(request: web.Request) -> web.Response:
    """Собрать один zip из нескольких путей (множественное скачивание, §16 v2)."""
    config: Config = request.app[CONFIG_KEY]
    try:
        payload = await request.json()
        raw_paths = payload.get("paths", [])
    except Exception:
        raise web.HTTPBadRequest(text="bad json")
    if not isinstance(raw_paths, list) or not raw_paths:
        raise web.HTTPBadRequest(text="no paths")

    # каждый путь — через предохранитель (потолок/traversal), затем разворот.
    items: list[tuple[Path, str]] = []
    for rp in raw_paths[:1000]:
        p = _resolve(config, rp, must_exist=True)
        items += _zip_items(p)
    if not items:
        raise web.HTTPBadRequest(text="nothing to zip")

    total = sum(f.stat().st_size for f, _ in items)
    if total > MAX_ZIP_BYTES:
        return web.json_response({"error": "archive too large"}, status=413)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for f, arc in items:
            zf.write(f, arc)
    data = buf.getvalue()
    log.info("file.zip", count=len(items), bytes=len(data))
    return web.Response(body=data, headers={
        "Content-Type": "application/zip",
        "Content-Disposition": 'attachment; filename="files.zip"',
    })


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
        # файл-браузер (§16)
        web.get("/v1/tree", _tree),
        web.get("/v1/fetch", _fetch),
        web.post("/v1/put", _put),
        web.put("/v1/write", _write),
        web.post("/v1/mkdir", _mkdir),
        web.post("/v1/move", _move),
        web.post("/v1/copy", _copy),
        web.delete("/v1/rm", _rm),
        web.post("/v1/attach", _attach),
        web.post("/v1/zip", _zip),
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
