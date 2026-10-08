"""§image: генерация растровых картинок через настраиваемый провайдер.

Формат-адаптеры выбираются по `cfg["format"]` (алиас `provider` для мягкости):

- **"openai"** — OpenAI Images API и всё OpenAI-совместимое: OmniRoute
  (→ nano-banana / gpt-image-1 / dall-e / flux), прямой OpenAI и т.п.
  `POST {base}/v1/images/generations`, `Authorization: Bearer {key}`,
  ответ `data[0].b64_json` ИЛИ `data[0].url`.
- **"deepai"** — DeepAI: `POST {base}/api/{model|text2img}`, заголовок
  `api-key: {key}`, form-поле `text=prompt`, ответ `{output_url}`.

Здесь ТОЛЬКО сеть + разбор ответа; доставку байтов в чат делает вызывающий
(`hedgehog_mcp.generate_image → session._attach_bytes_to_chat`).

Безопасность (ревью Fable):
- секрет (`api_key`) НИКОГДА не попадает в текст ошибки/лог;
- второй хоп (скачивание картинки по `url`/`output_url`) идёт на ЧУЖОЙ CDN —
  БЕЗ `Authorization` и только по http(s) (P0: иначе ключ утёк бы наружу);
- тело ответа читается с КАПОМ чанками (P0: не тянем гигабайты с чужого base_url
  — сервер держит все чаты). Образец — `gateways/omniroute.py::fetch_catalog`.
"""
from __future__ import annotations

import asyncio
import base64
import json
import re
from typing import Any

import aiohttp
import structlog

log = structlog.get_logger("image_gen")

_MAX_IMAGE_BYTES = 30 * 1024 * 1024      # кап байт самой картинки
# DeepAI-ответ несёт лишь {output_url} — 2 МБ с запасом.
_MAX_JSON_BYTES = 2 * 1024 * 1024
# OpenAI b64-путь: КАРТИНКА лежит В ТЕЛЕ ответа как base64 (+1/3 оверхед) — кап
# должен вмещать _MAX_IMAGE_BYTES после base64 плюс JSON-обёртку, иначе нормальная
# генерация gpt-image-1/nano-banana (отдаёт ТОЛЬКО b64_json) ловила бы «too large».
_MAX_OPENAI_JSON = _MAX_IMAGE_BYTES * 4 // 3 + 128 * 1024
_MAX_PROMPT = 4000                       # hard-лимит dall-e-3; дешевле round-trip
_SIZE_RE = re.compile(r"^(?:\d{3,4}x\d{3,4}|auto)$")
_HTTP_RE = re.compile(r"^https?://", re.IGNORECASE)


class ImageGenError(Exception):
    """Понятная агенту ошибка генерации (без секретов)."""


def _images_url(base_url: str) -> str:
    """URL images-эндпоинта из base_url. Толерантно к форме (как _models_url)."""
    b = (base_url or "").rstrip("/")
    if b.endswith("/v1/images/generations"):
        return b
    if b.endswith("/v1"):
        return b + "/images/generations"
    return b + "/v1/images/generations"


def _deepai_url(base_url: str, model: str) -> str:
    """URL DeepAI-эндпоинта: base + /api/<model|text2img>."""
    b = (base_url or "https://api.deepai.org").rstrip("/")
    ep = (model or "text2img").strip().strip("/") or "text2img"
    if b.endswith("/api/" + ep) or "/api/" in b:
        return b
    return f"{b}/api/{ep}"


def _sniff(data: bytes) -> tuple[str, str]:
    """Расширение/MIME по магическим байтам (b64-путь без Content-Type)."""
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "png", "image/png"
    if data[:3] == b"\xff\xd8\xff":
        return "jpg", "image/jpeg"
    if data[:6] in (b"GIF87a", b"GIF89a"):
        return "gif", "image/gif"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp", "image/webp"
    return "png", "image/png"


_CT_EXT = {
    "image/png": ("png", "image/png"),
    "image/jpeg": ("jpg", "image/jpeg"),
    "image/jpg": ("jpg", "image/jpeg"),
    "image/webp": ("webp", "image/webp"),
    "image/gif": ("gif", "image/gif"),
}


def _ext_from_ct(ct: str) -> tuple[str, str]:
    """Расширение/MIME по Content-Type; неизвестное → png (вайтлист, P1-5:
    иначе провайдер с text/html отдал бы *.html-вложение на телефон)."""
    key = (ct or "").split(";")[0].strip().lower()
    return _CT_EXT.get(key, ("png", "image/png"))


async def _read_capped(resp: aiohttp.ClientResponse, limit: int) -> bytes:
    """Прочитать тело ответа с жёстким капом (чанками, gzip уже разжат парсером)."""
    if (resp.content_length or 0) > limit:
        raise ImageGenError("provider response too large")
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await resp.content.read(64 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > limit:
            raise ImageGenError("provider response too large")
        chunks.append(chunk)
    return b"".join(chunks)


async def _fetch_url_image(url: str, timeout: float) -> tuple[bytes, str, str]:
    """Второй хоп: скачать картинку по URL. БЕЗ Authorization (чужой CDN!),
    только http(s), с капом размера."""
    if not _HTTP_RE.match(url or ""):
        raise ImageGenError("provider returned a non-http(s) image url")
    to = aiohttp.ClientTimeout(total=timeout, connect=10)
    async with aiohttp.ClientSession(timeout=to) as sess:
        async with sess.get(url) as resp:   # никаких секретных заголовков
            if resp.status != 200:
                raise ImageGenError(f"image download failed: HTTP {resp.status}")
            ext, mime = _ext_from_ct(resp.headers.get("Content-Type", ""))
            data = await _read_capped(resp, _MAX_IMAGE_BYTES)
    if not data:
        raise ImageGenError("provider returned an empty image")
    return data, ext, mime


def _openai_err(raw: bytes, status: int) -> str:
    """Вытащить {"error":{"message"}} из тела (чтобы агент сам исправился)."""
    try:
        d = json.loads(raw)
        if isinstance(d, dict):
            msg = (d.get("error") or {}).get("message") if isinstance(
                d.get("error"), dict) else d.get("error") or d.get("message")
            if msg:
                return f"provider error (HTTP {status}): {str(msg)[:300]}"
    except ValueError:
        pass
    return (f"provider error: HTTP {status}: "
            f"{raw[:200].decode('utf-8', 'replace')}")


async def _gen_openai(cfg: dict, prompt: str, size: str | None,
                      timeout: float) -> tuple[bytes, str, str]:
    url = _images_url(str(cfg.get("base_url") or ""))
    if not _HTTP_RE.match(url):
        raise ImageGenError("image base_url must be http(s)")
    body: dict[str, Any] = {"model": str(cfg.get("model") or ""),
                            "prompt": prompt, "n": 1}
    if size:                                  # P1-3: size не у всех моделей валиден
        body["size"] = size
    headers = {"Authorization": f"Bearer {cfg.get('api_key') or ''}",
               "Content-Type": "application/json"}
    to = aiohttp.ClientTimeout(total=timeout, connect=10)
    async with aiohttp.ClientSession(timeout=to) as sess:
        async with sess.post(url, json=body, headers=headers) as resp:
            raw = await _read_capped(resp, _MAX_OPENAI_JSON)
            if resp.status != 200:
                raise ImageGenError(_openai_err(raw, resp.status))
    try:
        data = json.loads(raw)
    except ValueError:
        raise ImageGenError("provider returned non-JSON response")
    arr = data.get("data") if isinstance(data, dict) else None
    if not isinstance(arr, list) or not arr or not isinstance(arr[0], dict):
        raise ImageGenError("provider returned no image data")
    item = arr[0]
    b64 = item.get("b64_json")
    if b64:
        try:
            img = base64.b64decode(b64)
        except (ValueError, TypeError):
            raise ImageGenError("provider returned invalid base64 image")
        if len(img) > _MAX_IMAGE_BYTES:
            raise ImageGenError("provider image too large")
        if not img:
            raise ImageGenError("provider returned an empty image")
        ext, mime = _sniff(img)
        return img, ext, mime
    if item.get("url"):
        return await _fetch_url_image(str(item["url"]), timeout)
    raise ImageGenError("provider response had neither b64_json nor url")


async def _gen_deepai(cfg: dict, prompt: str, size: str | None,
                      timeout: float) -> tuple[bytes, str, str]:
    url = _deepai_url(str(cfg.get("base_url") or ""), str(cfg.get("model") or ""))
    if not _HTTP_RE.match(url):
        raise ImageGenError("image base_url must be http(s)")
    form = aiohttp.FormData()
    form.add_field("text", prompt)
    if size:
        form.add_field("size", size)         # DeepAI игнорирует незнакомое поле
    headers = {"api-key": str(cfg.get("api_key") or "")}
    to = aiohttp.ClientTimeout(total=timeout, connect=10)
    async with aiohttp.ClientSession(timeout=to) as sess:
        async with sess.post(url, data=form, headers=headers) as resp:
            raw = await _read_capped(resp, _MAX_JSON_BYTES)
            if resp.status != 200:
                raise ImageGenError(
                    f"DeepAI error: HTTP {resp.status}: "
                    f"{raw[:200].decode('utf-8', 'replace')}")
    try:
        data = json.loads(raw)
    except ValueError:
        raise ImageGenError("DeepAI returned non-JSON response")
    out = data.get("output_url") if isinstance(data, dict) else None
    if not out:
        err = data.get("err") if isinstance(data, dict) else None
        raise ImageGenError("DeepAI returned no image"
                            + (f": {str(err)[:200]}" if err else ""))
    return await _fetch_url_image(str(out), timeout)


async def generate(cfg: dict, prompt: str, size: str | None = None,
                   *, timeout: float = 120.0) -> tuple[bytes, str, str]:
    """Сгенерировать картинку. → (bytes, ext, mime). Бросает ImageGenError с
    человекочитаемым (без секретов) текстом при любой проблеме."""
    prompt = (prompt or "").strip()
    if not prompt:
        raise ImageGenError("empty prompt")
    if len(prompt) > _MAX_PROMPT:
        raise ImageGenError(f"prompt too long (> {_MAX_PROMPT} chars)")
    # P2-2: cfg["size"] может быть не-строкой (админ напишет 1024) — str() до strip.
    size = (size if size else str(cfg.get("size") or "")).strip() or None
    if size and not _SIZE_RE.match(size):
        raise ImageGenError("size must look like 1024x1024 or 'auto'")
    fmt = str(cfg.get("format") or cfg.get("provider") or "").strip().lower()
    try:
        if fmt == "openai":
            return await _gen_openai(cfg, prompt, size, timeout)
        if fmt == "deepai":
            return await _gen_deepai(cfg, prompt, size, timeout)
    except ImageGenError:
        raise
    except asyncio.TimeoutError:
        raise ImageGenError(f"image provider timed out after {int(timeout)}s")
    except aiohttp.ClientError as e:
        raise ImageGenError(
            f"network error talking to image provider: {type(e).__name__}")
    raise ImageGenError(
        f"unknown image format '{fmt}' in image.json (expected 'openai' or 'deepai')")
