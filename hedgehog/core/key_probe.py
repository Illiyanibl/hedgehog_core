"""Проверка API-ключа / шлюза запросом списка моделей (§auth): GET по каталогу
моделей вендора. Возвращает (ok, ошибка-Msg|None, [id моделей])."""

from __future__ import annotations

import asyncio
import json
from typing import Any
from urllib.parse import urlsplit

from ..i18n import Msg
from .secrets_redact import redact

# kind → (дефолтный base, путь каталога, заголовки авторизации)
KINDS = {
    "xai": ("https://api.x.ai", "/v1/models", lambda k: {"Authorization": f"Bearer {k}"}),
    "openai": ("https://api.openai.com", "/v1/models",
               lambda k: {"Authorization": f"Bearer {k}"}),
    "gemini": ("https://generativelanguage.googleapis.com", "/v1beta/models",
               lambda k: {"x-goog-api-key": k}),
}


def models_url(kind: str, base_url: str | None) -> str:
    default, path, _ = KINDS[kind]
    root = (base_url or default).rstrip("/")
    # шлюзы часто хранят base вместе с /v1: не удваиваем сегмент
    if path.startswith("/v1/") and root.endswith("/v1"):
        path = path[len("/v1"):]
    return root + path


def redirect_host(location: str | None) -> str:
    """Хост из Location редиректа ('?' — нет/относительный/битый)."""
    try:
        return (urlsplit(location or "").hostname or "?")[:100]
    except ValueError:
        return "?"


def parse_model_ids(body: Any) -> list[str]:
    """{"data":[{"id":…}]} (OpenAI/xAI) или {"models":[{"name":"models/x"}]} (Gemini)."""
    if not isinstance(body, dict):
        return []
    items = body.get("data") if isinstance(body.get("data"), list) else body.get("models")
    out: list[str] = []
    for it in items if isinstance(items, list) else []:
        if not isinstance(it, dict):
            continue
        mid = it.get("id") or it.get("name")
        if isinstance(mid, str) and mid:
            out.append(mid.removeprefix("models/"))
    return out[:500]


async def probe(kind: str, base_url: str | None, api_key: str,
                timeout: float = 15.0) -> tuple[bool, Msg | None, list[str]]:
    import aiohttp
    url = models_url(kind, base_url)
    headers = KINDS[kind][2](api_key)
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout)) as s:
            async with s.get(url, headers=headers, allow_redirects=False) as r:
                if 300 <= r.status < 400:
                    return False, Msg("probe.redirect", status=r.status,
                                      host=redirect_host(r.headers.get("Location"))), []
                if r.status in (401, 403):
                    return False, Msg("probe.key_rejected", status=r.status), []
                if r.status >= 500:
                    return False, Msg("probe.server_unavailable_status",
                                      status=r.status), []
                raw = (await r.content.read(1_048_576)).decode("utf-8", "replace")
                if r.status == 429:           # ключ принят, лимит исчерпан
                    return True, None, []
                if 200 <= r.status < 300:
                    try:
                        body = json.loads(raw)
                    except ValueError:
                        body = None
                    if isinstance(body, dict):
                        return True, None, parse_model_ids(body)
                return False, Msg("probe.not_api_endpoint", status=r.status), []
    except (asyncio.TimeoutError, TimeoutError):
        return False, Msg("probe.timeout"), []
    except aiohttp.ClientError as e:
        return False, Msg("probe.server_unavailable", detail=redact(str(e))), []
    except Exception as e:  # noqa: BLE001 — проверка не должна ронять хендлер
        return False, Msg("probe.check_failed", detail=redact(str(e))), []
