"""§limits: лимиты подписки Claude (5-часовое и недельное окна).

Данные берём НЕ из /api/oauth/usage (там нужен scope user:profile, которого у
setup-токена Ёжика нет — возвращает 403), а из ЗАГОЛОВКОВ ответа
POST /v1/messages: минимальный запрос (haiku, max_tokens=1) возвращает
anthropic-ratelimit-unified-5h-* и -7d-* (utilization 0..1, reset — unix-ts,
status). Токен — тот же OAuth, что и у агента (scope user:inference достаточно).

Проверено на живом setup-токене 2026-07-27: заголовки приходят при HTTP 200.
Токен НИКОГДА не логируем.
"""

from __future__ import annotations

import aiohttp
import structlog

from .config import Config

log = structlog.get_logger("limits")

_API = "https://api.anthropic.com/v1/messages"
_BETA = "oauth-2025-04-20"
# Минимальный дешёвый запрос — нужен только ради заголовков лимитов (~9 токенов).
_PROBE = {
    "model": "claude-haiku-4-5",
    "max_tokens": 1,
    "messages": [{"role": "user", "content": "hi"}],
}


def _num(v) -> float | None:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def parse_window(headers, prefix: str) -> dict | None:
    """Одно окно лимита из заголовков (prefix '5h' | '7d'). None — если
    заголовков нет (старый API / нет подписки)."""
    util = headers.get(f"anthropic-ratelimit-unified-{prefix}-utilization")
    if util is None:
        return None
    return {
        "utilization": _num(util),  # 0..1 — доля использованного окна
        "reset": _num(headers.get(f"anthropic-ratelimit-unified-{prefix}-reset")),
        "status": headers.get(f"anthropic-ratelimit-unified-{prefix}-status"),
    }


def parse_limits(headers) -> dict:
    """Заголовки ответа → структура лимитов для клиента."""
    return {
        "status": headers.get("anthropic-ratelimit-unified-status"),
        "overageStatus": headers.get("anthropic-ratelimit-unified-overage-status"),
        "fiveHour": parse_window(headers, "5h"),
        "sevenDay": parse_window(headers, "7d"),
    }


async def fetch_limits(config: Config) -> dict:
    """Вернуть лимиты подписки {status, overageStatus, fiveHour, sevenDay}
    или {'error': ...}. Токен НЕ логируем."""
    token = config.load_oauth_token()
    if not token:
        return {"error": "auth", "message": "Ёжик не авторизован"}
    headers = {
        "Authorization": f"Bearer {token}",
        "anthropic-beta": _BETA,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }
    try:
        timeout = aiohttp.ClientTimeout(total=20)
        async with aiohttp.ClientSession(timeout=timeout) as sess:
            async with sess.post(_API, json=_PROBE, headers=headers) as resp:
                if resp.status in (401, 403):
                    log.warning("limits.auth_rejected", status=resp.status)
                    return {"error": "auth", "message": "Токен не принят API"}
                if resp.status >= 400:
                    log.warning("limits.http_error", status=resp.status)
                    return {"error": "http", "message": f"HTTP {resp.status}"}
                result = parse_limits(resp.headers)
                log.info("limits.fetched", five=result["fiveHour"],
                         seven=result["sevenDay"], status=result["status"])
                return result
    except aiohttp.ClientError as e:
        log.warning("limits.fetch_failed", err=str(e))
        return {"error": "network", "message": str(e)}
