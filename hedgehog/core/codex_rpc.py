"""§multi-cli (§20): разовые запросы к `codex app-server` вне чатовой сессии —
список моделей, лимиты аккаунта, состояние входа. Процесс живёт только на время
запроса (как `agy models` для Antigravity).
"""

from __future__ import annotations

import asyncio
from typing import Any, Awaitable, Callable

import structlog

from . import cli_registry, codex_auth
from .acp_common import has_http_code
from .acp_client import AcpClient, AcpClosed, AcpRpcError

log = structlog.get_logger("codex_rpc")

CLI_TYPE = "codex"
_CLIENT_INFO = {"name": "hedgehog", "title": "Hedgehog", "version": "1"}


async def _refuse(method: str, params: dict) -> Any:
    raise AcpRpcError(-32601, f"method not found: {method}")


async def with_app_server(fn: Callable[[AcpClient], Awaitable[Any]], *,
                          argv: list[str] | None = None,
                          timeout: float = 45.0) -> Any:
    """Поднять `codex app-server`, выполнить fn(client), закрыть процесс."""
    env = None
    if argv is None:
        binary = cli_registry.find_binary(CLI_TYPE)
        if binary is None:
            raise FileNotFoundError("codex binary not found")
        argv = [binary, "app-server"]
        env = cli_registry.spawn_env(CLI_TYPE, binary, codex_auth.codex_extra_env())
    client = AcpClient(argv, env=env, on_request=_refuse)
    await client.start()
    try:
        async def run():
            await client.request("initialize", {
                "clientInfo": _CLIENT_INFO, "capabilities": {}}, timeout=30)
            await client.notify("initialized")
            return await fn(client)
        return await asyncio.wait_for(run(), timeout)
    finally:
        await client.close()


# ---------- модели ----------

def parse_models(pages: list[dict]) -> dict[str, Any]:
    """Страницы `model/list` → {models, names, efforts, defaultEfforts, current}."""
    ids: list[str] = []
    names: dict[str, str] = {}
    efforts: dict[str, list[str]] = {}
    defaults: dict[str, str] = {}
    current = None
    for page in pages:
        data = page.get("data") if isinstance(page, dict) else None
        for m in data if isinstance(data, list) else []:
            if not isinstance(m, dict):
                continue
            mid = m.get("id") or m.get("model")
            if not isinstance(mid, str) or not mid or m.get("hidden") \
                    or mid in names:
                continue
            ids.append(mid)
            dn = m.get("displayName")
            names[mid] = dn if isinstance(dn, str) and dn else mid
            sup = m.get("supportedReasoningEfforts")
            efforts[mid] = [e["reasoningEffort"] for e in
                            (sup if isinstance(sup, list) else [])
                            if isinstance(e, dict)
                            and isinstance(e.get("reasoningEffort"), str)
                            and e["reasoningEffort"]]
            de = m.get("defaultReasoningEffort")
            if isinstance(de, str) and de:
                defaults[mid] = de
            if m.get("isDefault") and current is None:
                current = mid
    return {"models": ids, "names": names, "efforts": efforts,
            "defaultEfforts": defaults, "current": current}


async def _list_models(client: AcpClient) -> dict[str, Any]:
    pages: list[dict] = []
    cursor = None
    for _ in range(10):                          # потолок страниц
        page = await client.request("model/list", {
            "limit": 100, "includeHidden": False,
            **({"cursor": cursor} if cursor else {})}, timeout=30)
        pages.append(page or {})
        cursor = (page or {}).get("nextCursor")
        if not cursor:
            break
    return parse_models(pages)


async def probe_models(*, argv: list[str] | None = None) -> dict[str, Any]:
    """Проба для models_list (формат models.probe_models). Не залогинен →
    AUTH_REQUIRED без запуска процесса; нет бинарника → NO_CLI."""
    base = {"cliType": CLI_TYPE, "models": [], "current": None, "raw": ""}
    if argv is None and cli_registry.find_binary(CLI_TYPE) is None:
        return {**base, "auth_state": "NO_CLI", "cli_present": False}
    rec = codex_auth.alt_record() if argv is None else {}
    if rec.get("method") == "gateway":
        ms = [m for m in rec.get("models") or [] if isinstance(m, dict) and m.get("id")]
        return {**base, "models": [m["id"] for m in ms],
                "names": {m["id"]: str(m.get("name") or m["id"]) for m in ms},
                "current": rec.get("active_id") or (ms[0]["id"] if ms else None),
                "source": "gateway", "auth_state": "OK" if ms else "ERROR",
                "cli_present": True}
    if not rec and not codex_auth.is_logged_in():
        return {**base, "auth_state": "AUTH_REQUIRED", "cli_present": True}

    async def job(client: AcpClient):
        data = await _list_models(client)
        try:
            acc = await client.request("account/read",
                                       {"refreshToken": False}, timeout=20)
            data["plan"] = ((acc or {}).get("account") or {}).get("planType")
        except (AcpRpcError, asyncio.TimeoutError):
            pass
        return data
    try:
        data = await with_app_server(job, argv=argv)
    except (OSError, AcpClosed, AcpRpcError, asyncio.TimeoutError) as e:
        low = str(e).lower()
        state = ("AUTH_REQUIRED" if has_http_code(low, 401) or any(
            m in low for m in ("not logged in", "unauthor", "unauthenticated",
                               "log in", "login required")) else "ERROR")
        log.warning("codex.models_probe_failed", err=repr(e), state=state)
        return {**base, "auth_state": state, "cli_present": True}
    if not data["models"]:
        return {**base, "auth_state": "ERROR", "cli_present": True}
    return {**base, **data, "auth_state": "OK", "cli_present": True}


# ---------- лимиты ----------

def _d(x: Any) -> dict:
    return x if isinstance(x, dict) else {}


def _num(x: Any) -> float | None:
    """Число из ответа сервера (bool и строки не считаем числом)."""
    if isinstance(x, bool) or not isinstance(x, (int, float)):
        return None
    return float(x) if x == x and x not in (float("inf"), float("-inf")) else None


def _window(w: Any) -> dict | None:
    if not isinstance(w, dict):
        return None
    used = _num(w.get("usedPercent"))
    util = None if used is None else round(used / 100.0, 4)
    reset = _num(w.get("resetsAt"))
    mins = _num(w.get("windowDurationMins"))
    return {"utilization": util,                   # 0..1, как у Claude
            "reset": None if reset is None else int(reset),
            "status": ("rejected" if util is not None and util >= 1
                       else "allowed"),
            "windowMinutes": None if mins is None else int(mins)}


def map_rate_limits(resp: Any) -> dict[str, Any]:
    """`account/rateLimits/read` → форма `limits_result` (как у Claude):
    {status, overageStatus, fiveHour, sevenDay} + cliType/supported/planType.
    Окно ≈5 ч (300 мин) → fiveHour, ≈неделя (10080 мин) → sevenDay.

    Протокол Codex app-server экспериментальный — любое поле может прийти
    другого типа, поэтому разбор терпимый: неверное значение → None."""
    resp = _d(resp)
    rl = _d(_d(resp.get("rateLimitsByLimitId")).get("codex")) \
        or _d(resp.get("rateLimits"))
    five = seven = None
    for w in (rl.get("primary"), rl.get("secondary")):
        win = _window(w)
        if win is None:
            continue
        mins = win.get("windowMinutes") or 0
        if mins >= 7 * 24 * 60 and seven is None:
            seven = win
        elif five is None and mins < 7 * 24 * 60:
            five = win
        elif seven is None:
            seven = win
    credits = _d(rl.get("credits"))
    allowed = resp.get("ordinaryUsageAllowed", True) is not False
    reached = rl.get("rateLimitReachedType")
    reached = reached if isinstance(reached, str) and reached else None
    balance = credits.get("balance")
    plan = rl.get("planType")
    return {
        "cliType": CLI_TYPE, "supported": True,
        "status": "allowed" if allowed and not reached else "rejected",
        "overageStatus": ("allowed" if credits.get("hasCredits") is True
                          or credits.get("unlimited") is True else "rejected"),
        "fiveHour": five, "sevenDay": seven, "serverDate": None,
        "planType": plan if isinstance(plan, str) else None,
        "credits": {"hasCredits": credits.get("hasCredits") is True,
                    "unlimited": credits.get("unlimited") is True,
                    "balance": balance if isinstance(balance, (str, int, float))
                    and not isinstance(balance, bool) else None},
        "rateLimitReachedType": reached,
    }


async def fetch_limits(*, argv: list[str] | None = None) -> dict[str, Any]:
    """Лимиты аккаунта Codex в форме limits_result; ошибки — {'error', 'message'}."""
    from ..i18n import Msg
    if not codex_auth.is_logged_in():
        return {"cliType": CLI_TYPE, "error": "auth",
                "message": Msg("limits.not_authorized")}
    try:
        resp = await with_app_server(
            lambda c: c.request("account/rateLimits/read", {}, timeout=30),
            argv=argv)
    except asyncio.TimeoutError:
        return {"cliType": CLI_TYPE, "error": "network",
                "message": Msg("limits.timeout")}
    except (OSError, AcpClosed, AcpRpcError) as e:
        log.warning("codex.limits_failed", err=repr(e))
        low = str(e).lower()
        kind = "auth" if has_http_code(low, 401) or any(
            m in low for m in ("not logged in", "unauthor", "log in")) else "network"
        return {"cliType": CLI_TYPE, "error": kind, "message": str(e)[:200]}
    return map_rate_limits(resp)
