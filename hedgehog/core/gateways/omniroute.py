"""§gateways/omniroute: адаптер AI-шлюза OmniRoute.

Тянет каталог моделей у шлюза (OpenAI-совместимый `GET {base}/v1/models`) и
маппит его в нашу структуру «провайдер → модели»:

- Группируем по **namespace** (префикс id до `/`), напр. `cc/claude-opus-4-8`
  → namespace `cc`. Модификатор `no-think/` снимаем (это вариант базовой модели).
- Встроенный «зоопарк» OmniRoute (combo/auto, theoldllm, auggie, opencode,
  duckduckgo, chipotle, mimocode, veo*) сворачиваем в один синтетический
  провайдер **«OmniRoute default»** — он всегда ПОСЛЕДНИЙ (чтобы не мешать
  подключённым платным подпискам).
- `type=video` (veo/seedance) отсекаем — не для чат-CLI.
- Имя чистим от префикса namespace (`cc/Claude Opus 4.8` → `Claude Opus 4.8`),
  fallback на `root`/последний сегмент id.

Клиент рисует эту структуру (сворачиваемые провайдеры) и на шаге 1 (авторизация)
даёт назвать/выбрать модели. Тир-лимиты применяет КЛИЕНТ на шаге 2 — сервер тут
отдаёт полный каталог без ограничений.
"""
from __future__ import annotations

from typing import Any

import aiohttp
import structlog

log = structlog.get_logger("gateway.omniroute")

# namespace'ы встроенных бесплатных агрегаторов OmniRoute → в «OmniRoute default».
BUILTIN_NAMESPACES: frozenset[str] = frozenset({
    "auto",            # combo — мета-роутеры (best-coding, pro-reasoning…)
    "tllm",            # theoldllm
    "aug",             # auggie
    "oc",              # opencode
    "ddgw",            # duckduckgo-web
    "pepper",          # chipotle
    "mcode",           # mimocode
    "veo-free",        # видео (отсекаются type=video, но namespace на всякий)
    "veoaifree-web",
})

# Человеческие имена «реальных» провайдеров. Неизвестный реальный namespace →
# title-case (см. _provider_label).
NAMESPACE_LABELS: dict[str, str] = {
    "cc": "Claude Code",
    "claude": "Claude",
}

DEFAULT_PROVIDER_ID = "omniroute_default"
DEFAULT_PROVIDER_NAME = "OmniRoute default"

_NOTHINK_PREFIX = "no-think/"


def _strip_nothink(model_id: str) -> tuple[str, bool]:
    """Снять модификатор no-think/. → (base_id, is_no_think)."""
    if model_id.startswith(_NOTHINK_PREFIX):
        return model_id[len(_NOTHINK_PREFIX):], True
    return model_id, False


def _namespace(model_id: str) -> str:
    """namespace = первый сегмент id (после снятия no-think/)."""
    base, _ = _strip_nothink(model_id)
    return base.split("/", 1)[0] if "/" in base else base


def _provider_label(namespace: str) -> str:
    return NAMESPACE_LABELS.get(namespace) or namespace.replace("-", " ").title()


def _clean_name(model: dict, namespace: str) -> str:
    """Человеческое имя без префикса namespace. Fallback: root / хвост id."""
    name = (model.get("name") or "").strip()
    if name:
        # OmniRoute часто прошивает префикс в name: "cc/Claude Opus 4.8".
        for pref in (f"{namespace}/", f"{_NOTHINK_PREFIX}{namespace}/", _NOTHINK_PREFIX):
            if name.startswith(pref):
                name = name[len(pref):]
                break
        return name
    root = (model.get("root") or "").strip()
    if root:
        return root.split("/", 1)[-1]
    base, _ = _strip_nothink(str(model.get("id", "")))
    return base.split("/", 1)[-1] if "/" in base else base


def _caps(model: dict) -> dict:
    c = model.get("capabilities") or {}
    return {
        "tool_calling": bool(c.get("tool_calling")),
        "thinking": bool(c.get("thinking")),
        "reasoning": bool(c.get("reasoning")),
        "vision": bool(c.get("vision")),
    }


def build_catalog(raw_models: list[dict]) -> dict[str, Any]:
    """Сырой список из /v1/models → {providers: [...]}. Реальные провайдеры в
    порядке первого появления, «OmniRoute default» — последним."""
    order: list[str] = []                 # namespace'ы реальных провайдеров, first-seen
    groups: dict[str, list[dict]] = {}    # provider_id → models
    seen_ids: set[str] = set()            # дедуп (veo дублируется и т.п.)

    for m in raw_models or []:
        mid = str(m.get("id") or "").strip()
        if not mid:
            continue
        if m.get("type") == "video":      # не для чат-CLI
            continue
        ns = _namespace(mid)
        base_id, no_think = _strip_nothink(mid)
        is_builtin = ns in BUILTIN_NAMESPACES
        provider_id = DEFAULT_PROVIDER_ID if is_builtin else ns
        if provider_id not in groups:
            groups[provider_id] = []
            if not is_builtin:
                order.append(provider_id)
        # дедуп по полному id (с учётом no-think — это разные модели)
        if mid in seen_ids:
            continue
        seen_ids.add(mid)
        name = _clean_name(m, ns)
        if no_think:
            name = f"{name} · no-think"
        groups[provider_id].append({
            "id": mid,
            "name": name,
            "namespace": ns,                 # префикс для показа перед именем
            "no_think": no_think,
            "context_length": m.get("context_length"),
            "max_output": m.get("max_output_tokens"),
            **_caps(m),
        })

    providers: list[dict] = []
    for pid in order:
        providers.append({
            "id": pid, "name": _provider_label(pid),
            "builtin": False, "models": groups[pid],
        })
    if DEFAULT_PROVIDER_ID in groups:        # «OmniRoute default» — всегда последним
        providers.append({
            "id": DEFAULT_PROVIDER_ID, "name": DEFAULT_PROVIDER_NAME,
            "builtin": True, "models": groups[DEFAULT_PROVIDER_ID],
        })
    return {"providers": providers}


def _models_url(base_url: str) -> str:
    """URL каталога из base_url. Толерантно к разным формам ввода."""
    b = base_url.rstrip("/")
    if b.endswith("/v1/models"):
        return b
    if b.endswith("/v1"):
        return b + "/models"
    return b + "/v1/models"


async def fetch_catalog(base_url: str, api_key: str,
                        timeout: float = 20.0) -> dict[str, Any]:
    """GET {base}/v1/models → сгруппированный каталог. Кидает исключение при
    сетевой/HTTP ошибке (вызывающий переводит в error-фрейм)."""
    url = _models_url(base_url)
    headers = {"Authorization": f"Bearer {api_key}"}
    to = aiohttp.ClientTimeout(total=timeout)
    async with aiohttp.ClientSession(timeout=to) as sess:
        async with sess.get(url, headers=headers) as resp:
            if resp.status != 200:
                body = (await resp.text())[:200]
                raise RuntimeError(f"HTTP {resp.status}: {body}")
            data = await resp.json(content_type=None)
    raw = data.get("data") if isinstance(data, dict) else data
    if not isinstance(raw, list):
        raise RuntimeError("unexpected /v1/models shape")
    cat = build_catalog(raw)
    log.info("omniroute.catalog", url=url,
             providers=len(cat["providers"]),
             total=sum(len(p["models"]) for p in cat["providers"]))
    return cat
