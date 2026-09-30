"""§gateways/omniroute: адаптер AI-шлюза OmniRoute.

Тянет каталог моделей у шлюза (OpenAI-совместимый `GET {base}/v1/models`) и
маппит его в нашу структуру «провайдер → модели»:

- Группируем по **owned_by** (провайдер), а не по namespace: у одного
  провайдера бывает несколько префиксов id (Claude: `cc/` + `claude/`), но
  заголовок один. **namespace** (префикс id до `/`) при этом сохраняется у
  КАЖДОЙ модели — для показа перед именем. Модификатор `no-think/` снимаем
  (это вариант базовой модели).
- Встроенный «зоопарк» OmniRoute (combo/auto, theoldllm, auggie, opencode,
  duckduckgo, chipotle, mimocode) сворачиваем в один синтетический провайдер
  **«OmniRoute default»** — он всегда ПОСЛЕДНИЙ (чтобы не мешать подключённым
  платным подпискам).
- Видео-модели (`type=video` / известные owned_by / veo|seedance в id)
  отсекаем — не для чат-CLI.
- Имя чистим от префикса namespace (`cc/Claude Opus 4.8` → `Claude Opus 4.8`),
  fallback на `root`/последний сегмент id.

Клиент рисует эту структуру (сворачиваемые провайдеры) и на шаге 1 (авторизация)
даёт назвать/выбрать модели. Тир-лимиты применяет КЛИЕНТ на шаге 2 — сервер тут
отдаёт полный каталог без ограничений.
"""
from __future__ import annotations

import json
import re
from typing import Any

import aiohttp
import structlog

log = structlog.get_logger("gateway.omniroute")

# Группируем по ПРОВАЙДЕРУ (owned_by), а не по namespace префикса id: у одного
# провайдера бывает несколько префиксов (Claude: cc/ = Claude Code-протокол +
# claude/ = OpenAI-формат; Codex: cx/+codex/+codex-auto-review/). Заголовок один
# на провайдера, а префикс сохраняется у каждой модели (namespace).

# owned_by видео-провайдеров (VEO/Seedance) — отсекаем полностью (не для чат-CLI).
VIDEO_OWNERS: frozenset[str] = frozenset({"veoaifree-web"})

# L: подстраховка, когда шлюз не проставил type/owned_by — ловим видео по id
# (veo*/seedance* как отдельный сегмент или начало id). Без этого seedance без
# type пролезал бы в чат-каталог.
_VIDEO_ID_RE = re.compile(r"(?:^|/)(?:veo|seedance)(?![a-z])", re.IGNORECASE)


def _is_video(model_id: str, owner: str, mtype: str) -> bool:
    return (mtype == "video" or owner in VIDEO_OWNERS
            or _VIDEO_ID_RE.search(model_id) is not None)

# owned_by встроенных бесплатных агрегаторов OmniRoute → «OmniRoute default».
BUILTIN_OWNERS: frozenset[str] = frozenset({
    "combo",           # мета-роутеры auto/*
    "theoldllm",
    "auggie",
    "opencode",
    "duckduckgo-web",
    "chipotle",
    "mimocode",
})

# Человеческие имена «реальных» провайдеров (по owned_by). Иначе — title-case.
OWNER_LABELS: dict[str, str] = {
    "claude": "Claude Code",
    "codex": "Codex",
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
    """namespace = первый сегмент id (после снятия no-think/). Без `/` namespace
    ПУСТ (L): иначе он равнялся бы всему id и дублировал имя модели в UI."""
    base, _ = _strip_nothink(model_id)
    return base.split("/", 1)[0] if "/" in base else ""


def _provider_label(owner: str) -> str:
    return OWNER_LABELS.get(owner) or owner.replace("-", " ").title()


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
    order: list[str] = []                 # owned_by реальных провайдеров, first-seen
    groups: dict[str, list[dict]] = {}    # provider_id → models
    seen_ids: set[str] = set()            # дедуп (veo дублируется и т.п.)

    for m in raw_models or []:
        mid = str(m.get("id") or "").strip()
        if not mid:
            continue
        owner = (m.get("owned_by") or "").strip() or "unknown"
        if _is_video(mid, owner, (m.get("type") or "")):   # не для чат-CLI
            continue
        # M/L: дедуп по полному id (с учётом no-think — это разные модели) ДО
        # создания группы. Иначе дубль id под ДРУГИМ owner заводил бы пустую
        # группу+order (пустой заголовок провайдера в UI).
        if mid in seen_ids:
            continue
        seen_ids.add(mid)
        ns = _namespace(mid)              # префикс id (для показа у модели)
        base_id, no_think = _strip_nothink(mid)
        is_builtin = owner in BUILTIN_OWNERS
        provider_id = DEFAULT_PROVIDER_ID if is_builtin else owner
        if provider_id not in groups:
            groups[provider_id] = []
            if not is_builtin:
                order.append(provider_id)
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


_MAX_CATALOG_BYTES = 8 * 1024 * 1024   # L: потолок тела ответа шлюза (8 MiB)


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
                # L: и ошибочное тело читаем с капом (base_url задаёт клиент).
                body = (await resp.content.read(4096)).decode("utf-8", "replace")
                raise RuntimeError(f"HTTP {resp.status}: {body[:200]}")
            # L: лимит тела — не читаем гигабайты в память с чужого base_url.
            # content_length может врать/отсутствовать (chunked) → быстрый фейл по
            # заголовку + реальный кап в цикле. ВАЖНО: read(n) у aiohttp — «до n»
            # из буфера (короткое чтение ~64К), а не весь ответ; читаем до EOF
            # чанками, иначе большой каталог обрезался бы посреди JSON. gzip
            # aiohttp разжимает в парсере → кап применяется к РАЗжатым байтам.
            if (resp.content_length or 0) > _MAX_CATALOG_BYTES:
                raise RuntimeError("catalog response too large")
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = await resp.content.read(64 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > _MAX_CATALOG_BYTES:
                    raise RuntimeError("catalog response too large")
                chunks.append(chunk)
            data = json.loads(b"".join(chunks))
    raw = data.get("data") if isinstance(data, dict) else data
    if not isinstance(raw, list):
        raise RuntimeError("unexpected /v1/models shape")
    cat = build_catalog(raw)
    log.info("omniroute.catalog", url=url,
             providers=len(cat["providers"]),
             total=sum(len(p["models"]) for p in cat["providers"]))
    return cat
