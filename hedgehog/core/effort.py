"""§23: единый контракт уровня рассуждения (effort) для всех CLI.

models_list каждого CLI несёт:
  efforts        {modelId: [уровни]} — ключ для КАЖДОЙ модели из models,
                 [] — уровень у модели не выбирается;
  defaultEfforts {modelId: уровень}  — где CLI его сообщает;
  effortsDefault [уровни]           — уровни при model=null (дефолт CLI).
Уровни всегда по возрастанию по канону CANON; неизвестные — в хвост в
исходном порядке. Метки не шлём (клиент локализует сам).

Модуль без зависимостей от остального ядра: признак «Claude под шлюзом»
вычисляет вызывающий (claude_session.claude_via_gateway) и передаёт флагом.
"""
from __future__ import annotations

from typing import Any

# Канонический порядок (по возрастанию). none/minimal — в начало, если встретятся.
CANON: tuple[str, ...] = ("none", "minimal", "low", "medium", "high", "xhigh",
                          "max", "ultra")
_RANK = {lvl: i for i, lvl in enumerate(CANON)}

# Источники models_list, где effort не выбирается (шлюзы: модели любые, флаг
# --effort/reasoning у них не гарантирован).
GATEWAY_SOURCES = frozenset({"gateway", "omniroute", "api"})

# CLI без выбора уровня вовсе.
NO_EFFORT_CLIS = frozenset({"antigravity"})

# Claude: статическая таблица по алиасам `/model` (CLI уровни не сообщает).
# ПЕРЕСМОТРЕТЬ при смене пина claude-agent-sdk / Claude Code (EffortLevel SDK
# и набор алиасов могут измениться). Полный id (claude-opus-…, claude-haiku-…)
# → уровни семейства по подстроке; не распознан → [].
_CLAUDE_FULL = ("low", "medium", "high", "xhigh", "max")
CLAUDE_EFFORTS: dict[str, tuple[str, ...]] = {
    "default": _CLAUDE_FULL,
    "best": _CLAUDE_FULL,
    "opus": _CLAUDE_FULL,
    "opusplan": _CLAUDE_FULL,
    "sonnet": _CLAUDE_FULL,
    "fable": _CLAUDE_FULL,
    "haiku": ("low", "medium", "high"),
}


def sort_levels(levels: Any) -> list[str]:
    """Отсортировать уровни по канону (по возрастанию), без дублей; неизвестные
    строки — в хвост в исходном порядке. Не-строки/пустые отбрасываются."""
    seen: set[str] = set()
    known: list[str] = []
    unknown: list[str] = []
    for lvl in levels if isinstance(levels, (list, tuple)) else []:
        if not isinstance(lvl, str) or not lvl or lvl in seen:
            continue
        seen.add(lvl)
        (known if lvl in _RANK else unknown).append(lvl)
    known.sort(key=_RANK.__getitem__)
    return known + unknown


def _claude_alias(model: str) -> str:
    m = model.strip().lower()
    if m.endswith("[1m]"):
        m = m[:-4]
    return m


# Семейства для полного id (порядок проверки не важен: id несёт одно семейство).
_CLAUDE_FAMILIES = ("opus", "sonnet", "haiku", "fable")


def claude_efforts(model: str | None) -> list[str]:
    """Уровни Claude для алиаса (регистр не важен, суффикс [1m] отбрасывается).
    None → default. Полный id (claude-opus-4-8, us.anthropic.claude-haiku-…) →
    уровни семейства по подстроке. Не распознан → []."""
    if model is None:
        model = "default"
    alias = _claude_alias(model)
    lv = CLAUDE_EFFORTS.get(alias)
    if lv is None and "claude-" in alias:
        fam = next((f for f in _CLAUDE_FAMILIES if f in alias), None)
        lv = CLAUDE_EFFORTS.get(fam) if fam else None
    return list(lv or ())


def union_levels(efforts: Any) -> list[str]:
    """Объединение уровней всех моделей в каноническом порядке."""
    if not isinstance(efforts, dict):
        return []
    return sort_levels([lv for v in efforts.values()
                        if isinstance(v, (list, tuple)) for lv in v])


def normalize(data: dict[str, Any], cli: str, *,
              gateway: bool = False) -> dict[str, Any]:
    """models_list → форма §23 (новый dict, вход не меняется).

    gateway=True — CLI под шлюзом/ключом с base_url: уровни не выбираются."""
    out = dict(data)
    ids = [m for m in (data.get("models") or []) if isinstance(m, str)]
    raw = data.get("efforts") if isinstance(data.get("efforts"), dict) else {}
    no_effort = (gateway or cli in NO_EFFORT_CLIS
                 or data.get("source") in GATEWAY_SOURCES)
    efforts: dict[str, list[str]] = {}
    for mid in ids:
        if no_effort:
            efforts[mid] = []
        elif cli == "claude":
            efforts[mid] = claude_efforts(mid)
        else:
            efforts[mid] = sort_levels(raw.get(mid))
    rawd = (data.get("defaultEfforts")
            if isinstance(data.get("defaultEfforts"), dict) else {})
    defaults = {} if no_effort else {
        k: v for k, v in rawd.items()
        if k in efforts and isinstance(v, str) and v in efforts[k]}
    if no_effort or not ids:          # шлюз / списка ещё нет (PENDING и т.п.)
        eff_default: list[str] = []
    elif cli == "claude":
        eff_default = efforts.get("default") or claude_efforts(None)
    else:
        cur = data.get("current")
        if isinstance(cur, str) and cur in efforts:
            eff_default = list(efforts[cur])
        else:
            # дефолтная модель CLI неизвестна → объединение уровней всех моделей
            eff_default = union_levels(efforts)
    out["efforts"] = efforts
    out["defaultEfforts"] = defaults
    out["effortsDefault"] = eff_default
    return out


def strip(data: dict[str, Any]) -> dict[str, Any]:
    """Прежняя (до §23) форма для соединений без multi_cli."""
    return {k: v for k, v in data.items()
            if k not in ("efforts", "defaultEfforts", "effortsDefault")}


def _lookup(efforts: dict, model: str) -> list[str] | None:
    """efforts[model] без учёта регистра (точное совпадение — приоритетно)."""
    if model in efforts:
        return list(efforts[model])
    low = model.lower()
    for k, v in efforts.items():
        if isinstance(k, str) and k.lower() == low:
            return list(v)
    return None


def levels_for(data: dict[str, Any] | None, model: str | None,
               cli: str | None = None) -> list[str] | None:
    """Допустимые уровни для model. None = неизвестно (кэша нет/PENDING или
    уровней нет ни у одной модели) — тогда не валидируем, уровень как есть.

    cli — тип CLI (по умолчанию data["cliType"]). Модель ищется без учёта
    регистра. model=None → effortsDefault; у Codex/Grok при неизвестной
    дефолтной модели (current нет в списке) — объединение уровней всех моделей.
    Модель не из списка: Claude — по таблице алиасов/семейству
    (claude_efforts), нераспознанный id — объединение уровней Claude; Codex/
    Grok — объединение известных уровней CLI. Под шлюзом (effortsDefault []
    у Claude, source-шлюз) — []."""
    if (not isinstance(data, dict) or data.get("auth_state") not in (None, "OK")
            or not data.get("models") or not isinstance(data.get("efforts"), dict)):
        return None
    cli = cli or data.get("cliType")
    efforts = data["efforts"]
    eff_default = data.get("effortsDefault")
    no_effort = (cli in NO_EFFORT_CLIS or data.get("source") in GATEWAY_SOURCES
                 or (cli == "claude" and not eff_default))
    if model is None:
        if no_effort:
            return []
        if cli != "claude":
            cur = data.get("current")
            if not (isinstance(cur, str) and cur in efforts):
                return union_levels(efforts) or None
        return list(eff_default) if isinstance(eff_default, list) else None
    found = _lookup(efforts, model)
    if found is not None:
        return found
    if no_effort:
        return []
    if cli == "claude":
        return claude_efforts(model) or list(_CLAUDE_FULL)
    return union_levels(efforts) or None


class UnknownEffort(ValueError):
    """Уровень не из efforts[model] (список непуст)."""


def validate(data: dict[str, Any] | None, model: str | None,
             effort: str | None, cli: str | None = None) -> str | None:
    """Значение effort для сохранения. None/"" → None. Неизвестно (levels_for →
    None) → как есть. Список пуст → None. Уровень есть → он. Иначе —
    UnknownEffort."""
    if not effort:
        return None
    levels = levels_for(data, model, cli)
    if levels is None:
        return effort
    if not levels:
        return None
    if effort in levels:
        return effort
    raise UnknownEffort(effort)


def reconcile(data: dict[str, Any] | None, model: str | None,
              stored: str | None, cli: str | None = None) -> str | None:
    """Смена модели без effort: сохранённый уровень, если он допустим для новой
    модели (или допустимость неизвестна), иначе None."""
    if not stored:
        return None
    levels = levels_for(data, model, cli)
    if levels is None or stored in levels:
        return stored
    return None
