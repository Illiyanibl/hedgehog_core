"""ModelsRefresher: кэш/рефрешер списка моделей и models_list.

Вынесено из HedgehogServer (wss/server.py) без изменения поведения и протокола:
фоновый рефрешер кэша моделей (раз в сутки + по событию смены авторизации),
отмена one-shot пробы при ходе (§models M1) и троттлинг (M2), хендлер
list_models, источники omniroute/шлюза и рассылка models_list (§23).

Хост (сервер, см. services/base.ModelsHost) передаётся в конструктор. Его
методы зовём как ``self.host._x(...)`` в момент вызова; config/hub/store —
property-прокси на хост. wss.server не импортируем.
"""

from __future__ import annotations

import asyncio
import json
import time

import structlog

from ...core.claude_session import ClaudeSession
from ...core import models
from ...core import effort as effort_mod
from ...core import auth_store, cli_registry
from ...core.gateways import omniroute as omniroute_gw
from ...protocol import make_frame
from .base import ModelsHost

log = structlog.get_logger("wss")


class ModelsRefresher:
    def __init__(self, host: ModelsHost):
        self.host = host
        # §models: фоновый рефрешер списка моделей. Событие взводится при смене
        # авторизации (и при пустом кэше) → немедленное обновление вне суток.
        self._models_refresh_now = asyncio.Event()
        self._omni_models_sig: str | None = None   # последняя разосланная omni-выборка
        self._models_task: asyncio.Task | None = None
        # Текущая one-shot проба (для отмены при входящем user_msg — не держим
        # второй CLI-процесс во время хода, §models M1) + троттлинг проб (M2).
        self._models_probe_task: asyncio.Task | None = None
        self._last_probe_ts = 0.0

    # Прокси на хост: перенесённый код обращается к self.config/hub/store как раньше.
    @property
    def config(self):
        return self.host.config

    @property
    def hub(self):
        return self.host.hub

    @property
    def store(self):
        return self.host.store

    def start(self) -> None:
        # §models: фоновый рефрешер кэша моделей (раз в сутки + по событию).
        if self._models_task is None:
            self._models_task = asyncio.create_task(
                self._models_refresh_loop(), name="models-refresh")

    async def shutdown(self) -> None:
        probe = self._models_probe_task   # захватываем ДО отмены (её обнулит finally)
        self._cancel_models_probe()       # осиротевшую пробу тоже гасим
        if self._models_task is not None:
            self._models_task.cancel()
            # L: gather(return_exceptions) поглощает CancelledError/исключение
            # САМОЙ задачи, но пробрасывает отмену НАШЕГО shutdown (как у probe
            # ниже) — прежний `except (CancelledError, Exception)` глотал и её.
            await asyncio.gather(self._models_task, return_exceptions=True)
            self._models_task = None
        if probe is not None:             # дожать отменённую пробу (без warning)
            await asyncio.gather(probe, return_exceptions=True)

    # ---------- §models: фоновый рефрешер списка моделей ----------

    _MODELS_TTL = 24 * 3600      # штатный интервал обновления кэша
    _MODELS_RETRY = 120          # переспрос, если проба отложена (агент занят)
    _MODELS_MIN_INTERVAL = 60    # троттлинг: не чаще одной пробы CLI в минуту

    async def _models_refresh_loop(self) -> None:
        """Раз в сутки (и по событию смены авторизации) обновляет кэш моделей.
        Клиентский list_models кэш только ЧИТАЕТ — CLI тут не на его пути."""
        while True:
            delay = self._MODELS_TTL
            try:
                delay = await self._refresh_models_once()
            except asyncio.CancelledError:
                raise
            except Exception as e:  # noqa: BLE001 — рефрешер не должен падать
                log.warning("models.refresh_error", err=repr(e))
            try:
                await asyncio.wait_for(self._models_refresh_now.wait(),
                                       timeout=delay)
            except asyncio.TimeoutError:
                pass
            self._models_refresh_now.clear()

    async def _refresh_models_once(self) -> float:
        """Одна попытка обновить кэш. Возвращает СЛЕДУЮЩУЮ задержку (сек):
        занят агент → скоро (RETRY); проба недавно (троттл M2) → дождаться окна;
        успех/скип → сутки. Клиентский спам list_models так не плодит процессы."""
        # §omni S1: при активной omniroute-авторизации нового вида список — это
        # ВЫБРАННЫЕ пользователем модели (не CLI-проба). Не поднимаем CLI и
        # бродкастим выбранные, иначе рефрешер (проснувшийся на invalidate после
        # set_models) затёр бы omniroute-пикер CLI-алиасами.
        omni = self._omniroute_models_list(models.DEFAULT_CLI_TYPE)
        if omni is not None:
            # Рассылаем при первом проходе и при изменении выбора, а не на
            # каждом витке (иначе старые клиенты получали бы models_list каждые
            # 1–2 мин. во время длинных ходов — ревью §multi-cli).
            sig = json.dumps(omni, sort_keys=True, default=str)
            if sig != self._omni_models_sig:
                self._omni_models_sig = sig
                await self._broadcast_models_list(omni, models.DEFAULT_CLI_TYPE)
            # §multi-cli: другие CLI омни не касается — их модели обновляем.
            if all(t == models.DEFAULT_CLI_TYPE for t in models.KNOWN_CLI_TYPES):
                return self._MODELS_TTL
        else:
            self._omni_models_sig = None
        # Не поднимаем второй CLI-процесс Claude во время активного хода
        # (§models M1); пробы других CLI (`agy models`) ходу не мешают.
        if omni is None and any(
                isinstance(s, ClaudeSession) and s.status == "busy"
                for s in self.host.sessions.values()):
            log.info("models.refresh_deferred_busy")
            return self._MODELS_RETRY
        # Троттлинг: между реальными пробами не меньше _MODELS_MIN_INTERVAL —
        # иначе клиент, поллящий PENDING, гнал бы процессы спина к спине (M2).
        since = time.time() - self._last_probe_ts
        if since < self._MODELS_MIN_INTERVAL:
            return self._MODELS_MIN_INTERVAL - since
        self._last_probe_ts = time.time()

        # §cli-types: обновляем кэш КАЖДОГО известного типа CLI (сейчас один —
        # claude). Каждый тип — своя проба/кэш/бродкаст.
        for cli_type in models.KNOWN_CLI_TYPES:
            if omni is not None and cli_type == models.DEFAULT_CLI_TYPE:
                continue          # claude под omniroute — список уже разослан
            if self._gateway_models_list(cli_type) is not None:
                continue          # §auth: у шлюза список из выбора, CLI не пробуем
            # Проба — отдельной таской, чтобы входящий user_msg мог её отменить
            # (M1: не держим второй процесс во время хода).
            self._models_probe_task = asyncio.create_task(
                models.probe_models(self.config, str(self.config.data_dir),
                                    cli_type))
            try:
                data = await self._models_probe_task
            except asyncio.CancelledError:
                # Различаем отмену САМОГО рефрешера (shutdown отменил
                # _models_task — у текущей таски есть pending-cancel) от отмены
                # только пробы (user_msg → _cancel_models_probe отменил лишь
                # дочернюю таску). Не полагаемся на флаг: он мог бы «проглотить»
                # отмену рефрешера.
                cur = asyncio.current_task()
                if cur is not None and cur.cancelling() > 0:
                    raise                       # отменяют рефрешер (shutdown)
                log.info("models.probe_cancelled_busy", cli=cli_type)
                return self._MODELS_RETRY       # отменили пробу из-за хода
            finally:
                self._models_probe_task = None

            if data.get("auth_state") == "OK" and data.get("models"):
                data["updated_at"] = time.time()
                models.save_cache(self.config, data, cli_type)
                log.info("models.refreshed", cli=cli_type,
                         n=len(data["models"]), current=data.get("current"))
                # §models L1: клиенты на PENDING узнают о готовности.
                # Типы, скрытые от старых клиентов (§18.3), — только multi_cli.
                await self._broadcast_models_list(data, cli_type)
                if self.host.cli_auth.clear_token_rejected(cli_type):   # MED-1: токен снова работает
                    await self.host._broadcast_cli_status(cli_type)
            else:
                # Не затираем последний хороший кэш (auth/нет CLI/ошибка).
                log.info("models.refresh_skip", cli=cli_type,
                         auth=data.get("auth_state"),
                         present=data.get("cli_present"))
        return self._MODELS_TTL

    def _cancel_models_probe(self) -> None:
        """§models M1: отменить фоновую пробу `/model` (пришёл user_msg — не
        держим второй CLI-процесс рядом с ходом). Проба толерантна к отмене;
        _refresh_models_once отличит эту отмену от отмены рефрешера по
        current_task().cancelling()."""
        t = self._models_probe_task
        if t is not None and not t.done():
            t.cancel()

    def _invalidate_models_cache(self) -> None:
        """Смена авторизации: список моделей мог смениться. Гасим пробу в
        полёте (она под СТАРЫМИ кредами — иначе разослала бы стейл-список) и
        будим рефрешер на свежую пробу."""
        self._cancel_models_probe()
        self._models_refresh_now.set()

    # ---------- list_models / models_list (§models, §23) ----------

    async def _h_list_models(self, conn_id, frame, p):
        # §models/§cli-types: отдаём кэш нужного типа CLI МГНОВЕННО (CLI не
        # дёргаем). Неизвестный тип → UNSUPPORTED; нет кэша → PENDING + будим
        # фоновый рефрешер.
        data = self._models_data(p.cliType)
        if data.get("auth_state") == "PENDING":
            self._models_refresh_now.set()
        if not self.hub.conn_has_cap(conn_id, cli_registry.MULTI_CLI_CAP):
            data = effort_mod.strip(data)     # §23: legacy — прежняя форма
        await self.hub.send_global(
            conn_id, make_frame("models_list", data))
        return

    def _models_data(self, cli_type: str) -> dict:
        """models_list типа CLI в форме §23 (efforts/defaultEfforts/
        effortsDefault). Неизвестный тип → UNSUPPORTED; нет кэша → PENDING."""
        if cli_type not in models.KNOWN_CLI_TYPES:
            data = {"cliType": cli_type, "models": [], "current": None,
                    "raw": "", "auth_state": "UNSUPPORTED",
                    "cli_present": False, "updated_at": 0}
        elif (cli_type == models.DEFAULT_CLI_TYPE
              and (omni := self._omniroute_models_list(cli_type)) is not None):
            # §omni: при omniroute-авторизации Claude источник — ВЫБРАННЫЕ
            # модели (шаг 1), а не CLI-проба. Тир-лимит (первые N) применяет
            # клиент. Других CLI omniroute (вход Claude) не касается.
            data = omni
        elif (gw := self._gateway_models_list(cli_type)) is not None:
            data = gw       # §auth: шлюз другого CLI — выбранные модели
        else:
            # L7: load_cache уже нормализует — второй раз не гоняем (и auth
            # не перечитываем ради признака шлюза Claude).
            data = models.load_cache(self.config, cli_type)
            if data is not None:
                return data
            data = {"cliType": cli_type, "models": [], "current": None,
                    "raw": "", "auth_state": "PENDING",
                    "cli_present": None, "updated_at": 0}
        return models.normalize(self.config, data, cli_type)

    async def _broadcast_models_list(self, data: dict, cli_type: str) -> None:
        """§23: рассылка models_list — multi_cli получают форму §23, остальные —
        прежнюю (без efforts/defaultEfforts/effortsDefault). Типы, скрытые от
        старых клиентов (§18.3), — только multi_cli."""
        data = models.normalize(self.config, data, cli_type)
        spec = cli_registry.spec_for(cli_type)
        if spec is not None and not spec.legacy_visible:
            await self.hub.broadcast_global(
                make_frame("models_list", data),
                require_cap=cli_registry.MULTI_CLI_CAP)
            return
        await self.hub.broadcast_variants(
            make_frame("models_list", effort_mod.strip(data)),
            make_frame("models_list", data), cli_registry.MULTI_CLI_CAP)

    def _gateway_models_list(self, cli_type: str) -> dict | None:
        """§auth: models_list из выбранных моделей шлюза не-Claude CLI."""
        if cli_type == models.DEFAULT_CLI_TYPE:
            return None
        rec = auth_store.load(self.config, cli_type)
        if rec.get("catalog") and rec.get("method") in (auth_store.API_KEY,
                                                        auth_store.GATEWAY):
            # CLI с фиксированными моделями (Antigravity) под ключом: каталог API
            return {"cliType": cli_type, "models": list(rec["catalog"]),
                    "names": {i: i for i in rec["catalog"]},
                    "efforts": {i: [] for i in rec["catalog"]}, "current": None,
                    "source": "api", "raw": "", "auth_state": "OK",
                    "cli_present": True, "updated_at": 0}
        if rec.get("method") != auth_store.GATEWAY or not rec.get("models"):
            return None
        sel = rec["models"]
        return {"cliType": cli_type, "models": [m["id"] for m in sel],
                "names": {m["id"]: m.get("name") or m["id"] for m in sel},
                "efforts": {m["id"]: [] for m in sel},   # §23: под шлюзом не выбирается
                "current": rec.get("active_id"), "source": "gateway", "raw": "",
                "auth_state": "OK", "cli_present": True, "updated_at": 0}

    def _omniroute_models_list(self, cli_type: str) -> dict | None:
        """§omni: models_list из ВЫБРАННЫХ моделей (если активна omniroute-авториз.
        нового вида). Иначе None → обычный источник (CLI-проба). Тир НЕ режем —
        отдаём всё, первые N покажет клиент. omniroute — способ входа Claude:
        для других CLI всегда None (их список — свой)."""
        if cli_type != models.DEFAULT_CLI_TYPE:
            return None
        auth = self.config.load_auth_config()
        if auth.get("mode") != "omniroute" or not auth.get("active_id"):
            return None
        sel = auth.get("models") or []
        # Метка чипа в CLI-view = «алиас/имя» (напр. cc/Opus): алиас = префикс id
        # (namespace, no-think снят), имя — заданное пользователем.
        def _label(m: dict) -> str:
            name = m.get("name") or m["id"]
            alias = omniroute_gw._namespace(m["id"])
            return f"{alias}/{name}"
        return {
            "cliType": cli_type,
            "models": [m["id"] for m in sel],                       # compat: id-строки
            "names": {m["id"]: _label(m) for m in sel},             # id→«алиас/имя»
            "efforts": {m["id"]: [] for m in sel},                  # §23: шлюз
            "current": auth.get("active_id"),
            "source": "omniroute",
            "raw": "", "auth_state": "OK",
            "cli_present": True, "updated_at": 0,
        }
