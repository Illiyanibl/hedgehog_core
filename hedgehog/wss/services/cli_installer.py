"""CliInstallService: присутствие CLI, фоновая установка и cli_status.

Вынесено из HedgehogServer (wss/server.py) без изменения поведения и протокола:
проверка наличия/валидности типа CLI (create_chat/set_cli), фоновая установка
по пину compat.json (§cli-pins, single-flight на CLI), снимок hello.cliStatus и
рассылка cli_status (§18.7). Не путать с core/cli_install.py (сама установка).

Хост (сервер, см. services/base.CliInstallHost) передаётся в конструктор. Его
методы зовём как ``self.host._x(...)`` в момент вызова; config/hub/store —
property-прокси на хост. wss.server не импортируем.
"""

from __future__ import annotations

import asyncio
import threading
from typing import Any

import structlog

from ...core import models
from ...core import auth_store, cli_install, cli_registry, grok_auth
from ...protocol import Err, make_frame
from ... import i18n
from .base import CliInstallHost
from .cli_auth import LOGIN_MODULES

log = structlog.get_logger("wss")


class CliInstallService:
    def __init__(self, host: CliInstallHost):
        self.host = host
        # §cli-pins: фоновая установка CLI при set_cli/create_chat на
        # неустановленный (single-flight на CLI); чаты, ждущие установку (им —
        # error CLI_INSTALL_FAILED); флаги отмены потоков установки.
        self._cli_install_tasks: dict[str, asyncio.Task] = {}
        self._cli_install_chats: dict[str, set[str]] = {}
        self._cli_install_cancel: dict[str, Any] = {}

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

    async def shutdown(self) -> None:
        # §cli-pins: установки CLI — флаг отмены (поток urllib/subprocess
        # прерывается на следующем блоке) + отмена задач.
        for ev in self._cli_install_cancel.values():
            ev.set()
        cli_tasks = [t for t in self._cli_install_tasks.values() if not t.done()]
        for t in cli_tasks:
            t.cancel()
        if cli_tasks:
            await asyncio.gather(*cli_tasks, return_exceptions=True)
        self._cli_install_tasks.clear()

    # ---------- §multi-cli ----------

    def cli_present(self, cli_type: str) -> bool:
        spec = cli_registry.spec_for(cli_type)
        if spec is None:
            return False
        if spec.bundled or not spec.binary:
            return True
        return cli_registry.find_binary(cli_type) is not None

    def cli_error(self, cli_type: str, *, allow_install: bool = False
                   ) -> tuple[str, str] | None:
        """Валидация типа CLI для create_chat/set_cli: (код, текст) или None.
        allow_install: CLI не установлен, но в compat.json есть валидная запись
        для этой платформы (или установка уже идёт) — не ошибка, вызывающий
        запустит фоновую установку (start_cli_install)."""
        if cli_registry.spec_for(cli_type) is None:
            return Err.CLI_UNKNOWN, f"unknown cliType {cli_type!r}"
        if not self.cli_present(cli_type):
            if allow_install and (self._cli_installing(cli_type)
                                  or cli_install.installable(cli_type)):
                return None
            return Err.CLI_UNAVAILABLE, f"CLI {cli_type!r} is not installed"
        return None

    # ---------- §cli-pins: фоновая установка CLI ----------

    def _cli_installing(self, cli: str) -> bool:
        t = self._cli_install_tasks.get(cli)
        return t is not None and not t.done()

    def start_cli_install(self, cli: str, chat_id: str | None = None) -> None:
        """Запустить фоновую установку CLI (single-flight): CLI не установлен,
        в compat.json есть запись. Ждущие сессии этого CLI (воркер,
        cli_install.wait_pending) стартуют после неё."""
        if self.cli_present(cli):
            return
        if chat_id:
            self._cli_install_chats.setdefault(cli, set()).add(chat_id)
        if self._cli_installing(cli):
            return
        cancel = self._cli_install_cancel[cli] = threading.Event()
        task = asyncio.create_task(self._cli_install_job(cli, cancel),
                                   name=f"cli-install:{cli}")
        self._cli_install_tasks[cli] = task
        cli_install.track(cli, task)

    async def _cli_install_job(self, cli: str, cancel) -> None:
        res: dict = {"ok": False, "error": "cancelled"}
        try:
            log.info("cli.install_start", cli=cli)
            await self.host._broadcast_cli_status(cli, install=True)   # installing: true
            res = await asyncio.to_thread(cli_install.ensure_installed, cli,
                                          cancel=cancel)
        except asyncio.CancelledError:
            raise
        except Exception as e:  # noqa: BLE001 — сбой установки не роняет сервер
            res = {"ok": False, "error": f"{type(e).__name__}: {e}"}
        finally:
            if self._cli_install_tasks.get(cli) is asyncio.current_task():
                self._cli_install_tasks.pop(cli, None)
            self._cli_install_cancel.pop(cli, None)
        chats = self._cli_install_chats.pop(cli, set())
        log.info("cli.install_done", cli=cli, ok=res.get("ok"),
                 version=res.get("version"), err=res.get("error"))
        if res.get("ok"):
            self.host._invalidate_models_cache()
        else:
            for chat_id in sorted(chats):
                if self.store.get(chat_id) is None:
                    continue
                # Старый клиент кода не знает — ему хватит CLI_UNAVAILABLE
                # от воркера сессии на ждавший ход.
                await self.hub.publish(chat_id, "error", {
                    "code": Err.CLI_INSTALL_FAILED, "cliType": cli,
                    "message": i18n.Msg("cli.install_failed", cli=cli,
                                        error=str(res.get("error") or "")[:300])},
                    require_cap=cli_registry.MULTI_CLI_CAP)
        await self.host._broadcast_cli_status(cli, install=True)   # present, installing: false

    def cli_status_snapshot(self) -> dict[str, dict]:
        """hello.cliStatus (§18.3): present/auth_state/cliCapabilities по CLI."""
        out: dict[str, dict] = {}
        for cli_type, spec in cli_registry.CLI_SPECS.items():
            present = self.cli_present(cli_type)
            cache = models.load_cache(self.config, cli_type) if present else None
            if not present:
                state = "NO_CLI"
            elif (cli_type in LOGIN_MODULES
                  and auth_store.active_method(self.config, cli_type)
                  == auth_store.SUBSCRIPTION
                  and not LOGIN_MODULES[cli_type].is_logged_in()):
                state = "AUTH_REQUIRED"      # токена нет — проба не нужна
            elif self.host.cli_auth.token_rejected(cli_type):
                state = "AUTH_REQUIRED"      # MED-1: токен есть, но CLI ответил 401
            else:
                state = (cache or {}).get("auth_state") or "PENDING"
            out[cli_type] = {"present": present, "auth_state": state,
                             **self._install_flags(cli_type, present),
                             "cliCapabilities": list(spec.capabilities),
                             "experimental": spec.experimental,
                             # §auth: какие способы входа реализованы и какой активен
                             "authMethods": [
                                 m.public() for m in spec.auth_methods
                                 if not (cli_type == "grok"
                                         and grok_auth.managed_home() is None
                                         and m.id != cli_registry.AUTH_DEVICE_CODE)],
                             "activeMethod": auth_store.active_method(
                                 self.config, cli_type),
                             "authDetail": auth_store.detail(self.config, cli_type)}
        return out

    def _install_flags(self, cli: str, present: bool) -> dict:
        """§cli-pins (hello.cliStatus): installing — идёт фоновая установка;
        installable — CLI нет, но Ёжик поставит его при set_cli/create_chat.
        Поля добавочные и только когда true (иначе — как до фичи)."""
        if present:
            return {}
        if self._cli_installing(cli):
            return {"installing": True}
        if cli_registry.spec_for(cli) is not None and cli_install.installable(cli):
            return {"installable": True}
        return {}

    async def broadcast_cli_status(self, cli: str, *, install: bool = False) -> None:
        """cli_status (§18.7) — глобально, только клиентам multi_cli.
        §cli-pins: поле installing — в кадрах фоновой установки (install=True:
        старт → true, итог → false) и пока она идёт; иначе поля нет (= false)."""
        if not self.hub.any_conn_has_cap(cli_registry.MULTI_CLI_CAP):
            return
        snap = self.cli_status_snapshot().get(cli)
        if snap is None:
            return
        payload = {
            "cliType": cli, "present": snap["present"],
            "auth_state": snap["auth_state"],
            "activeMethod": snap["activeMethod"],
            "authDetail": snap["authDetail"]}
        if install or self._cli_installing(cli):
            payload["installing"] = self._cli_installing(cli)
        await self.hub.broadcast_global(make_frame("cli_status", payload),
                                        require_cap=cli_registry.MULTI_CLI_CAP)
