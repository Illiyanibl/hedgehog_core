"""WS-протокол v1 — pydantic-модели фреймов.

Source of truth: protocol/messages.md. Этот модуль — его дословный перевод
в код; любое расхождение чинится в сторону messages.md.

Входящие фреймы валидируются через `parse_client_frame` (typed union по
`type`), исходящие собираются через `make_frame`. Неизвестный `type` /
битый payload → BadFrame, отправитель получает error BAD_FRAME (§2, §9.4).
"""

from __future__ import annotations

import json
import time
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .ids import new_ulid

PROTOCOL_V = 1


# ---------- коды ошибок (§8) ----------

class Err:
    AUTH_FAILED = "AUTH_FAILED"
    BAD_FRAME = "BAD_FRAME"
    CHAT_NOT_FOUND = "CHAT_NOT_FOUND"
    CHAT_BUSY = "CHAT_BUSY"
    PERMISSION_TIMEOUT = "PERMISSION_TIMEOUT"
    AGENT_CRASH = "AGENT_CRASH"
    AUTH_REQUIRED = "AUTH_REQUIRED"
    FILE_NOT_FOUND = "FILE_NOT_FOUND"
    FILE_TOO_LARGE = "FILE_TOO_LARGE"
    RATE_LIMITED = "RATE_LIMITED"
    INTERNAL = "INTERNAL"


class BadFrame(Exception):
    """Невалидный входящий фрейм; message уходит клиенту в error BAD_FRAME."""


# ---------- payload-модели client→server (§3) ----------

class _Payload(BaseModel):
    # Forward-compat (§9.4): неизвестные поля игнорируем, не падаем.
    model_config = ConfigDict(extra="ignore")


class Attachment(_Payload):
    fileId: str
    mime: str
    name: str


class UserMsgPayload(_Payload):
    content: str
    attachments: list[Attachment] = Field(default_factory=list)
    # Метка отправителя для user_msg_echo (§4.15): "tg", "cli", "cron", ...
    sender: str | None = None


class PermissionResponsePayload(_Payload):
    related: str
    decision: Literal["allow", "deny", "allow_always"]


class PickerResponsePayload(_Payload):
    related: str
    option_id: str


class PtyWritePayload(_Payload):
    data: str


class PtyResizePayload(_Payload):
    rows: int = Field(ge=1, le=500)
    cols: int = Field(ge=1, le=1000)


class EmptyPayload(_Payload):
    pass


class CreateChatPayload(_Payload):
    name: str
    addressee: Literal["claude", "broker_shell"]
    cwd: str | None = None
    # §3.7 (non-breaking): MCP по именам из реестра + пресет прав.
    mcp: list[str] = Field(default_factory=list)
    permission_mode: Literal[
        "default", "acceptEdits", "bypassPermissions"] = "default"
    # §3.7 log_kb: размер транскрипта чата в КиБ. None → серверный дефолт
    # (TRANSCRIPT_DEFAULT_BYTES), 0 → транскрипт не пишется вовсе.
    log_kb: int | None = Field(default=None, ge=0)


class SetModePayload(_Payload):
    permission_mode: Literal["default", "acceptEdits", "bypassPermissions"]


class InstallSkillPayload(_Payload):
    # §skills v2: ссылка на git-репозиторий (github). default_for_new —
    # сразу пометить группу «по умолчанию для новых чатов».
    url: str = Field(min_length=1)
    default_for_new: bool = False


class SetSkillGroupPayload(_Payload):
    # Групповое вкл/выкл источника в ТЕКУЩЕМ чате (все скиллы группы вместе).
    source: str = Field(min_length=1)
    enabled: bool


class SetSkillDefaultPayload(_Payload):
    # Флаг «по умолчанию для новых чатов» у источника (глобально).
    source: str = Field(min_length=1)
    default_for_new: bool


class GetLogPayload(_Payload):
    tail: int = 50


class AuthCodePayload(_Payload):
    code: str = Field(min_length=1)


class ClientLogPayload(_Payload):
    # §14: строка(и) лога приложения. Ограничим размер одного кадра.
    text: str = Field(max_length=64 * 1024)


class DeleteChatPayload(_Payload):
    # §3.8: снести и рабочую папку чата (cwd), не только data/chats/<id>.
    delete_cwd: bool = False


class RenameChatPayload(_Payload):
    name: str = Field(min_length=1, max_length=200)


class AckPayload(_Payload):
    last_seen_id: str


class ResumePayload(_Payload):
    last_seen_id: str | None = None


# type → (payload-модель, нужен ли chatId в обёртке)
CLIENT_FRAME_TYPES: dict[str, tuple[type[_Payload], bool]] = {
    "user_msg": (UserMsgPayload, True),
    "permission_response": (PermissionResponsePayload, True),
    "picker_response": (PickerResponsePayload, True),
    "pty_write": (PtyWritePayload, True),
    "pty_resize": (PtyResizePayload, True),
    "subscribe_chat": (EmptyPayload, True),
    "unsubscribe_chat": (EmptyPayload, True),
    "create_chat": (CreateChatPayload, False),
    "set_mode": (SetModePayload, True),
    "list_skills": (EmptyPayload, True),
    "install_skill": (InstallSkillPayload, False),
    "set_skill_group": (SetSkillGroupPayload, True),
    "set_skill_default": (SetSkillDefaultPayload, False),
    "get_log": (GetLogPayload, True),
    "get_status": (EmptyPayload, True),
    "delete_chat": (DeleteChatPayload, True),
    "rename_chat": (RenameChatPayload, True),
    "list_chats": (EmptyPayload, False),
    "ack": (AckPayload, True),
    "resume": (ResumePayload, True),
    "ping": (EmptyPayload, False),
    # §13: авторизация Claude на сервере (глобальные, без chatId)
    "auth_start": (EmptyPayload, False),
    "auth_code": (AuthCodePayload, False),
    # §14: лог приложения-клиента (глобальный, без chatId)
    "client_log": (ClientLogPayload, False),
}


class ClientFrame(BaseModel):
    """Распарсенный и провалидированный входящий фрейм."""
    model_config = ConfigDict(extra="ignore")

    v: int
    id: str
    ts: float
    chatId: str | None = None
    type: str
    payload: Any  # конкретная модель из CLIENT_FRAME_TYPES


def parse_client_frame(raw: str | bytes) -> ClientFrame:
    """JSON → ClientFrame с типизированным payload. Кидает BadFrame."""
    try:
        obj = json.loads(raw)
    except (ValueError, UnicodeDecodeError) as e:
        raise BadFrame(f"invalid JSON: {e}") from e
    if not isinstance(obj, dict):
        raise BadFrame("frame must be a JSON object")

    ftype = obj.get("type")
    if not isinstance(ftype, str) or ftype not in CLIENT_FRAME_TYPES:
        raise BadFrame(f"unknown type: {ftype!r}")

    if obj.get("v") != PROTOCOL_V:
        raise BadFrame(f"unsupported protocol version: {obj.get('v')!r}")

    payload_model, needs_chat = CLIENT_FRAME_TYPES[ftype]
    try:
        frame = ClientFrame.model_validate(obj)
        frame.payload = payload_model.model_validate(obj.get("payload") or {})
    except ValidationError as e:
        raise BadFrame(f"payload validation failed for {ftype}: {e}") from e

    if needs_chat and not frame.chatId:
        raise BadFrame(f"{ftype} requires chatId")
    return frame


# ---------- сборка исходящих фреймов server→client (§4) ----------

def make_frame(ftype: str, payload: dict, chat_id: str | None = None) -> dict:
    """Готовый к json.dumps фрейм с обёрткой v/id/ts."""
    frame: dict[str, Any] = {
        "v": PROTOCOL_V,
        "id": new_ulid(),
        "ts": time.time(),
        "type": ftype,
        "payload": payload,
    }
    if chat_id is not None:
        frame["chatId"] = chat_id
    return frame


def make_error(code: str, message: str, chat_id: str | None = None,
               related: str | None = None) -> dict:
    payload: dict[str, Any] = {"code": code, "message": message}
    if related is not None:
        payload["related"] = related
    return make_frame("error", payload, chat_id)


def dumps(frame: dict) -> str:
    return json.dumps(frame, ensure_ascii=False, separators=(",", ":"))
