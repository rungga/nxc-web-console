"""Pydantic request/response models shared across the API."""
from __future__ import annotations

import re
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator, model_validator

MAX_SCAN_TARGETS = 2048
MAX_CREDENTIAL_VALUES = 1024
MAX_MODULES = 64
MAX_MODULE_OPTIONS = 128
MAX_EXTRA_ARGS_LENGTH = 8192
MAX_SCAN_ARGUMENT_CHARS = 65_536

ProtocolValue = Annotated[str, StringConstraints(min_length=1, max_length=16, pattern=r"^[a-z0-9_-]+$")]
TargetValue = Annotated[str, StringConstraints(min_length=1, max_length=512)]
UsernameValue = Annotated[str, StringConstraints(min_length=1, max_length=512)]
SecretValue = Annotated[str, StringConstraints(min_length=1, max_length=2048)]
HashValue = Annotated[str, StringConstraints(min_length=1, max_length=512)]
ModuleNameValue = Annotated[str, StringConstraints(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")]


def _validate_password(value: str) -> str:
    classes = [
        any(c.islower() for c in value),
        any(c.isupper() for c in value),
        any(c.isdigit() for c in value),
        any(not c.isalnum() for c in value),
    ]
    if sum(classes) < 3:
        raise ValueError("Password must use at least three character classes")
    return value


class LoginRequest(BaseModel):
    username: str
    password: str


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str = Field(min_length=12, max_length=256)

    @field_validator("new_password")
    @classmethod
    def validate_new_password(cls, value: str) -> str:
        return _validate_password(value)


class UserCreateRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    password: str = Field(min_length=12, max_length=256)
    role: Literal["admin", "operator"] = "operator"

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        return _validate_password(value)


class UserUpdateRequest(BaseModel):
    role: Literal["admin", "operator"] | None = None
    enabled: bool | None = None


class UserPasswordResetRequest(BaseModel):
    new_password: str = Field(min_length=12, max_length=256)

    @field_validator("new_password")
    @classmethod
    def validate_new_password(cls, value: str) -> str:
        return _validate_password(value)


class UserResponse(BaseModel):
    username: str
    role: Literal["admin", "operator"]
    enabled: bool
    created_at: float
    updated_at: float


_SENSITIVE_CONTEXT_RE = re.compile(
    r"(?i)(?:password|passwd|credential|ntlm|hash|api[ _-]?key|access[ _-]?token)\s*[:=]|"
    r"\b[0-9a-f]{32,64}\b|://[^\s/:]+:[^\s/@]+@"
)


class AiSuggestionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    field: Literal[
        "execute_command",
        "execute_powershell",
        "module_options",
        "extra_args",
        "backconnect_command",
    ]
    protocol: str = Field(min_length=1, max_length=16, pattern=r"^[a-z0-9_-]+$")
    goal: str = Field(default="", max_length=400)
    modules: list[str] = Field(default_factory=list, max_length=8)
    shell_type: Literal["cmd", "powershell"] | None = None
    language: Literal["auto", "id", "en"] = "auto"

    @field_validator("goal")
    @classmethod
    def reject_sensitive_goal(cls, value: str) -> str:
        cleaned = value.strip()
        if _SENSITIVE_CONTEXT_RE.search(cleaned):
            raise ValueError("Do not include credentials, hashes, tokens, or API keys")
        return cleaned

    @field_validator("modules")
    @classmethod
    def validate_modules(cls, values: list[str]) -> list[str]:
        if any(not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", value) for value in values):
            raise ValueError("Invalid module name")
        return values


class AiSuggestion(BaseModel):
    title: str = Field(min_length=1, max_length=120)
    command: str = Field(min_length=1, max_length=2048)
    explanation: str = Field(min_length=1, max_length=500)
    risk: Literal["low", "medium", "high"]


class AiSuggestionResponse(BaseModel):
    provider: str
    model: str | None = None
    language: Literal["id", "en"]
    suggestions: list[AiSuggestion]
    notice: str


class AiStatusResponse(BaseModel):
    available: bool
    provider: str
    model: str | None = None
    mode: Literal["local", "remote"]


class ModuleOption(BaseModel):
    model_config = ConfigDict(extra="forbid")

    key: str = Field(min_length=1, max_length=128)
    value: str = Field(max_length=2048)


class ScanRequest(BaseModel):
    """Maps 1:1 to how you'd invoke `nxc <protocol> <targets> <flags>` on the CLI."""

    model_config = ConfigDict(extra="forbid")

    protocol: ProtocolValue
    targets: list[TargetValue] = Field(default_factory=list, max_length=MAX_SCAN_TARGETS)

    username: list[UsernameValue] = Field(default_factory=list, max_length=MAX_CREDENTIAL_VALUES)
    password: list[SecretValue] = Field(default_factory=list, max_length=MAX_CREDENTIAL_VALUES)
    hashes: list[HashValue] = Field(default_factory=list, max_length=MAX_CREDENTIAL_VALUES)
    domain: str | None = Field(default=None, max_length=255)

    kerberos: bool = False
    local_auth: bool = False

    execute_command: str | None = Field(default=None, max_length=16_384)       # -x
    execute_powershell: str | None = Field(default=None, max_length=16_384)    # -X
    exec_method: str | None = Field(default=None, max_length=64)               # --exec-method
    no_output: bool = False

    modules: list[ModuleNameValue] = Field(default_factory=list, max_length=MAX_MODULES)
    module_options: list[ModuleOption] = Field(default_factory=list, max_length=MAX_MODULE_OPTIONS)

    extra_args: str = Field(default="", max_length=MAX_EXTRA_ARGS_LENGTH)

    workspace: str | None = Field(default=None, max_length=128)

    @model_validator(mode="after")
    def validate_total_argument_size(self) -> "ScanRequest":
        values = [
            *self.targets,
            *self.username,
            *self.password,
            *self.hashes,
            *self.modules,
            self.domain or "",
            self.execute_command or "",
            self.execute_powershell or "",
            self.exec_method or "",
            self.extra_args,
            self.workspace or "",
            *(f"{option.key}={option.value}" for option in self.module_options),
        ]
        if sum(len(value.encode("utf-8")) for value in values) > MAX_SCAN_ARGUMENT_CHARS:
            raise ValueError("Combined scan arguments exceed the 64 KiB request limit")
        return self


class JobSummary(BaseModel):
    id: str
    protocol: str
    command_preview: str
    status: str
    started_at: float
    finished_at: float | None = None
    return_code: int | None = None
    pwned_hosts: list[str] = Field(default_factory=list)


class JobDetail(JobSummary):
    argv: list[str]
    log_tail: list[str] = Field(default_factory=list)


class BackConnectListenerRequest(BaseModel):
    port: int = Field(gt=0, lt=65536)
    allowed_source: str = Field(min_length=1, max_length=64)
    label: str | None = None


class BackConnectTriggerRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    protocol: ProtocolValue
    target: TargetValue
    workspace: str = Field(default="default", min_length=1, max_length=128)
    username: list[UsernameValue] = Field(default_factory=list, max_length=MAX_CREDENTIAL_VALUES)
    password: list[SecretValue] = Field(default_factory=list, max_length=MAX_CREDENTIAL_VALUES)
    hashes: list[HashValue] = Field(default_factory=list, max_length=MAX_CREDENTIAL_VALUES)
    domain: str | None = Field(default=None, max_length=255)
    kerberos: bool = False
    local_auth: bool = False

    command: str = Field(min_length=1, max_length=16_384)
    shell_type: str = Field(pattern="^(cmd|powershell)$")
    confirm_authorized: bool = False
    exec_method: str | None = Field(default=None, max_length=64)
    extra_args: str = Field(default="", max_length=MAX_EXTRA_ARGS_LENGTH)

    @model_validator(mode="after")
    def validate_total_argument_size(self) -> "BackConnectTriggerRequest":
        values = [
            self.target,
            self.workspace,
            *self.username,
            *self.password,
            *self.hashes,
            self.domain or "",
            self.command,
            self.exec_method or "",
            self.extra_args,
        ]
        if sum(len(value.encode("utf-8")) for value in values) > MAX_SCAN_ARGUMENT_CHARS:
            raise ValueError("Combined back-connect arguments exceed the 64 KiB request limit")
        return self
