"""Strict, bounded API contracts for missions and anonymous HTTP evidence."""

from __future__ import annotations

import datetime as dt
import re
from typing import Annotated, Literal
from urllib.parse import unquote

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

HostInput = Annotated[str, Field(min_length=1, max_length=253, pattern=r"^[A-Za-z0-9.:\-]+$")]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class HTTPSettings(StrictModel):
    scheme: Literal["http", "https"] = "https"
    port: int | None = Field(default=None, ge=1, le=65535)
    path: str = Field(default="/", min_length=1, max_length=128)
    method: Literal["HEAD", "GET"] = "HEAD"
    body_preview_bytes: int = Field(default=0, ge=0, le=8192)

    @model_validator(mode="after")
    def origin_relative_path(self) -> HTTPSettings:
        decoded = unquote(self.path)
        if (
            not self.path.isascii()
            or re.search(r"%(?![0-9a-fA-F]{2})", self.path)
            or not decoded.startswith("/")
            or decoded.startswith("//")
            or any(c in decoded for c in "?#\\")
            or any(ord(c) < 32 or ord(c) == 127 for c in decoded)
        ):
            raise ValueError(
                "Use an origin-relative path without credentials, query, fragment or control characters."
            )
        if self.body_preview_bytes and self.method != "GET":
            raise ValueError(
                "Body previews require an explicit GET; the default HEAD stores no response body."
            )
        return self

    def tool_params(self) -> dict[str, str | int]:
        return {
            "scheme": self.scheme,
            "port": self.port or (443 if self.scheme == "https" else 80),
            "path": self.path,
            "method": self.method,
        }


class MissionCreateRequest(StrictModel):
    engagement_id: str = Field(min_length=3, max_length=64)
    name: str = Field(min_length=3, max_length=96)
    goal: str = Field(
        default="Read-only surface assessment and evidence review.", min_length=8, max_length=1000
    )
    targets: list[HostInput] = Field(min_length=1, max_length=8)
    skill_id: str = Field(default="web-surface-audit", min_length=3, max_length=64)
    http: HTTPSettings = Field(default_factory=HTTPSettings)
    capture_evidence: bool = True
    max_actions: int = Field(default=24, ge=1, le=128)
    max_seconds: int = Field(default=300, ge=10, le=3600)
    mode_id: str | None = Field(
        default=None,
        max_length=160,
        pattern=r"^[a-z][a-z0-9_]*(\+[a-z][a-z0-9_]*)*$",
        description=(
            "Optional operational mode. Accepts a single id (``pentest``) or a composed "
            "spec (``pentest+ssl_tls_analysis``). When set, the mission ceiling, mandatory "
            "capabilities and TLS obligation come from config/capabilities.yaml. Omitted "
            "missions keep the legacy 2.1 bounds."
        ),
    )

    @field_validator("name", "goal", mode="before")
    @classmethod
    def trim_description(cls, value: object) -> object:
        return value.strip() if isinstance(value, str) else value

    @model_validator(mode="after")
    def legacy_bounds_without_mode(self) -> "MissionCreateRequest":
        """Keep the 2.1 bounds unless a 2.2 mode explicitly widens the ceiling.

        The mode ceiling itself is enforced by ``CapabilityRegistry.enforce_ceiling``
        against ``config/capabilities.yaml``; this validator only stops a client
        from asking for 2.2-sized budgets while declaring no mode at all.
        """
        if self.mode_id is None:
            if self.max_actions > 64:
                raise ValueError("max_actions above 64 requires a declared mode_id.")
            if self.max_seconds > 1800:
                raise ValueError("max_seconds above 1800 requires a declared mode_id.")
        return self


class MissionControlRequest(StrictModel):
    action: Literal["start", "pause", "resume", "cancel"]


class EvidenceCaptureRequest(HTTPSettings):
    engagement_id: str = Field(min_length=3, max_length=64)
    target: HostInput


class RetestRequest(StrictModel):
    note: str = Field(default="", max_length=500)


class HTTPObservation(StrictModel):
    """Validate a service response before treating any of it as evidence."""

    url: str = Field(max_length=512)
    method: Literal["HEAD", "GET"]
    connected_ip: str = Field(max_length=45)
    status_code: int = Field(ge=100, le=599)
    request_headers: dict[str, str]
    response_headers: dict[str, str]
    body_preview: str = Field(default="", max_length=8192)
    body_truncated: bool = False
    body_omitted: str = Field(default="", max_length=128)
    captured_at: dt.datetime
    duration_ms: int = Field(ge=0, le=60000)
