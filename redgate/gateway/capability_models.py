"""Strict API contracts for the widened 2.2 capability surface.

Every model forbids unknown fields so a client cannot smuggle an unbounded value
past the Gateway. Budget/ceiling values are validated against both Pydantic
bounds and (at request time) the mode ceiling in ``config/capabilities.yaml``.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

HostInput = Annotated[str, Field(min_length=1, max_length=253, pattern=r"^[A-Za-z0-9.:*\-]+$")]
#: A single mode ("pentest") or a composed spec ("pentest+ssl_tls_analysis").
#: Composition is validated against ``compose``/``max_modes`` at request time, so a
#: malformed combination is a 422 from the registry rather than from the schema.
ModeId = Annotated[
    str,
    Field(
        min_length=3,
        max_length=160,
        pattern=r"^[a-z][a-z0-9_]*(\+[a-z][a-z0-9_]*){0,5}$",
    ),
]

ExpansionKind = Literal["targets", "budget", "quota", "privilege"]
PrivilegeClass = Literal[
    "elevated_review",
    "destructive_confirmation",
    "credential_handling",
    "mass_scan_budget",
]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ExpansionRequestCreate(StrictModel):
    """Submit a mid-engagement expansion request; nothing changes until approved."""

    engagement_id: str = Field(min_length=3, max_length=64)
    kind: ExpansionKind
    mission_id: str | None = Field(default=None, max_length=64)
    roe_clause: str = Field(
        min_length=2,
        max_length=64,
        description="A clause declared in allowlist.yaml under expansion_clauses.",
    )
    justification: str = Field(min_length=12, max_length=800)
    targets: list[HostInput] = Field(default_factory=list, max_length=8)
    action_increase: int = Field(default=0, ge=0, le=64)
    seconds_increase: int = Field(default=0, ge=0, le=1800)
    quota_calls_increase: int = Field(default=0, ge=0, le=500)
    quota_tokens_increase: int = Field(default=0, ge=0, le=500000)
    privilege: PrivilegeClass | None = None

    @model_validator(mode="after")
    def only_relevant_fields(self) -> "ExpansionRequestCreate":
        if self.kind == "targets":
            if not self.targets:
                raise ValueError("A target expansion must propose at least one target.")
        elif self.targets:
            raise ValueError("Only a 'targets' expansion may carry targets.")
        if self.kind == "budget" and not (self.action_increase or self.seconds_increase):
            raise ValueError("A budget expansion must raise actions and/or seconds.")
        if self.kind == "quota" and not (self.quota_calls_increase or self.quota_tokens_increase):
            raise ValueError("A quota expansion must raise calls and/or tokens.")
        if self.kind == "privilege" and not self.privilege:
            raise ValueError("A privilege expansion must name a privilege class.")
        if self.kind != "privilege" and self.privilege:
            raise ValueError("Only a 'privilege' expansion may name a privilege class.")
        return self


class ExpansionDecision(StrictModel):
    decision: Literal["approved", "rejected"]
    note: str = Field(default="", max_length=500)


class TLSAuditRequest(StrictModel):
    engagement_id: str = Field(min_length=3, max_length=64)
    target: HostInput
    port: int = Field(default=443, ge=1, le=65535)
    mission_id: str | None = Field(default=None, max_length=64)
    include_hsts: bool = True


class BinaryTriageRequest(StrictModel):
    engagement_id: str = Field(min_length=3, max_length=64)
    artifact_path: str = Field(
        min_length=1,
        max_length=256,
        description="Path relative to REDGATE_ARTIFACT_DIR; never an absolute or parent path.",
    )

    @field_validator("artifact_path")
    @classmethod
    def relative_only(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned or cleaned.startswith(("/", "\\", "~")) or ".." in cleaned.split("/"):
            raise ValueError("Artifact paths must be relative and may not contain '..'.")
        if "\x00" in cleaned or not cleaned.isprintable():
            raise ValueError("Artifact path contains control characters.")
        return cleaned


class SessionStartRequest(StrictModel):
    """Session-start protocol: declare the mission and its governance envelope."""

    engagement_id: str = Field(min_length=3, max_length=64)
    mission_id: str | None = Field(default=None, max_length=64)
    mode_id: ModeId | None = None
    declare: bool = Field(
        default=True,
        description="Emit the session-start brief into the audit ledger.",
    )


class CapabilityQuery(StrictModel):
    engagement_id: str = Field(min_length=3, max_length=64)
    mode_id: ModeId
    capabilities: list[str] = Field(default_factory=list, max_length=32)
    principal_role: Literal["operator", "approver", "admin"] | None = None


class AgentPlanRequest(StrictModel):
    engagement_id: str = Field(min_length=3, max_length=64)
    mode_id: ModeId
    phase: str | None = Field(default=None, max_length=32)


class GateEvaluationRequest(StrictModel):
    """Evaluate already-observed findings against the seven-question gate."""

    engagement_id: str = Field(min_length=3, max_length=64)
    target: HostInput
    mission_id: str | None = Field(default=None, max_length=64)
    findings: list[dict[str, Any]] = Field(min_length=1, max_length=50)
    known_by_design: bool = False


class ModeToggleRequest(StrictModel):
    """Administrative toggle for the capability-mode allow-list."""

    enabled: bool
    modes: list[ModeId] | None = Field(
        default=None,
        max_length=8,
        description="Null means every manifest mode is permitted.",
    )


class ComposeRequest(StrictModel):
    """Ask the registry what a composition would resolve to, before declaring it."""

    modes: list[ModeId] = Field(min_length=1, max_length=6)


class ApproachRequest(StrictModel):
    """Observations in, a deterministic next-step plan out (advisory only)."""

    engagement_id: str = Field(min_length=3, max_length=64)
    target: HostInput
    mode_id: ModeId | None = None
    mission_id: str | None = Field(default=None, max_length=64)
    observations: dict[str, Any] = Field(default_factory=dict)
    already_run: list[str] = Field(default_factory=list, max_length=64)
