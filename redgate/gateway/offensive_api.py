"""Authenticated API for the 2.3 offensive surface.

Everything the prompt asks an operator to *drive* has an endpoint here, and
every refusal is written to the audit ledger before the HTTP error is returned —
an attempted widening must be visible even when it is denied.

Surface map (prefix ``/api/v1/offensive``):

* ``GET  /posture`` / ``POST /posture``        — per-engagement control posture
* ``POST /consent`` / ``GET /consent``          — operator consent records
* ``GET  /policy``                              — resolved policy rows + posture
* ``POST /decide``                              — "may I run this?" before running
* ``GET  /tools``                               — the catalog, grouped
* ``POST /tools/run``                           — governed tool execution
* ``POST /findings`` … ``POST /findings/{id}/verify`` — PoC lifecycle
* ``GET/POST /chains``                          — attack chains from verified findings
* ``POST /explore/discover`` … ``/explore/mass-scan`` — recursive discovery + budgets
* ``POST /bounty/programs`` … ``/reports``      — bug-bounty workflow
* ``POST /pwntools/run`` / ``GET /pwntools/status``
* ``POST /loops`` … ``/brain``                  — hunt loops + persistent brain
* ``GET  /brief``                               — the Session Start Protocol brief
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any, Callable, Iterator

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from gateway.auth import OperatorPrincipal
from gateway.bugbounty import BountyError, BugBountyService
from gateway.capabilities import CapabilityRegistry
from gateway.db import Database
from gateway.evidence import redact_text
from gateway.exploitation import ExploitError, ExploitationService
from gateway.exploration import ExplorationError, ExplorationService
from gateway.hunt_loop import HuntLoopError, HuntLoopService
from gateway.offensive_policy import HIGH_IMPACT_POLICIES, OffensivePolicyEngine
from gateway.pwntools_layer import PwntoolsError, PwntoolsLayer
from gateway.scan_runner import ScanRunner
from gateway.workspace_store import WorkspaceStore

_SERVICE_ERRORS = (
    ExploitError,
    ExplorationError,
    BountyError,
    PwntoolsError,
    HuntLoopError,
    ValueError,
)


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------
class PostureRequest(BaseModel):
    engagement_id: str
    posture_id: str
    justification: str = Field(default="", max_length=1000)


class ConsentRequest(BaseModel):
    engagement_id: str
    policy_id: str
    statement: str = Field(min_length=20, max_length=4000)


class DecisionRequest(BaseModel):
    engagement_id: str
    action: str = Field(min_length=3, max_length=120)
    tool_name: str | None = Field(default=None, max_length=80)
    policy_id: str | None = Field(default=None, max_length=120)
    mission_mode: str | None = Field(default=None, max_length=60)


class ToolRunRequest(BaseModel):
    engagement_id: str
    tool: str = Field(min_length=1, max_length=80)
    target: str = Field(min_length=1, max_length=2048)
    flags: list[str] = Field(default_factory=list, max_length=12)
    mission_id: str | None = None
    timeout_sec: int = Field(default=60, ge=1, le=300)


class FindingDraftRequest(BaseModel):
    engagement_id: str
    target: str
    vulnerability: str = Field(min_length=3, max_length=300)
    poc_body: str = Field(min_length=1, max_length=200_000)
    language: str = "python"
    severity: str = "high"
    mission_id: str | None = None
    reproduction_steps: list[str] = Field(default_factory=list, max_length=40)


class ExecutionRecordRequest(BaseModel):
    output: str = Field(default="", max_length=500_000)
    success: bool = True
    exit_code: int = 0


class VerifyRequest(BaseModel):
    reproduced_output: str = Field(default="", max_length=500_000)
    note: str = Field(default="", max_length=500)


class ChainRequest(BaseModel):
    engagement_id: str
    step_ids: list[str] = Field(min_length=2, max_length=20)
    rationale: str = Field(min_length=10, max_length=2000)
    mission_id: str | None = None


class ChainValidateRequest(BaseModel):
    engagement_id: str
    chain_id: str
    reproduce_step: int | None = Field(default=None, ge=1, le=40)
    reproduced: bool
    note: str = Field(default="", max_length=500)


class DiscoverRequest(BaseModel):
    engagement_id: str
    candidates: list[str] = Field(min_length=1, max_length=200)
    mission_id: str | None = None
    propose: bool = False
    justification: str = Field(default="", max_length=2000)


class MassScanRequest(BaseModel):
    engagement_id: str
    target_count: int = Field(ge=1, le=4096)
    request_count: int = Field(ge=1, le=1_000_000)
    mission_id: str | None = None
    justification: str = Field(min_length=10, max_length=2000)


class ProgramRequest(BaseModel):
    engagement_id: str
    platform: str
    handle: str = Field(min_length=1, max_length=120)
    display_name: str = Field(default="", max_length=200)
    scope_entries: list[Any] = Field(default_factory=list, max_length=500)


class DuplicateRequest(BaseModel):
    program_id: str
    finding_key: str = Field(min_length=3, max_length=200)
    endpoint: str = Field(default="", max_length=400)
    title: str = Field(default="", max_length=300)
    summary: str = Field(default="", max_length=2000)


class ReportDraftRequest(BaseModel):
    engagement_id: str
    exploit_id: str
    program_id: str | None = None
    check_id: str | None = None
    repro_command: str = Field(default="", max_length=4000)
    impact: str = Field(default="", max_length=8000)
    remediation: str = Field(default="", max_length=8000)


class PwntoolsRunRequest(BaseModel):
    engagement_id: str
    action: str
    target: str = Field(default="", max_length=2048)
    artifact_path: str | None = Field(default=None, max_length=500)
    source: str = Field(default="", max_length=64_000)
    hex_bytes: str = Field(default="", max_length=64_000)
    length: int = Field(default=64, ge=1, le=65536)
    arch: str = Field(default="amd64", max_length=20)
    registers: list[str] = Field(default_factory=list, max_length=8)
    script: str = Field(default="", max_length=64_000)
    mission_id: str | None = None


class LoopRequest(BaseModel):
    engagement_id: str
    role_id: str = Field(min_length=3, max_length=80)
    hypothesis: str = Field(min_length=12, max_length=2000)
    mission_id: str | None = None
    max_iterations: int = Field(default=8, ge=1, le=64)


class LoopIterateRequest(BaseModel):
    note: str = Field(min_length=3, max_length=8000)
    status: str | None = None


class GateAnswersRequest(BaseModel):
    answers: dict[str, str] = Field(default_factory=dict)
    evidence_ref: str = Field(default="", max_length=400)


class BrainNoteRequest(BaseModel):
    engagement_id: str
    kind: str = "note"
    content: str = Field(min_length=1, max_length=8000)
    loop_id: str | None = None
    role_id: str = Field(default="", max_length=80)
    evidence_ref: str = Field(default="", max_length=400)
    mission_id: str | None = None


# ---------------------------------------------------------------------------
def offensive_router(
    *,
    db: Database,
    policies: OffensivePolicyEngine,
    exploitation: ExploitationService,
    exploration: ExplorationService,
    bounty: BugBountyService,
    pwntools: PwntoolsLayer,
    loops: HuntLoopService,
    runner: ScanRunner,
    registry: CapabilityRegistry,
    store: WorkspaceStore,
    get_principal: Callable[..., OperatorPrincipal],
    ensure_access: Callable[[OperatorPrincipal, str], None],
) -> APIRouter:
    router = APIRouter(prefix="/api/v1/offensive", tags=["Offensive surface · 2.3"])

    def audit_refusal(
        principal: OperatorPrincipal,
        engagement_id: str,
        action: str,
        reason: str,
        target: str = "-",
    ) -> None:
        db.write_audit_log(
            engagement_id=engagement_id,
            operator_id=principal.operator_id,
            target=target,
            tool_or_script=f"offensive:{action}",
            status="rejected",
            rejection_reason=redact_text(reason)[:500],
        )

    @contextmanager
    def guarded(
        principal: OperatorPrincipal,
        engagement_id: str,
        action: str,
        target: str = "-",
    ) -> Iterator[None]:
        try:
            yield
        except PermissionError as exc:
            audit_refusal(principal, engagement_id, action, str(exc), target)
            raise HTTPException(status_code=403, detail=redact_text(str(exc))[:500]) from exc
        except _SERVICE_ERRORS as exc:
            audit_refusal(principal, engagement_id, action, str(exc), target)
            raise HTTPException(status_code=422, detail=redact_text(str(exc))[:500]) from exc

    # ------------------------------------------------------------------
    # Posture, consent, decision
    # ------------------------------------------------------------------
    @router.get("/policy")
    async def policy_surface(
        engagement_id: str | None = Query(default=None),
        principal: OperatorPrincipal = Depends(get_principal),
    ) -> dict[str, Any]:
        if engagement_id:
            ensure_access(principal, engagement_id)
        posture = policies.posture(engagement_id) if engagement_id else policies.posture(None)
        rows = policies.list_policies()
        high_impact_rows = [
            row for row in rows if row["policy_id"] in HIGH_IMPACT_POLICIES
        ]
        return {
            "postures": policies.list_policies("posture"),
            # High-impact rows are stored under their own policy_type
            # (exploitation / credential / mass_scan), so they are collected by id
            # rather than by type; otherwise this list would silently be empty.
            "policies": high_impact_rows,
            "tools": [r for r in rows if r["policy_id"].startswith("tool:")],
            "high_impact": sorted(HIGH_IMPACT_POLICIES),
            "active_posture": posture.policy_id,
            "control_model": {
                "default_posture": "posture:permissive_in_scope",
                "two_person_only_for": sorted(HIGH_IMPACT_POLICIES),
                "scope_always_enforced": True,
                "note": (
                    "Permissive within the declared scope. Two-person approval is reserved "
                    "for high-impact actions; it is not the default for active testing."
                ),
            },
        }

    @router.get("/posture")
    async def get_posture(
        engagement_id: str, principal: OperatorPrincipal = Depends(get_principal)
    ) -> dict[str, Any]:
        ensure_access(principal, engagement_id)
        posture = policies.posture(engagement_id)
        return {
            "engagement_id": engagement_id,
            "posture": posture.describe(),
            "consent_met": policies.has_consent(
                operator_id=principal.operator_id,
                level=posture.consent_required,
                engagement_id=engagement_id,
                policy=posture,
            ),
            "two_person_required_for": sorted(HIGH_IMPACT_POLICIES),
        }

    @router.post("/posture")
    async def set_posture(
        request: PostureRequest, principal: OperatorPrincipal = Depends(get_principal)
    ) -> dict[str, Any]:
        ensure_access(principal, request.engagement_id)
        with guarded(principal, request.engagement_id, "set_posture"):
            if not principal.can_approve():
                raise PermissionError("Only an approver may change an engagement's posture.")
            policies.set_posture(request.engagement_id, request.posture_id, principal.operator_id)
            db.write_audit_log(
                engagement_id=request.engagement_id,
                operator_id=principal.operator_id,
                target=request.engagement_id,
                tool_or_script="offensive:set_posture",
                params={
                    "posture_id": request.posture_id,
                    "justification": request.justification[:500],
                },
                status="completed",
                stdout_summary=f"Posture set to {request.posture_id}.",
            )
            return {
                "engagement_id": request.engagement_id,
                "posture_id": request.posture_id,
                "set_by": principal.operator_id,
                "note": (
                    "Changing posture does not grant consent and never widens the allowlist."
                ),
            }

    @router.post("/consent")
    async def grant_consent(
        request: ConsentRequest, principal: OperatorPrincipal = Depends(get_principal)
    ) -> dict[str, Any]:
        ensure_access(principal, request.engagement_id)
        with guarded(principal, request.engagement_id, "consent", request.policy_id):
            record = policies.grant_consent(
                principal=principal,
                level=policies.get(request.policy_id).consent_required
                if policies.get(request.policy_id)
                else "operator",
                engagement_id=request.engagement_id,
                policy_id=request.policy_id,
                statement=request.statement,
            )
            db.write_audit_log(
                engagement_id=request.engagement_id,
                operator_id=principal.operator_id,
                target=request.policy_id,
                tool_or_script="offensive:consent",
                params={"policy_id": request.policy_id, "consent_id": record.get("consent_id")},
                status="completed",
                stdout_summary=f"Consent recorded for {request.policy_id}.",
            )
            return record

    @router.get("/consent")
    async def list_consent(
        engagement_id: str,
        principal: OperatorPrincipal = Depends(get_principal),
    ) -> dict[str, Any]:
        ensure_access(principal, engagement_id)
        return {
            "engagement_id": engagement_id,
            "consents": db.list_consents(engagement_id=engagement_id, operator_id=principal.operator_id),
        }

    @router.post("/decide")
    async def decide(
        request: DecisionRequest, principal: OperatorPrincipal = Depends(get_principal)
    ) -> dict[str, Any]:
        """Answer "may I run this?" without running it. Never refuses to answer."""
        ensure_access(principal, request.engagement_id)
        decision = policies.evaluate_action(
            principal=principal,
            engagement_id=request.engagement_id,
            action=request.action,
            tool_name=request.tool_name,
            policy_id=request.policy_id,
            mission_mode=request.mission_mode,
        )
        return decision.to_dict()

    # ------------------------------------------------------------------
    # Tool surface
    # ------------------------------------------------------------------
    @router.get("/tools")
    async def tools(
        category: str | None = Query(default=None),
        principal: OperatorPrincipal = Depends(get_principal),
    ) -> dict[str, Any]:
        from mcp_server.catalog import catalog_size, category_counts, grouped, list_tools

        del principal  # authenticated, no engagement context needed
        return {
            "count": catalog_size(),
            "categories": category_counts(),
            "tools": list_tools(category) if category else grouped(),
            "installed_on_this_image": runner.installed_tools(),
            "note": (
                "A tool appears here regardless of whether its binary is installed; "
                "'installed_on_this_image' is the honest subset that can actually run."
            ),
        }

    @router.post("/tools/run")
    async def run_tool(
        request: ToolRunRequest, principal: OperatorPrincipal = Depends(get_principal)
    ) -> dict[str, Any]:
        ensure_access(principal, request.engagement_id)
        with guarded(principal, request.engagement_id, "tool_run", request.tool):
            result = await runner.run(
                principal=principal,
                engagement_id=request.engagement_id,
                tool=request.tool,
                target=request.target,
                flags=request.flags,
                mission_id=request.mission_id,
                timeout_sec=request.timeout_sec,
            )
            return result.to_dict()

    # ------------------------------------------------------------------
    # Findings (PoC lifecycle)
    # ------------------------------------------------------------------
    @router.post("/findings")
    async def draft_finding(
        request: FindingDraftRequest, principal: OperatorPrincipal = Depends(get_principal)
    ) -> dict[str, Any]:
        ensure_access(principal, request.engagement_id)
        with guarded(principal, request.engagement_id, "draft_finding", request.target):
            return exploitation.draft(
                principal=principal,
                engagement_id=request.engagement_id,
                target=request.target,
                vulnerability=request.vulnerability,
                poc_body=request.poc_body,
                language=request.language,
                severity=request.severity,
                mission_id=request.mission_id,
                reproduction_steps=request.reproduction_steps,
            )

    @router.get("/findings")
    async def list_findings(
        engagement_id: str,
        status_filter: str | None = Query(default=None, alias="status"),
        principal: OperatorPrincipal = Depends(get_principal),
    ) -> dict[str, Any]:
        ensure_access(principal, engagement_id)
        with guarded(principal, engagement_id, "list_findings"):
            return {
                "engagement_id": engagement_id,
                "findings": exploitation.list_findings(engagement_id=engagement_id, status=status_filter),
                "summary": exploitation.evidence_summary(engagement_id),
            }

    @router.post("/findings/{exploit_id}/execution")
    async def record_execution(
        exploit_id: str,
        request: ExecutionRecordRequest,
        principal: OperatorPrincipal = Depends(get_principal),
    ) -> dict[str, Any]:
        with guarded(principal, "SYSTEM", "record_execution", exploit_id):
            return exploitation.record_execution(
                principal=principal,
                exploit_id=exploit_id,
                output=request.output,
                success=request.success,
                exit_code=request.exit_code,
            )

    @router.post("/findings/{exploit_id}/verify")
    async def verify_finding(
        exploit_id: str,
        request: VerifyRequest,
        principal: OperatorPrincipal = Depends(get_principal),
    ) -> dict[str, Any]:
        with guarded(principal, "SYSTEM", "verify_finding", exploit_id):
            return exploitation.verify(
                principal=principal,
                exploit_id=exploit_id,
                reproduced_output=request.reproduced_output,
                note=request.note,
            )

    # ------------------------------------------------------------------
    # Attack chains
    # ------------------------------------------------------------------
    @router.post("/chains")
    async def propose_chain(
        request: ChainRequest, principal: OperatorPrincipal = Depends(get_principal)
    ) -> dict[str, Any]:
        ensure_access(principal, request.engagement_id)
        with guarded(principal, request.engagement_id, "propose_chain"):
            return exploitation.propose_chain(
                principal=principal,
                engagement_id=request.engagement_id,
                step_ids=request.step_ids,
                rationale=request.rationale,
                mission_id=request.mission_id,
            )

    @router.get("/chains")
    async def list_chains(
        engagement_id: str, principal: OperatorPrincipal = Depends(get_principal)
    ) -> dict[str, Any]:
        ensure_access(principal, engagement_id)
        return {"engagement_id": engagement_id, "chains": exploitation.list_chains(engagement_id)}

    @router.post("/chains/validate")
    async def validate_chain(
        request: ChainValidateRequest, principal: OperatorPrincipal = Depends(get_principal)
    ) -> dict[str, Any]:
        ensure_access(principal, request.engagement_id)
        with guarded(principal, request.engagement_id, "validate_chain", request.chain_id):
            return exploitation.validate_chain(
                principal=principal,
                engagement_id=request.engagement_id,
                chain_id=request.chain_id,
                reproduce_step=request.reproduce_step,
                reproduced=request.reproduced,
                note=request.note,
            )

    # ------------------------------------------------------------------
    # Recursive discovery & mass scanning
    # ------------------------------------------------------------------
    @router.post("/explore/discover")
    async def discover(
        request: DiscoverRequest, principal: OperatorPrincipal = Depends(get_principal)
    ) -> dict[str, Any]:
        ensure_access(principal, request.engagement_id)
        with guarded(principal, request.engagement_id, "discover"):
            result = exploration.discover(
                principal=principal,
                engagement_id=request.engagement_id,
                candidates=request.candidates,
                mission_id=request.mission_id,
            )
            payload = result.to_dict()
            if request.propose and result.proposals:
                payload["expansion_request"] = exploration.propose_expansion(
                    principal=principal,
                    engagement_id=request.engagement_id,
                    discovery=result,
                    mission_id=request.mission_id,
                    justification=request.justification or "Related assets discovered in scope.",
                )
            return payload

    @router.get("/explore/secondary")
    async def secondary_targets(
        engagement_id: str,
        mission_id: str | None = None,
        principal: OperatorPrincipal = Depends(get_principal),
    ) -> dict[str, Any]:
        ensure_access(principal, engagement_id)
        return exploration.derive_secondary_targets(engagement_id, mission_id=mission_id)

    @router.post("/explore/mass-scan")
    async def mass_scan(
        request: MassScanRequest, principal: OperatorPrincipal = Depends(get_principal)
    ) -> dict[str, Any]:
        ensure_access(principal, request.engagement_id)
        with guarded(principal, request.engagement_id, "mass_scan"):
            return exploration.request_mass_scan(
                principal=principal,
                engagement_id=request.engagement_id,
                mission_id=request.mission_id,
                target_count=request.target_count,
                request_count=request.request_count,
                justification=request.justification,
            )

    @router.get("/explore/budget")
    async def scan_budget(
        engagement_id: str, principal: OperatorPrincipal = Depends(get_principal)
    ) -> dict[str, Any]:
        ensure_access(principal, engagement_id)
        live = db.live_scan_authorization(engagement_id)
        return {
            "engagement_id": engagement_id,
            "authorization": live,
            "note": (
                "No authorisation means any scan beyond the mission budget needs two-person "
                "approval first."
            ),
        }

    # ------------------------------------------------------------------
    # Bug bounty
    # ------------------------------------------------------------------
    @router.post("/bounty/programs")
    async def register_program(
        request: ProgramRequest, principal: OperatorPrincipal = Depends(get_principal)
    ) -> dict[str, Any]:
        ensure_access(principal, request.engagement_id)
        with guarded(principal, request.engagement_id, "bounty_program", request.handle):
            return bounty.register_program(
                principal=principal,
                engagement_id=request.engagement_id,
                platform=request.platform,
                handle=request.handle,
                display_name=request.display_name,
                scope_entries=request.scope_entries,
            )

    @router.get("/bounty/programs")
    async def list_programs(
        engagement_id: str, principal: OperatorPrincipal = Depends(get_principal)
    ) -> dict[str, Any]:
        ensure_access(principal, engagement_id)
        return {"engagement_id": engagement_id, "programs": bounty.list_programs(engagement_id)}

    @router.post("/bounty/programs/{program_id}/sync")
    async def sync_program(
        program_id: str, principal: OperatorPrincipal = Depends(get_principal)
    ) -> dict[str, Any]:
        with guarded(principal, "SYSTEM", "bounty_sync", program_id):
            return bounty.sync_program(principal=principal, program_id=program_id)

    @router.post("/bounty/duplicates")
    async def dup_check(
        request: DuplicateRequest, principal: OperatorPrincipal = Depends(get_principal)
    ) -> dict[str, Any]:
        with guarded(principal, "SYSTEM", "bounty_dup", request.finding_key):
            return bounty.check_duplicates(
                principal=principal,
                program_id=request.program_id,
                finding_key=request.finding_key,
                endpoint=request.endpoint,
                title=request.title,
                summary=request.summary,
            )

    @router.post("/bounty/reports")
    async def draft_report(
        request: ReportDraftRequest, principal: OperatorPrincipal = Depends(get_principal)
    ) -> dict[str, Any]:
        ensure_access(principal, request.engagement_id)
        with guarded(principal, request.engagement_id, "bounty_report", request.exploit_id):
            findings = exploitation.list_findings(engagement_id=request.engagement_id, limit=500)
            match = next((f for f in findings if f["exploit_id"] == request.exploit_id), None)
            if match is None:
                raise BountyError("Unknown finding for this engagement.")
            return bounty.draft_report(
                principal=principal,
                engagement_id=request.engagement_id,
                finding=match,
                program_id=request.program_id,
                check_id=request.check_id,
                repro_command=request.repro_command,
                impact=request.impact,
                remediation=request.remediation,
            )

    @router.post("/bounty/reports/{report_id}/ready")
    async def report_ready(
        report_id: str, principal: OperatorPrincipal = Depends(get_principal)
    ) -> dict[str, Any]:
        with guarded(principal, "SYSTEM", "bounty_ready", report_id):
            return bounty.mark_ready(principal=principal, report_id=report_id)

    @router.get("/bounty/reports")
    async def list_reports(
        engagement_id: str, principal: OperatorPrincipal = Depends(get_principal)
    ) -> dict[str, Any]:
        ensure_access(principal, engagement_id)
        return {"engagement_id": engagement_id, "reports": bounty.list_reports(engagement_id)}

    @router.get("/bounty/programs/{program_id}/drift")
    async def scope_drift(
        program_id: str,
        engagement_id: str,
        principal: OperatorPrincipal = Depends(get_principal),
    ) -> dict[str, Any]:
        ensure_access(principal, engagement_id)
        return bounty.scope_drift(program_id, engagement_id)

    # ------------------------------------------------------------------
    # pwntools
    # ------------------------------------------------------------------
    @router.get("/pwntools/status")
    async def pwntools_status(
        refresh: bool = Query(default=False),
        principal: OperatorPrincipal = Depends(get_principal),
    ) -> dict[str, Any]:
        del principal
        status = pwntools.availability(refresh=refresh)
        return {
            "layer": "pwntools",
            **status,
            "default_on_for": ["ctf", "binary missions"],
            "fallback": (
                "binary_triage reports ELF hardening facts without pwntools; it is not a "
                "substitute for the toolkit."
            ),
        }

    @router.post("/pwntools/run")
    async def pwntools_run(
        request: PwntoolsRunRequest, principal: OperatorPrincipal = Depends(get_principal)
    ) -> dict[str, Any]:
        ensure_access(principal, request.engagement_id)
        with guarded(principal, request.engagement_id, "pwntools_run", request.action):
            return pwntools.run(
                principal=principal,
                engagement_id=request.engagement_id,
                action=request.action,
                target=request.target,
                artifact_path=request.artifact_path,
                source=request.source,
                hex_bytes=request.hex_bytes,
                length=request.length,
                arch=request.arch,
                registers=request.registers,
                script=request.script,
                mission_id=request.mission_id,
            )

    @router.get("/pwntools/jobs")
    async def pwntools_jobs(
        engagement_id: str, principal: OperatorPrincipal = Depends(get_principal)
    ) -> dict[str, Any]:
        ensure_access(principal, engagement_id)
        return {"engagement_id": engagement_id, "jobs": pwntools.list_jobs(engagement_id)}

    # ------------------------------------------------------------------
    # Hunt loops & brain
    # ------------------------------------------------------------------
    @router.get("/agents")
    async def roster(
        phase: str | None = Query(default=None),
        principal: OperatorPrincipal = Depends(get_principal),
    ) -> dict[str, Any]:
        del principal  # authenticated; the roster is not engagement-scoped
        return loops.roster(phases=[phase] if phase else None)

    @router.post("/loops")
    async def open_loop(
        request: LoopRequest, principal: OperatorPrincipal = Depends(get_principal)
    ) -> dict[str, Any]:
        ensure_access(principal, request.engagement_id)
        with guarded(principal, request.engagement_id, "open_loop", request.role_id):
            return loops.open_loop(
                principal=principal,
                engagement_id=request.engagement_id,
                role_id=request.role_id,
                hypothesis=request.hypothesis,
                mission_id=request.mission_id,
                max_iterations=request.max_iterations,
            )

    @router.get("/loops")
    async def list_loops(
        engagement_id: str,
        status_filter: str | None = Query(default=None, alias="status"),
        principal: OperatorPrincipal = Depends(get_principal),
    ) -> dict[str, Any]:
        ensure_access(principal, engagement_id)
        return {
            "engagement_id": engagement_id,
            "loops": loops.list_loops(engagement_id, status=status_filter),
            "brain": loops.brain_summary(engagement_id),
        }

    @router.post("/loops/{loop_id}/iterate")
    async def iterate_loop(
        loop_id: str,
        request: LoopIterateRequest,
        principal: OperatorPrincipal = Depends(get_principal),
    ) -> dict[str, Any]:
        with guarded(principal, "SYSTEM", "iterate_loop", loop_id):
            return loops.iterate(
                principal=principal, loop_id=loop_id, note=request.note, status=request.status
            )

    @router.post("/loops/{loop_id}/kill")
    async def kill_loop(
        loop_id: str,
        request: LoopIterateRequest,
        principal: OperatorPrincipal = Depends(get_principal),
    ) -> dict[str, Any]:
        with guarded(principal, "SYSTEM", "kill_loop", loop_id):
            return loops.kill_loop(principal=principal, loop_id=loop_id, reason=request.note)

    @router.post("/loops/{loop_id}/gate")
    async def apply_gate(
        loop_id: str,
        request: GateAnswersRequest,
        principal: OperatorPrincipal = Depends(get_principal),
    ) -> dict[str, Any]:
        with guarded(principal, "SYSTEM", "loop_gate", loop_id):
            return loops.apply_gate(
                principal=principal,
                loop_id=loop_id,
                answers=request.answers,
                evidence_ref=request.evidence_ref,
            )

    @router.get("/brain")
    async def brain(
        engagement_id: str,
        loop_id: str | None = None,
        principal: OperatorPrincipal = Depends(get_principal),
    ) -> dict[str, Any]:
        ensure_access(principal, engagement_id)
        return {
            "engagement_id": engagement_id,
            "summary": loops.brain_summary(engagement_id),
            "entries": loops.recall(engagement_id, loop_id=loop_id),
        }

    @router.post("/brain")
    async def brain_note(
        request: BrainNoteRequest, principal: OperatorPrincipal = Depends(get_principal)
    ) -> dict[str, Any]:
        ensure_access(principal, request.engagement_id)
        with guarded(principal, request.engagement_id, "brain_note"):
            return loops.append_brain(
                principal=principal,
                engagement_id=request.engagement_id,
                kind=request.kind,
                content=request.content,
                loop_id=request.loop_id,
                role_id=request.role_id,
                evidence_ref=request.evidence_ref,
                mission_id=request.mission_id,
            )

    # ------------------------------------------------------------------
    # Session Start Protocol brief
    # ------------------------------------------------------------------
    @router.get("/brief")
    async def brief(
        engagement_id: str,
        mission_id: str | None = None,
        principal: OperatorPrincipal = Depends(get_principal),
    ) -> dict[str, Any]:
        """The Session Start Protocol, assembled from the ledger."""
        ensure_access(principal, engagement_id)
        engagement = db.get_engagement(engagement_id) or {}
        allowlist = db.list_allowlist(engagement_id=engagement_id, active_only=True)
        mission = store.get_mission(mission_id) if mission_id else None
        posture = policies.posture(engagement_id)
        audits = store.list_tls_audits(engagement_id, mission_id=mission_id, limit=1)
        pending_expansions = store.list_expansion_requests(
            engagement_id=engagement_id, mission_id=mission_id, status="pending"
        )
        pwn_status = pwntools.availability()
        return {
            "session_brief_version": "2.3",
            "mission": {
                "mission_id": mission_id,
                "type": (mission or {}).get("mode_id") or "unclassified",
                "status": (mission or {}).get("status"),
                "budget": None
                if not mission
                else {
                    "max_actions": mission["max_actions"],
                    "used_actions": mission["used_actions"],
                    "actions_remaining": max(
                        0, mission["max_actions"] - mission["used_actions"]
                    ),
                    "deadline_at": mission["deadline_at"],
                },
            },
            "scope": {
                "engagement_id": engagement_id,
                "engagement_name": engagement.get("name"),
                "active": bool(engagement.get("active", 0)),
                "valid_from": engagement.get("valid_from"),
                "valid_until": engagement.get("valid_until"),
                "allowlist_entries": len(allowlist),
                "sample_targets": [e["target"] for e in allowlist[:10]],
                "approved_expansions": None,
                "pending_expansion_requests": len(pending_expansions),
            },
            "roe": {
                "posture": posture.policy_id,
                "posture_name": getattr(posture, "name", ""),
                "consent_required": posture.consent_required,
                "consent_met": policies.has_consent(
                    operator_id=principal.operator_id,
                    level=posture.consent_required,
                    engagement_id=engagement_id,
                    policy=posture,
                ),
                "consent_requirements": policies.consent_requirements(
                    engagement_id, principal.operator_id
                ),
                "two_person_required_for": sorted(HIGH_IMPACT_POLICIES),
                "remaining_budget": None
                if not mission
                else max(0, mission["max_actions"] - mission["used_actions"]),
            },
            "tls": {
                "mandatory": True,
                "completed": bool(audits),
                "pending": not audits,
                "last_audit_id": audits[0]["audit_id"] if audits else None,
                "last_risk": audits[0]["payload"]["summary"]["risk"] if audits else None,
            },
            "capability_layers": [
                {
                    "id": "tool_execution",
                    "status": "available" if runner.installed_tools() else "degraded",
                    "detail": f"{len(runner.installed_tools())} catalogued binaries installed",
                },
                {
                    "id": "agents",
                    "status": "available",
                    "detail": f"{len(loops.roster()['roles'])} advisory roles",
                },
                {
                    "id": "pwntools",
                    "status": "available" if pwn_status["available"] else "unavailable",
                    "detail": pwn_status["detail"],
                },
            ],
            "restrictions": {
                "two_person_high_impact_only": True,
                "scope_never_widened_by_posture": True,
                "destructive_poc_refused": True,
                "cloud_metadata_denied": True,
                "dns_pinning_required": True,
            },
            "declared": bool(mission_id),
            "operator": {
                "operator_id": principal.operator_id,
                "role": principal.role,
                "can_approve": principal.can_approve(),
            },
        }

    return router
