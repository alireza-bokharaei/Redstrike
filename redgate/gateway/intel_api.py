"""Authenticated API for the intel engine, coverage ledger and response diffing.

Prefix ``/api/v1``. Every route is engagement-scoped where an engagement applies,
and the two mutating families (intel outcomes, coverage) are recorded in the audit
ledger so a ranking can be traced back to the work that produced it.

Nothing here executes a tool, raises a budget or promotes a finding: the engine
orders work and the coverage ledger records it.
"""

from __future__ import annotations

from typing import Any, Callable

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from gateway.auth import OperatorPrincipal
from gateway.coverage import CoverageError, CoverageLedger, ResponseTracker
from gateway.evidence import redact_text
from gateway.intel_engine import (
    IntelError,
    OutcomeStore,
    allocate_budget,
    brain_signals_from_entries,
    chain_plan,
    cvss_base,
    evidence_score,
    exhaustion_gate,
    rank_classes,
    rank_surface,
)


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ClassRankRequest(StrictModel):
    engagement_id: str | None = Field(default=None, max_length=64)
    tech_stack: list[str] = Field(default_factory=list, max_length=64)
    observations: list[str] = Field(default_factory=list, max_length=64)
    hacktivity: dict[str, float] = Field(default_factory=dict)
    use_brain: bool = True
    limit: int = Field(default=8, ge=1, le=32)


class SurfaceRankRequest(StrictModel):
    endpoints: list[dict[str, Any]] = Field(min_length=1, max_length=500)
    kill_below: float = Field(default=0.0, ge=0.0, le=1.0)


class BudgetRequest(StrictModel):
    classes: list[dict[str, Any]] = Field(min_length=1, max_length=32)
    minutes: int = Field(default=120, ge=1, le=2880)
    tokens: int = Field(default=200_000, ge=1000, le=5_000_000)
    max_per_class: int = Field(default=4, ge=1, le=32)


class ExhaustionRequest(StrictModel):
    attempts: int = Field(default=0, ge=0, le=10_000)
    evidence_items: int = Field(default=0, ge=0, le=10_000)
    variants_tried: int = Field(default=0, ge=0, le=10_000)
    unexplained_anomaly: bool = False


class ChainRequest(StrictModel):
    capabilities: list[str] = Field(min_length=1, max_length=64)


class EvidenceScoreRequest(StrictModel):
    finding: dict[str, Any]


class CvssRequest(StrictModel):
    vector: str = Field(min_length=8, max_length=256)


class OutcomeRequest(StrictModel):
    engagement_id: str = Field(min_length=3, max_length=64)
    vuln_class: str = Field(min_length=2, max_length=48)
    result: str = Field(pattern=r"^(confirmed|rejected|inconclusive|blocked)$")
    note: str = Field(default="", max_length=500)
    evidence_id: str | None = Field(default=None, max_length=64)


class CoverageRequest(StrictModel):
    engagement_id: str = Field(min_length=3, max_length=64)
    surface: str = Field(min_length=1, max_length=253)
    checks: list[str] = Field(default_factory=list, max_length=32)
    category: str = Field(default="", max_length=64)
    depth: str = Field(default="standard", pattern=r"^(shallow|standard|deep)$")
    status: str = Field(default="covered", pattern=r"^(covered|partial|skipped|out_of_scope)$")
    skip_reason: str = Field(default="", max_length=400)
    mission_id: str | None = Field(default=None, max_length=64)


class ObserveRequest(StrictModel):
    engagement_id: str = Field(min_length=3, max_length=64)
    asset: str = Field(min_length=1, max_length=253)
    status_code: int = Field(default=200, ge=0, le=599)
    body: str = Field(default="", max_length=200_000)
    headers: dict[str, str] = Field(default_factory=dict)


def intel_router(
    *,
    db: Any,
    outcomes: OutcomeStore,
    coverage: CoverageLedger,
    tracker: ResponseTracker,
    get_principal: Callable[..., OperatorPrincipal],
    ensure_access: Callable[[OperatorPrincipal, str], None],
) -> APIRouter:
    router = APIRouter(prefix="/api/v1", tags=["Intel · coverage · diff"])

    def _failure(principal: OperatorPrincipal, engagement: str, action: str, exc: Exception) -> HTTPException:
        db.write_audit_log(
            engagement_id=engagement,
            operator_id=principal.operator_id,
            target=action,
            tool_or_script=f"intel:{action}",
            status="rejected",
            rejection_reason=redact_text(str(exc))[:500],
        )
        return HTTPException(status_code=422, detail=redact_text(str(exc))[:500])

    # ------------------------------------------------------------------
    # Ranking and planning
    # ------------------------------------------------------------------
    @router.post("/intel/classes")
    async def rank_classes_route(
        request: ClassRankRequest, principal: OperatorPrincipal = Depends(get_principal)
    ) -> dict[str, Any]:
        if request.engagement_id:
            ensure_access(principal, request.engagement_id)
        brain_entries: list[dict[str, Any]] = []
        history: list[dict[str, Any]] = []
        if request.engagement_id and request.use_brain:
            with db.connection() as conn:
                brain_entries = [
                    dict(r)
                    for r in conn.execute(
                        """SELECT kind, content, verdict FROM brain_entries
                           WHERE engagement_id=? ORDER BY created_at DESC LIMIT 200""",
                        (request.engagement_id,),
                    ).fetchall()
                ]
            history = outcomes.list(request.engagement_id)
        try:
            result = rank_classes(
                tech_stack=request.tech_stack,
                observations=request.observations,
                hacktivity=request.hacktivity,
                brain_signals=brain_signals_from_entries(brain_entries),
                outcomes=history,
                limit=request.limit,
            )
        except IntelError as exc:
            raise _failure(principal, request.engagement_id or "SYSTEM", "rank_classes", exc) from exc
        result["engagement_id"] = request.engagement_id
        return result

    @router.post("/intel/surface")
    async def rank_surface_route(
        request: SurfaceRankRequest, principal: OperatorPrincipal = Depends(get_principal)
    ) -> dict[str, Any]:
        try:
            return rank_surface(request.endpoints, kill_below=request.kill_below)
        except IntelError as exc:
            raise _failure(principal, "SYSTEM", "rank_surface", exc) from exc

    @router.post("/intel/budget")
    async def budget_route(
        request: BudgetRequest, principal: OperatorPrincipal = Depends(get_principal)
    ) -> dict[str, Any]:
        try:
            return allocate_budget(
                request.classes,
                minutes=request.minutes,
                tokens=request.tokens,
                max_per_class=request.max_per_class,
            )
        except IntelError as exc:
            raise _failure(principal, "SYSTEM", "budget", exc) from exc

    @router.post("/intel/exhaustion")
    async def exhaustion_route(
        request: ExhaustionRequest, principal: OperatorPrincipal = Depends(get_principal)
    ) -> dict[str, Any]:
        return exhaustion_gate(request.model_dump())

    @router.post("/intel/chain")
    async def chain_route(
        request: ChainRequest, principal: OperatorPrincipal = Depends(get_principal)
    ) -> dict[str, Any]:
        return chain_plan(request.capabilities)

    @router.post("/intel/evidence-score")
    async def evidence_score_route(
        request: EvidenceScoreRequest, principal: OperatorPrincipal = Depends(get_principal)
    ) -> dict[str, Any]:
        return evidence_score(request.finding)

    @router.post("/intel/cvss")
    async def cvss_route(
        request: CvssRequest, principal: OperatorPrincipal = Depends(get_principal)
    ) -> dict[str, Any]:
        try:
            return cvss_base(request.vector)
        except IntelError as exc:
            raise _failure(principal, "SYSTEM", "cvss", exc) from exc

    # ------------------------------------------------------------------
    # Outcomes (the ranking's only learning input)
    # ------------------------------------------------------------------
    @router.post("/intel/outcomes")
    async def record_outcome(
        request: OutcomeRequest, principal: OperatorPrincipal = Depends(get_principal)
    ) -> dict[str, Any]:
        ensure_access(principal, request.engagement_id)
        try:
            row = outcomes.record(
                engagement_id=request.engagement_id,
                vuln_class=request.vuln_class,
                result=request.result,
                note=request.note,
                evidence_id=request.evidence_id,
                operator_id=principal.operator_id,
            )
        except IntelError as exc:
            raise _failure(principal, request.engagement_id, "outcome", exc) from exc
        db.write_audit_log(
            engagement_id=request.engagement_id,
            operator_id=principal.operator_id,
            target=request.vuln_class,
            tool_or_script="intel:outcome",
            params={"result": request.result, "evidence_id": request.evidence_id},
            status="completed",
            stdout_summary=f"Outcome recorded: {request.vuln_class}={request.result}",
        )
        return row

    @router.get("/intel/outcomes")
    async def list_outcomes(
        engagement_id: str = Query(min_length=3),
        principal: OperatorPrincipal = Depends(get_principal),
    ) -> dict[str, Any]:
        ensure_access(principal, engagement_id)
        return {
            "engagement_id": engagement_id,
            "outcomes": outcomes.list(engagement_id),
            "summary": outcomes.summary(engagement_id),
        }

    # ------------------------------------------------------------------
    # Coverage ledger
    # ------------------------------------------------------------------
    @router.post("/coverage")
    async def record_coverage(
        request: CoverageRequest, principal: OperatorPrincipal = Depends(get_principal)
    ) -> dict[str, Any]:
        ensure_access(principal, request.engagement_id)
        try:
            row = coverage.record(
                engagement_id=request.engagement_id,
                surface=request.surface,
                checks=request.checks,
                category=request.category,
                depth=request.depth,
                status=request.status,
                skip_reason=request.skip_reason,
                mission_id=request.mission_id,
                operator_id=principal.operator_id,
            )
        except CoverageError as exc:
            raise _failure(principal, request.engagement_id, "coverage", exc) from exc
        db.write_audit_log(
            engagement_id=request.engagement_id,
            operator_id=principal.operator_id,
            target=request.surface,
            tool_or_script="coverage:record",
            params={"status": request.status, "depth": request.depth, "checks": request.checks},
            status="completed",
            stdout_summary=f"Coverage {request.status} for {request.surface}",
        )
        return row

    @router.get("/coverage")
    async def coverage_summary(
        engagement_id: str = Query(min_length=3),
        expected: str | None = Query(default=None, description="Comma-separated declared surfaces"),
        principal: OperatorPrincipal = Depends(get_principal),
    ) -> dict[str, Any]:
        ensure_access(principal, engagement_id)
        expected_list = [s.strip() for s in (expected or "").split(",") if s.strip()]
        return coverage.summary(engagement_id, expected=expected_list)

    @router.delete("/coverage")
    async def drop_coverage(
        engagement_id: str = Query(min_length=3),
        surface: str = Query(min_length=1),
        principal: OperatorPrincipal = Depends(get_principal),
    ) -> dict[str, Any]:
        ensure_access(principal, engagement_id)
        removed = coverage.drop(engagement_id, surface)
        db.write_audit_log(
            engagement_id=engagement_id,
            operator_id=principal.operator_id,
            target=surface,
            tool_or_script="coverage:drop",
            status="completed" if removed else "rejected",
            stdout_summary="Coverage record removed" if removed else "No such coverage record",
        )
        if not removed:
            raise HTTPException(status_code=404, detail="No such coverage record.")
        return {"removed": True, "surface": surface}

    # ------------------------------------------------------------------
    # Response diffing
    # ------------------------------------------------------------------
    @router.post("/responses/observe")
    async def observe_response(
        request: ObserveRequest, principal: OperatorPrincipal = Depends(get_principal)
    ) -> dict[str, Any]:
        ensure_access(principal, request.engagement_id)
        try:
            row = tracker.observe(
                engagement_id=request.engagement_id,
                asset=request.asset,
                status_code=request.status_code,
                body=request.body,
                headers=request.headers,
            )
        except CoverageError as exc:
            raise _failure(principal, request.engagement_id, "observe", exc) from exc
        db.write_audit_log(
            engagement_id=request.engagement_id,
            operator_id=principal.operator_id,
            target=request.asset,
            tool_or_script="response:observe",
            params={"status_code": request.status_code, "fingerprint": row["fingerprint_id"]},
            status="completed",
            stdout_summary=f"Fingerprint {row['fingerprint_id']} stored for {request.asset}",
        )
        return row

    @router.get("/responses/diff")
    async def diff_response(
        engagement_id: str = Query(min_length=3),
        asset: str = Query(min_length=1),
        principal: OperatorPrincipal = Depends(get_principal),
    ) -> dict[str, Any]:
        ensure_access(principal, engagement_id)
        return tracker.diff(engagement_id, asset)

    @router.get("/responses/history")
    async def response_history(
        engagement_id: str = Query(min_length=3),
        asset: str = Query(min_length=1),
        principal: OperatorPrincipal = Depends(get_principal),
    ) -> dict[str, Any]:
        ensure_access(principal, engagement_id)
        rows = tracker.history(engagement_id, asset)
        return {"asset": asset, "count": len(rows), "observations": rows}

    return router
