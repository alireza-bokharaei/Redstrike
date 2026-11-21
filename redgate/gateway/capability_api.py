"""Authenticated API for 2.2 capability modes, deep TLS, expansion and the gate.

Every handler resolves the operator first, then the engagement access check, then
the mode/capability decision. A refusal is always written to the audit ledger
before the HTTP error is returned, so an attempted widening is visible even when
it is denied.
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Any, Callable, Iterator

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import JSONResponse

from gateway.agents_registry import UnknownRole, list_roles, plan
from gateway.auth import OperatorPrincipal
from gateway.binary_triage import BinaryTriageError, triage
from gateway.capabilities import CapabilityError, CapabilityRegistry, mode_label
from gateway.capability_models import (
    AgentPlanRequest,
    ApproachRequest,
    BinaryTriageRequest,
    CapabilityQuery,
    ComposeRequest,
    ExpansionDecision,
    ExpansionRequestCreate,
    GateEvaluationRequest,
    ModeToggleRequest,
    SessionStartRequest,
    TLSAuditRequest,
)
from gateway.evidence import redact_text
from gateway.evidence_gate import EvidenceGate
from gateway.expansion import ExpansionError, ExpansionService, PRIVILEGE_CLASSES
from gateway.tls_audit import TLSAuditError, TLSAuditService
from gateway.workspace_store import WorkspaceConflict


def capability_router(
    *,
    registry: CapabilityRegistry,
    gate: EvidenceGate,
    tls: TLSAuditService,
    expansion: ExpansionService,
    db: Any,
    store: Any,
    get_principal: Callable[..., OperatorPrincipal],
    ensure_access: Callable[[OperatorPrincipal, str], None],
    artifact_root: str,
) -> APIRouter:
    router = APIRouter(prefix="/api/v1", tags=["Capability modes · 2.2"])

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
            tool_or_script=f"capability:{action}",
            status="rejected",
            rejection_reason=redact_text(reason)[:500],
        )

    @contextmanager
    def guarded(
        principal: OperatorPrincipal, engagement_id: str, action: str, target: str = "-"
    ) -> Iterator[None]:
        try:
            yield
        except PermissionError as exc:
            audit_refusal(principal, engagement_id, action, str(exc), target)
            raise HTTPException(status_code=403, detail=redact_text(str(exc))[:500]) from exc
        except (CapabilityError, ExpansionError, BinaryTriageError, TLSAuditError) as exc:
            audit_refusal(principal, engagement_id, action, str(exc), target)
            raise HTTPException(status_code=422, detail=redact_text(str(exc))[:500]) from exc
        except WorkspaceConflict as exc:
            audit_refusal(principal, engagement_id, action, str(exc), target)
            raise HTTPException(status_code=409, detail=redact_text(str(exc))[:500]) from exc
        except UnknownRole as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    # ------------------------------------------------------------------
    # Discovery & session-start protocol
    # ------------------------------------------------------------------
    @router.get("/capabilities")
    async def capabilities(
        principal: OperatorPrincipal = Depends(get_principal),
    ) -> dict[str, Any]:
        """Public-to-authenticated description of modes, layers and gate questions."""
        return {
            "manifest_version": registry.manifest_version,
            "modes": registry.describe(),
            "layers": registry.layers(),
            "tls_audit": registry.session_brief(db)["tls_audit"],
            "composition": {
                "max_modes": registry.composition_spec().get("max_modes", 1),
                "rules": registry.composition_spec().get("rules") or {},
                "allowed": registry.composition_allowed(),
                "note": (
                    "Composition widens the permitted capability set only: the narrowest "
                    "ceiling wins, mandatory obligations are the union, and expansion "
                    "clauses are intersected."
                ),
            },
            "expansion": registry.session_brief(db)["expansion"],
            "evidence_gate": registry.session_brief(db)["evidence_gate"],
            "agents": {"total": len(list_roles())},
            "invariants": {
                "two_person_rule": True,
                "cloud_metadata_denied": True,
                "dns_pinning_required": True,
                "permanently_banned_tool_flags": True,
                "exploit_generation": False,
            },
        }

    @router.post("/session/start")
    async def session_start(
        request: SessionStartRequest, principal: OperatorPrincipal = Depends(get_principal)
    ) -> dict[str, Any]:
        ensure_access(principal, request.engagement_id)
        brief = _build_brief(principal, request.engagement_id, request.mission_id, request.mode_id)
        if request.declare:
            db.write_audit_log(
                engagement_id=request.engagement_id,
                operator_id=principal.operator_id,
                target=request.mission_id or request.engagement_id,
                tool_or_script="capability:session_start",
                params={
                    "mode_id": request.mode_id,
                    "mission_id": request.mission_id,
                    "mandatory": brief["tls"]["mandatory"],
                },
                status="completed",
                stdout_summary=(
                    f"Session declared: mode={request.mode_id or 'unclassified'} "
                    f"tls_complete={brief['tls']['completed']}"
                ),
            )
        return brief

    def _build_brief(
        principal: OperatorPrincipal,
        engagement_id: str,
        mission_id: str | None,
        mode_id: str | None,
    ) -> dict[str, Any]:
        engagement = db.get_engagement(engagement_id) or {}
        allowlist = db.list_allowlist(engagement_id=engagement_id, active_only=True)
        mission = store.get_mission(mission_id) if mission_id else None
        effective_mode = mode_id or (mission or {}).get("mode_id")
        mode_summary: dict[str, Any] = {"id": None, "label": mode_label(registry, None)}
        if effective_mode:
            try:
                mode = registry.get_mode(effective_mode)
                mode_summary = {
                    "id": mode.mode_id,
                    "label": mode.label,
                    "ceiling": {
                        "max_hosts": mode.ceiling.max_hosts,
                        "max_actions": mode.ceiling.max_actions,
                        "max_seconds": mode.ceiling.max_seconds,
                    },
                    "mandatory_capabilities": sorted(mode.mandatory_capabilities),
                }
            except CapabilityError as exc:
                mode_summary = {
                    "id": effective_mode,
                    "label": mode_label(registry, effective_mode),
                    "error": str(exc),
                }

        audits = store.list_tls_audits(engagement_id, mission_id=mission_id, limit=1)
        tls_completed = bool(audits)
        pending = store.list_expansion_requests(
            engagement_id=engagement_id, mission_id=mission_id, status="pending"
        )
        quota = db.get_or_init_quota(
            operator_id=principal.operator_id,
            period=principal.quota_period,
            max_calls=principal.quota_max_calls,
            max_tokens=principal.quota_max_tokens,
        )
        budget = None
        if mission:
            budget = {
                "max_actions": mission["max_actions"],
                "used_actions": mission["used_actions"],
                "actions_remaining": max(0, mission["max_actions"] - mission["used_actions"]),
                "max_seconds": mission["max_seconds"],
                "deadline_at": mission["deadline_at"],
                "status": mission["status"],
            }
        return {
            "mission": {
                "mission_id": mission_id,
                "type": mode_summary["label"],
                "mode_id": mode_summary.get("id"),
                "declared_ceiling": mode_summary.get("ceiling"),
                "budget": budget,
            },
            "scope": {
                "engagement_id": engagement_id,
                "engagement_name": engagement.get("name"),
                "valid_from": engagement.get("valid_from"),
                "valid_until": engagement.get("valid_until"),
                "active": bool(engagement.get("active", 0)),
                "active_allowlist_entries": len(allowlist),
                "sample_targets": [e["target"] for e in allowlist[:10]],
                "expansion_clauses": expansion.engagement_clauses(engagement_id),
            },
            "roe": {
                "two_person_approval_for": [
                    "expansion requests",
                    "gated tool execution",
                    "script execution",
                    "elevated review classes",
                ],
                "distinct_approver_required": bool(
                    registry.expansion_policy().get("require_distinct_approver", True)
                ),
                "pending_expansion_requests": len(pending),
                "quota": {
                    "period": principal.quota_period,
                    "used_calls": quota["used_calls"],
                    "max_calls": quota["max_calls"],
                    "used_tokens": quota["used_tokens"],
                    "max_tokens": quota["max_tokens"],
                },
            },
            "tls": {
                "mandatory": "tls_deep_analysis"
                in (mode_summary.get("mandatory_capabilities") or []),
                "completed": tls_completed,
                "pending": (not tls_completed),
                "last_audit_id": audits[0]["audit_id"] if audits else None,
                "last_risk": (audits[0]["payload"]["summary"]["risk"] if audits else None),
            },
            "capability_layers": [
                {
                    "id": layer.get("id"),
                    "status": layer.get("status"),
                    "adapter": layer.get("adapter"),
                }
                for layer in registry.layers()
            ],
            "restrictions": {
                "exploit_generation": False,
                "credential_attacks": False,
                "destructive_actions_require_approval": True,
                "unbounded_scanning": False,
                "hard_code_invariants_removable_by_config": False,
            },
            "operator": {
                "operator_id": principal.operator_id,
                "role": principal.role,
                "can_approve": principal.can_approve(),
            },
        }

    # ------------------------------------------------------------------
    # Mode binding & capability resolution
    # ------------------------------------------------------------------
    @router.post("/capabilities/resolve")
    async def resolve_capabilities(
        request: CapabilityQuery, principal: OperatorPrincipal = Depends(get_principal)
    ) -> dict[str, Any]:
        ensure_access(principal, request.engagement_id)
        role = request.principal_role or principal.role
        decisions = [
            registry.resolve(db, request.mode_id, cap, principal_role=role).__dict__
            for cap in (request.capabilities or registry.capabilities_for(request.mode_id))
        ]
        return {"mode_id": request.mode_id, "decisions": decisions}

    @router.post("/capabilities/compose")
    async def compose_capabilities(
        request: ComposeRequest, principal: OperatorPrincipal = Depends(get_principal)
    ) -> dict[str, Any]:
        """Resolve a composition without declaring it; nothing is executed."""
        try:
            mode, audit = registry.compose(list(request.modes))
        except CapabilityError as exc:
            raise HTTPException(status_code=422, detail=redact_text(str(exc))[:500]) from exc
        return {
            "mode": {
                "id": mode.mode_id,
                "label": mode.label,
                "ceiling": {
                    "max_hosts": mode.ceiling.max_hosts,
                    "max_actions": mode.ceiling.max_actions,
                    "max_seconds": mode.ceiling.max_seconds,
                    "concurrent_missions": mode.ceiling.concurrent_missions,
                },
                "mandatory_capabilities": sorted(mode.mandatory_capabilities),
                "capabilities": sorted(mode.capabilities),
            },
            "audit": audit,
            "operator_id": principal.operator_id,
        }

    @router.post("/decide/approach")
    async def decide_approach(
        request: ApproachRequest, principal: OperatorPrincipal = Depends(get_principal)
    ) -> dict[str, Any]:
        """Deterministic next-step suggestions for one target (advisory only)."""
        ensure_access(principal, request.engagement_id)
        assets = store.list_assets(request.engagement_id)
        history = db.list_audit_log(request.engagement_id) if hasattr(db, "list_audit_log") else []
        with guarded(principal, request.engagement_id, "capability:decide_approach", request.target):
            plan = registry.decide_approach(
                target=request.target,
                observations=request.observations,
                assets=assets,
                mode_id=request.mode_id,
                history=history,
            )
        db.write_audit_log(
            engagement_id=request.engagement_id,
            operator_id=principal.operator_id,
            target=request.target,
            tool_or_script="capability:decide_approach",
            params={
                "mode_id": request.mode_id,
                "observation_keys": sorted(request.observations),
                "already_run": request.already_run,
            },
            status="completed",
            stdout_summary=(
                "Advisory plan: "
                + (", ".join(step["tool"] for step in plan["recommended"][:4]) or "no step")
            ),
        )
        plan["engagement_id"] = request.engagement_id
        plan["operator_id"] = principal.operator_id
        return plan

    @router.post("/capabilities/toggle")
    async def toggle_modes(
        request: ModeToggleRequest, principal: OperatorPrincipal = Depends(get_principal)
    ) -> dict[str, Any]:
        if not principal.is_admin():
            db.write_audit_log(
                engagement_id="SYSTEM",
                operator_id=principal.operator_id,
                target="redgate_capability_mode",
                tool_or_script="capability:toggle",
                status="rejected",
                rejection_reason="Only an admin may change the capability-mode allow-list.",
            )
            raise HTTPException(status_code=403, detail="Only an admin may toggle capability modes.")
        if request.modes:
            unknown = [m for m in request.modes if m not in registry.mode_ids()]
            if unknown:
                raise HTTPException(status_code=422, detail=f"Unknown mode(s): {unknown}")
        db.upsert_tool_policy(
            tool_name="redgate_capability_mode",
            enabled=request.enabled,
            max_timeout=5,
            allowed_params={"modes": request.modes},
            risk_level="medium",
            requires_approval=False,
            description="Administrative toggle for 2.2 operational modes.",
        )
        db.write_audit_log(
            engagement_id="SYSTEM",
            operator_id=principal.operator_id,
            target="redgate_capability_mode",
            tool_or_script="capability:toggle",
            params={"enabled": request.enabled, "modes": request.modes},
            status="completed",
            stdout_summary=f"Capability modes enabled={request.enabled}.",
        )
        return {"toggle": registry.db_toggle(db)}

    # ------------------------------------------------------------------
    # Agent role catalogue
    # ------------------------------------------------------------------
    @router.get("/agents/roles")
    async def agent_roles(
        principal: OperatorPrincipal = Depends(get_principal),
    ) -> dict[str, Any]:
        return {"roles": list_roles(), "advisory_only": True}

    @router.post("/agents/plan")
    async def agent_plan(
        request: AgentPlanRequest, principal: OperatorPrincipal = Depends(get_principal)
    ) -> dict[str, Any]:
        ensure_access(principal, request.engagement_id)
        with guarded(principal, request.engagement_id, "agent_plan"):
            enabled, reason = registry.mode_enabled(db, request.mode_id)
            if not enabled:
                raise CapabilityError(reason)
            caps = set(registry.capabilities_for(request.mode_id))
            return plan(capabilities=caps, mode_id=request.mode_id, phase=request.phase)

    # ------------------------------------------------------------------
    # Deep TLS analysis
    # ------------------------------------------------------------------
    @router.post("/tls/audit", status_code=status.HTTP_201_CREATED)
    async def tls_audit(
        request: TLSAuditRequest, principal: OperatorPrincipal = Depends(get_principal)
    ) -> dict[str, Any]:
        ensure_access(principal, request.engagement_id)
        with guarded(principal, request.engagement_id, "tls_audit", request.target):
            result = await tls.analyze(
                principal=principal,
                engagement_id=request.engagement_id,
                target=request.target,
                port=request.port,
                mission_id=request.mission_id,
                include_hsts=request.include_hsts,
            )
            return {
                "audit": result,
                "summary": result["summary"],
                "findings": result["findings"],
            }

    @router.get("/tls/audits")
    async def list_tls_audits(
        engagement_id: str = Query(min_length=3, max_length=64),
        mission_id: str | None = Query(default=None, max_length=64),
        limit: int = Query(default=20, ge=1, le=100),
        principal: OperatorPrincipal = Depends(get_principal),
    ) -> dict[str, Any]:
        ensure_access(principal, engagement_id)
        rows = store.list_tls_audits(
            engagement_id, mission_id=mission_id, limit=limit
        )
        return {"audits": rows, "limit": limit}

    @router.get("/tls/audits/{audit_id}")
    async def get_tls_audit(
        audit_id: str, principal: OperatorPrincipal = Depends(get_principal)
    ) -> dict[str, Any]:
        record = store.get_tls_audit(audit_id)
        if not record:
            raise HTTPException(status_code=404, detail="TLS audit not found.")
        ensure_access(principal, record["engagement_id"])
        return {"audit": record}

    # ------------------------------------------------------------------
    # Expansion requests
    # ------------------------------------------------------------------
    @router.post("/expansion/requests", status_code=status.HTTP_201_CREATED)
    async def create_expansion(
        request: ExpansionRequestCreate, principal: OperatorPrincipal = Depends(get_principal)
    ) -> dict[str, Any]:
        ensure_access(principal, request.engagement_id)
        with guarded(
            principal, request.engagement_id, "expansion_request", request.mission_id or "-"
        ):
            result = expansion.submit(
                principal=principal,
                engagement_id=request.engagement_id,
                kind=request.kind,
                mission_id=request.mission_id,
                targets=request.targets,
                roe_clause=request.roe_clause,
                action_increase=request.action_increase,
                seconds_increase=request.seconds_increase,
                quota_calls_increase=request.quota_calls_increase,
                quota_tokens_increase=request.quota_tokens_increase,
                privilege=request.privilege,
                justification=request.justification,
            )
            return {"request": result.to_dict(), "privilege_classes": PRIVILEGE_CLASSES}

    @router.get("/expansion/requests")
    async def list_expansions(
        engagement_id: str = Query(min_length=3, max_length=64),
        mission_id: str | None = Query(default=None, max_length=64),
        status_filter: str | None = Query(default=None, alias="status", max_length=16),
        principal: OperatorPrincipal = Depends(get_principal),
    ) -> dict[str, Any]:
        ensure_access(principal, engagement_id)
        return {
            "requests": store.list_expansion_requests(
                engagement_id=engagement_id, mission_id=mission_id, status=status_filter
            )
        }

    @router.post("/expansion/requests/{expansion_id}/decide")
    async def decide_expansion(
        expansion_id: str,
        request: ExpansionDecision,
        principal: OperatorPrincipal = Depends(get_principal),
    ) -> dict[str, Any]:
        record = store.get_expansion_request(expansion_id)
        if not record:
            raise HTTPException(status_code=404, detail="Expansion request not found.")
        ensure_access(principal, record["engagement_id"])
        with guarded(
            principal,
            record["engagement_id"],
            "expansion_decide",
            record.get("mission_id") or record["engagement_id"],
        ):
            try:
                updated = expansion.decide(
                    expansion_id=expansion_id,
                    principal=principal,
                    decision=request.decision,
                    note=request.note,
                )
            except LookupError as exc:
                raise HTTPException(status_code=404, detail=str(exc)) from exc
            return {"request": updated}

    # ------------------------------------------------------------------
    # Evidence gate
    # ------------------------------------------------------------------
    @router.post("/gate/evaluate")
    async def evaluate_gate(
        request: GateEvaluationRequest, principal: OperatorPrincipal = Depends(get_principal)
    ) -> dict[str, Any]:
        ensure_access(principal, request.engagement_id)
        context = {
            "engagement_id": request.engagement_id,
            "target": request.target,
            "known_by_design": request.known_by_design,
            "evidence_available": True,
        }
        results = gate.evaluate_many(request.findings, context)
        store.save_gate_results(
            engagement_id=request.engagement_id,
            mission_id=request.mission_id,
            target=request.target,
            results=results,
        )
        db.write_audit_log(
            engagement_id=request.engagement_id,
            operator_id=principal.operator_id,
            target=request.target,
            tool_or_script="capability:evidence_gate",
            params={
                "mission_id": request.mission_id,
                "counts": gate.summary(results)["status_counts"],
            },
            status="completed",
            stdout_summary=f"Evidence gate evaluated {len(results)} finding(s).",
        )
        return {
            "results": results,
            "summary": gate.summary(results),
            "note": (
                "Only status='confirmed' may be reported as verified. Model text alone "
                "can never satisfy the blocking questions."
            ),
        }

    @router.get("/gate/results")
    async def gate_results(
        engagement_id: str = Query(min_length=3, max_length=64),
        mission_id: str | None = Query(default=None, max_length=64),
        limit: int = Query(default=50, ge=1, le=200),
        principal: OperatorPrincipal = Depends(get_principal),
    ) -> dict[str, Any]:
        ensure_access(principal, engagement_id)
        return {
            "results": store.list_gate_results(
                engagement_id, mission_id=mission_id, limit=limit
            )
        }

    # ------------------------------------------------------------------
    # Binary hardening triage (restricted)
    # ------------------------------------------------------------------
    @router.post("/binary/triage")
    async def binary_triage(
        request: BinaryTriageRequest, principal: OperatorPrincipal = Depends(get_principal)
    ) -> dict[str, Any]:
        ensure_access(principal, request.engagement_id)
        with guarded(principal, request.engagement_id, "binary_triage", request.artifact_path):
            modes = [
                m
                for m in registry.mode_ids()
                if "binary_hardening_triage" in registry.capabilities_for(m)
            ]
            permitted = any(registry.mode_enabled(db, m)[0] for m in modes)
            if not permitted:
                raise CapabilityError(
                    "Binary triage is not enabled in any mode currently allowed by policy."
                )
            if not (principal.can_approve() or principal.is_admin()):
                raise PermissionError(
                    "Binary triage is restricted to an approver or admin in 2.2."
                )
            result = triage(
                artifact_root=artifact_root,
                relative_path=request.artifact_path,
            )
            gate_results = gate.evaluate_many(
                result["findings"],
                {
                    "engagement_id": request.engagement_id,
                    "target": request.artifact_path,
                    "evidence_available": bool(result["artifact"]["sha256"]),
                },
            )
            store.save_gate_results(
                engagement_id=request.engagement_id,
                mission_id=None,
                target=request.artifact_path,
                results=gate_results,
            )
            db.write_audit_log(
                engagement_id=request.engagement_id,
                operator_id=principal.operator_id,
                target=request.artifact_path,
                tool_or_script="capability:binary_triage",
                params={"sha256": result["artifact"]["sha256"], "findings": len(gate_results)},
                status="completed",
                stdout_summary=f"ELF hardening triage on {request.artifact_path}.",
            )
            return {**result, "gate": gate_results}

    # ------------------------------------------------------------------
    # Reporting helper
    # ------------------------------------------------------------------
    @router.get("/capabilities/summary")
    async def capability_summary(
        engagement_id: str = Query(min_length=3, max_length=64),
        principal: OperatorPrincipal = Depends(get_principal),
    ) -> JSONResponse:
        ensure_access(principal, engagement_id)
        audits = store.list_tls_audits(engagement_id, limit=50)
        gate_rows = store.list_gate_results(engagement_id, limit=200)
        counts: dict[str, int] = {"confirmed": 0, "candidate": 0, "rejected": 0}
        for row in gate_rows:
            counts[row["status"]] = counts.get(row["status"], 0) + 1
        return JSONResponse(
            {
                "engagement_id": engagement_id,
                "artifact_directory": os.path.basename(artifact_root.rstrip("/")) or "(none)",
                "tls_audits": len(audits),
                "tls_worst_risk": _worst_risk(audits),
                "gate": counts,
                "gate_questions": [q["id"] for q in gate.questions],
                "modes": registry.mode_ids(),
            }
        )

    def _worst_risk(audits: list[dict[str, Any]]) -> str:
        order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        worst = 0
        for audit in audits:
            risk = str(((audit.get("payload") or {}).get("summary") or {}).get("risk", "info"))
            worst = max(worst, order.get(risk, 0))
        return {v: k for k, v in order.items()}[worst]

    return router
