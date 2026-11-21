"""Recursive discovery and secondary target expansion for 2.3.

The prompt permits deeper enumeration, recursive discovery and secondary target
expansion **when the RoE allows it**. This module implements exactly that, with
one hard rule:

    Discovery never widens reachability by itself. A newly discovered asset is
    either (a) already inside the allowlist, in which case it becomes a testable
    node, or (b) recorded as a *proposal* that a different human must approve
    through the existing expansion queue.

That rule keeps "related assets" honest: the agent can find them, but the signed
scope still decides whether they may be touched.

Mass scanning is handled by the same budget mechanism: a scan may only exceed
the default action budget when a live ``scan_authorizations`` row covers the
requested host/request counts. "Outside budget" therefore has a concrete
meaning rather than being a policy promise.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable

from gateway.auth import OperatorPrincipal
from gateway.db import Database
from gateway.offensive_policy import OffensivePolicyEngine
from gateway.policy import ScopePolicyEngine
from gateway.workspace_store import WorkspaceStore

SAFE_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?$")
MAX_DISCOVERY_PER_RUN = 200
MAX_PROPOSALS_PER_RUN = 25


class ExplorationError(ValueError):
    """A discovery or mass-scan request violates the declared scope or budget."""


def _normalise_host(raw: str) -> str:
    text = raw.strip().lower().rstrip(".")
    if "://" in text:
        from urllib.parse import urlparse

        text = (urlparse(text).hostname or "").lower()
    if not text or any(ch in text for ch in "/\\@?# \t\r\n"):
        raise ExplorationError(f"Refusing to treat '{raw}' as a host.")
    return text


def _parent_domain(host: str) -> str:
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


@dataclass
class DiscoveryResult:
    in_scope: list[str] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)
    proposals: list[dict[str, Any]] = field(default_factory=list)
    rejected: list[dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "in_scope": sorted(self.in_scope),
            "out_of_scope": sorted(self.out_of_scope),
            "proposals": self.proposals,
            "rejected": self.rejected,
            "counts": {
                "in_scope": len(self.in_scope),
                "out_of_scope": len(self.out_of_scope),
                "proposals": len(self.proposals),
                "rejected": len(self.rejected),
            },
        }


class ExplorationService:
    """Scope-aware recursive discovery, proposals and mass-scan budgets."""

    def __init__(
        self,
        *,
        db: Database,
        scope: ScopePolicyEngine,
        store: WorkspaceStore,
        policies: OffensivePolicyEngine,
    ) -> None:
        self.db = db
        self.scope = scope
        self.store = store
        self.policies = policies

    # ------------------------------------------------------------------
    # Recursive discovery
    # ------------------------------------------------------------------
    def discover(
        self,
        *,
        principal: OperatorPrincipal,
        engagement_id: str,
        candidates: Iterable[str],
        mission_id: str | None = None,
        roe_clause: str | None = None,
        allow_related: bool | None = None,
    ) -> DiscoveryResult:
        """Classify candidate hosts found during enumeration.

        ``allow_related`` defaults to whether the engagement declares a clause
        that covers related assets; when it is false, out-of-scope discoveries
        are reported but never proposed for approval.
        """
        if not principal.can_access_engagement(engagement_id):
            raise PermissionError("The operator is not assigned to this engagement.")
        result = DiscoveryResult()
        clause = roe_clause or self._default_clause(engagement_id)
        related_allowed = (
            self._related_assets_allowed(engagement_id)
            if allow_related is None
            else bool(allow_related)
        )

        seen: set[str] = set()
        for raw in list(candidates)[:MAX_DISCOVERY_PER_RUN]:
            try:
                host = _normalise_host(raw)
            except ExplorationError as exc:
                result.rejected.append({"host": str(raw)[:120], "reason": str(exc)})
                continue
            if host in seen:
                continue
            seen.add(host)
            decision = self.scope.evaluate_target(engagement_id, host, resolve_dns=False)
            if decision.allowed:
                result.in_scope.append(host)
                continue
            result.out_of_scope.append(host)
            if not related_allowed or len(result.proposals) >= MAX_PROPOSALS_PER_RUN:
                result.rejected.append(
                    {"host": host, "reason": decision.reason or "Out of scope; no related-asset clause."}
                )
                continue
            result.proposals.append(
                {
                    "host": host,
                    "reason": (decision.reason or "Out of scope.")[:300],
                    "roe_clause": clause,
                    "mission_id": mission_id,
                    "requires": "expansion request + independent approval",
                }
            )

        self.db.write_audit_log(
            engagement_id=engagement_id,
            operator_id=principal.operator_id,
            target=mission_id or engagement_id,
            tool_or_script="exploration:discover",
            params={
                "candidates": len(seen),
                "in_scope": len(result.in_scope),
                "out_of_scope": len(result.out_of_scope),
                "proposals": len(result.proposals),
            },
            status="completed",
            stdout_summary=(
                f"Discovery classified {len(seen)} candidate(s): "
                f"{len(result.in_scope)} testable, {len(result.proposals)} proposed."
            ),
        )
        return result

    def _default_clause(self, engagement_id: str) -> str:
        """Pick a declared clause that covers related assets, if any."""
        from gateway.expansion import read_expansion_clauses

        declared = read_expansion_clauses(engagement_id)
        for preferred in ("related_assets", "in_scope_subdomains"):
            if preferred in declared:
                return preferred
        return declared[0] if declared else ""

    def _related_assets_allowed(self, engagement_id: str) -> bool:
        clause = self._default_clause(engagement_id)
        return clause in {"related_assets", "in_scope_subdomains"}

    def propose_expansion(
        self,
        *,
        principal: OperatorPrincipal,
        engagement_id: str,
        discovery: DiscoveryResult,
        mission_id: str | None,
        justification: str,
    ) -> dict[str, Any]:
        """Turn discovery proposals into an expansion request (still needs approval)."""
        from gateway.expansion import ExpansionService

        if not discovery.proposals:
            raise ExplorationError("There is nothing to propose; no out-of-scope assets found.")
        clause = discovery.proposals[0]["roe_clause"]
        if not clause:
            raise ExplorationError("The engagement declares no clause covering related assets.")
        service = ExpansionService(
            db=self.db,
            scope=self.scope,
            store=self.store,
            policy={"enabled": True, "max_pending_per_mission": 5, "request_ttl_seconds": 3600},
            registry=None,
        )
        targets = [p["host"] for p in discovery.proposals][:8]
        result = service.submit(
            principal=principal,
            engagement_id=engagement_id,
            kind="targets",
            mission_id=mission_id,
            targets=targets,
            roe_clause=clause,
            justification=justification,
        )
        return result.to_dict()

    # ------------------------------------------------------------------
    # Mass scanning
    # ------------------------------------------------------------------
    def request_mass_scan(
        self,
        *,
        principal: OperatorPrincipal,
        engagement_id: str,
        mission_id: str | None,
        target_count: int,
        request_count: int,
        justification: str,
    ) -> dict[str, Any]:
        """Queue a two-person mass-scan authorisation request."""
        if target_count < 1 or request_count < 1:
            raise ExplorationError("A mass scan needs at least one host and one request.")
        existing = self.policies.check_scan_budget(
            engagement_id=engagement_id,
            requested_hosts=target_count,
            requested_requests=request_count,
        )
        if existing["allowed"]:
            return {"status": "already_authorized", **existing}

        approval = self.db.enqueue_approval(
            engagement_id=engagement_id,
            request_type="mass_scan",
            target=mission_id or engagement_id,
            tool_or_script="mass_scan:expanded_budget",
            payload={
                "mission_id": mission_id,
                "target_count": int(target_count),
                "request_count": int(request_count),
                "justification": justification[:800],
                "policy_id": "mass_scan:expanded_budget",
            },
            requested_by=principal.operator_id,
        )
        self.db.write_audit_log(
            engagement_id=engagement_id,
            operator_id=principal.operator_id,
            target=mission_id or engagement_id,
            tool_or_script="mass_scan:request",
            params={
                "approval_id": approval["request_id"],
                "target_count": int(target_count),
                "request_count": int(request_count),
            },
            status="pending",
            stdout_summary="Mass-scan authorisation queued for two-person approval.",
        )
        return {
            "status": "pending_approval",
            "approval_id": approval["request_id"],
            "detail": (
                "A different approver must grant this before any scan exceeds the "
                "default budget."
            ),
        }

    def enforce_mass_scan(
        self,
        *,
        engagement_id: str,
        requested_hosts: int,
        requested_requests: int,
    ) -> dict[str, Any]:
        """Gate a scan that exceeds the default budget (caller already knows it does)."""
        decision = self.policies.check_scan_budget(
            engagement_id=engagement_id,
            requested_hosts=requested_hosts,
            requested_requests=requested_requests,
        )
        if not decision["allowed"]:
            raise ExplorationError(decision["reason"])
        return decision

    def consume_mass_scan(self, authorization_id: str, requests: int) -> dict[str, Any]:
        return self.db.consume_scan_budget(authorization_id, requests)

    # ------------------------------------------------------------------
    # Secondary target derivation (asset graph aware)
    # ------------------------------------------------------------------
    def derive_secondary_targets(
        self, engagement_id: str, *, mission_id: str | None = None, limit: int = 50
    ) -> dict[str, Any]:
        """Suggest in-scope follow-ups from already-known assets.

        This never invents a target: every suggestion is an existing asset row
        whose host the scope engine still allows.
        """
        assets = self.store.list_assets(engagement_id, limit=max(1, min(limit, 200)))
        in_scope, stale = [], []
        for asset in assets:
            decision = self.scope.evaluate_target(engagement_id, asset["host"], resolve_dns=False)
            item = {
                "asset_id": asset["asset_id"],
                "host": asset["host"],
                "kind": asset["kind"],
                "tested": bool(asset.get("run_count") or asset.get("evidence_count")),
            }
            (in_scope if decision.allowed else stale).append(item)
        return {
            "engagement_id": engagement_id,
            "mission_id": mission_id,
            "in_scope_targets": in_scope,
            "no_longer_in_scope": stale,
            "note": (
                "Suggestions are existing assets only. An asset that is no longer in scope "
                "must not be re-tested even if it was in scope earlier."
            ),
        }
