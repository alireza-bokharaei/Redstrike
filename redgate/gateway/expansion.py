"""Mid-engagement scope, budget and quota expansion requests (2.2).

Operators may now *request* more than the mission's original plan. The request is
never applied on submission:

1. The requester is authorised, the mission is live, and a per-mission cap on
   pending requests is enforced.
2. The requested targets must be syntactically valid allowlist entries that pass
   ``validate_allowlist_entry_syntax`` — cloud metadata and over-broad CIDRs are
   refused before a human ever sees them.
3. When the engagement declares an explicit ``expansion_clauses`` list in
   ``config/allowlist.yaml``, a request must cite a clause from that list. An
   engagement with no declared clauses cannot be widened at all.
4. A *different* principal (approver/admin) must decide. The database rule is
   additionally enforced by the existing ``approval_queue`` constraints.
5. Only on approval are allowlist rows, budget and quota mutated, each in its own
   audited transaction with the approving request id attached.
"""

from __future__ import annotations

import datetime as dt
import json
from dataclasses import dataclass
from typing import Any

from gateway.auth import OperatorPrincipal
from gateway.db import Database
from gateway.policy import ScopePolicyEngine, validate_allowlist_entry_syntax
from gateway.workspace_store import WorkspaceStore

REQUEST_KINDS = frozenset({"targets", "budget", "quota", "privilege"})
TERMINAL = frozenset({"approved", "rejected", "expired", "withdrawn"})

# Privilege classes an operator may ask for. None of these unlock banned flags;
# they change the review path, not the code-level safety invariants.
PRIVILEGE_CLASSES = {
    "elevated_review": "Request approver review for a high-impact but permitted action.",
    "destructive_confirmation": "Request explicit sign-off before any destructive action.",
    "credential_handling": "Request handling of credential material under engagement policy.",
    "mass_scan_budget": "Request a scan budget that exceeds the mission's original action cap.",
}


class ExpansionError(ValueError):
    """An expansion request violates policy and was refused before review."""


@dataclass
class ExpansionResult:
    request_id: str
    kind: str
    mission_id: str | None
    status: str
    pending: bool
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "kind": self.kind,
            "mission_id": self.mission_id,
            "status": self.status,
            "pending": self.pending,
            "detail": self.detail,
        }


def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def read_expansion_clauses(engagement_id: str, config_dir: str | None = None) -> list[str]:
    """Return the ``expansion_clauses`` declared for an engagement.

    Module-level so other subsystems (exploration, reporting) can ask the same
    question without constructing a service or reaching into ``config/``
    themselves.
    """
    import os
    from pathlib import Path

    import yaml

    base = Path(
        config_dir
        or os.environ.get(
            "REDGATE_CONFIG_DIR", str(Path(__file__).resolve().parent.parent / "config")
        )
    )
    path = base / "allowlist.yaml"
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, ValueError):
        return []
    for eng in data.get("engagements", []) or []:
        if str(eng.get("id")) == engagement_id:
            return [str(c) for c in eng.get("expansion_clauses", []) or []]
    return []


class ExpansionService:
    """Queue, decide and apply mid-engagement expansion requests."""

    def __init__(
        self,
        *,
        db: Database,
        scope: ScopePolicyEngine,
        store: WorkspaceStore,
        policy: dict[str, Any] | None = None,
        registry: Any | None = None,
        skills: list[dict[str, Any]] | None = None,
    ) -> None:
        self.db = db
        self.scope = scope
        self.store = store
        self.policy = dict(policy or {})
        self.registry = registry
        self.skills = skills

    # ------------------------------------------------------------------
    # Clauses & eligibility
    # ------------------------------------------------------------------
    def engagement_clauses(self, engagement_id: str) -> list[str]:
        """Read the optional ``expansion_clauses`` from the engagement config."""
        return read_expansion_clauses(engagement_id)

    def _mode_ceiling_actions(self, mission: dict[str, Any]) -> int:
        mode_id = mission.get("mode_id")
        if not mode_id or self.registry is None:
            return 64
        try:
            return int(self.registry.get_mode(mode_id).ceiling.max_actions)
        except Exception:  # noqa: BLE001
            return 64

    # ------------------------------------------------------------------
    # Submission
    # ------------------------------------------------------------------
    def submit(
        self,
        *,
        principal: OperatorPrincipal,
        engagement_id: str,
        kind: str,
        mission_id: str | None = None,
        targets: list[str] | None = None,
        roe_clause: str = "",
        action_increase: int = 0,
        seconds_increase: int = 0,
        quota_calls_increase: int = 0,
        quota_tokens_increase: int = 0,
        privilege: str | None = None,
        justification: str = "",
    ) -> ExpansionResult:
        if not self.policy.get("enabled", False):
            raise ExpansionError("Expansion requests are disabled by policy.")
        if kind not in REQUEST_KINDS:
            raise ExpansionError(f"Unknown expansion kind '{kind}'.")
        if not principal.can_access_engagement(engagement_id):
            raise ExpansionError("The operator is not assigned to this engagement.")
        if len(justification.strip()) < 12:
            raise ExpansionError("An expansion request needs a justification (≥12 characters).")

        mission: dict[str, Any] | None = None
        if mission_id:
            mission = self.store.get_mission(mission_id)
            if not mission or mission["engagement_id"] != engagement_id:
                raise ExpansionError("The mission does not belong to this engagement.")
            if mission["status"] not in {"running", "pausing", "paused", "draft", "cancelling"}:
                raise ExpansionError("Only a live or paused mission may be expanded.")

        clauses = self.engagement_clauses(engagement_id)
        if not clauses:
            raise ExpansionError(
                "This engagement declares no expansion clauses; scope cannot be widened."
            )
        if not roe_clause:
            raise ExpansionError(
                f"A RoE clause is required. Declared clauses: {', '.join(clauses)}."
            )
        if roe_clause not in clauses:
            raise ExpansionError(
                f"RoE clause '{roe_clause}' is not declared for this engagement "
                f"({', '.join(clauses)})."
            )

        max_pending = int(self.policy.get("max_pending_per_mission", 5) or 0)
        if mission_id and self._pending_count(mission_id) >= max_pending:
            raise ExpansionError(
                f"At most {max_pending} pending expansion requests are allowed per mission."
            )

        payload: dict[str, Any] = {"kind": kind, "roe_clause": roe_clause, "justification": justification[:800]}

        if kind == "targets":
            clean = self._validate_targets(engagement_id, targets or [])
            if not clean:
                raise ExpansionError("At least one target must be proposed.")
            if mission and self.registry is not None and mission.get("mode_id"):
                mode = self.registry.get_mode(str(mission["mode_id"]))
                existing = len(mission.get("intents", []))
                if existing + len(clean) > mode.ceiling.max_hosts:
                    raise ExpansionError(
                        f"Mode '{mode.mode_id}' allows at most {mode.ceiling.max_hosts} hosts "
                        f"in total; the mission already has {existing}."
                    )
            payload["targets"] = clean
        elif kind == "budget":
            payload.update(
                self._validate_budget_increase(mission, action_increase, seconds_increase)
            )
            if not payload.get("action_increase") and not payload.get("seconds_increase"):
                raise ExpansionError("A budget request must raise actions and/or seconds.")
        elif kind == "quota":
            payload.update(
                self._validate_quota_increase(quota_calls_increase, quota_tokens_increase)
            )
            if not payload.get("quota_calls_increase") and not payload.get("quota_tokens_increase"):
                raise ExpansionError("A quota request must raise calls and/or tokens.")
        else:  # privilege
            if privilege not in PRIVILEGE_CLASSES:
                raise ExpansionError(
                    f"Unknown privilege class '{privilege}'. Known: {sorted(PRIVILEGE_CLASSES)}."
                )
            payload["privilege"] = privilege
            payload["privilege_description"] = PRIVILEGE_CLASSES[privilege]

        # Reuse the existing Two-Person approval queue: it already enforces
        # requested_by != approved_by in SQL as well as in Python.
        approval = self.db.enqueue_approval(
            engagement_id=engagement_id,
            request_type=f"expansion:{kind}",
            target=mission_id or engagement_id,
            tool_or_script=f"expansion:{kind}",
            payload={"mission_id": mission_id, **payload},
            requested_by=principal.operator_id,
        )
        record = self.store.save_expansion_request(
            engagement_id=engagement_id,
            mission_id=mission_id,
            kind=kind,
            requested_by=principal.operator_id,
            approval_id=approval["request_id"],
            roe_clause=roe_clause,
            justification=justification[:800],
            payload=payload,
            ttl_seconds=int(self.policy.get("request_ttl_seconds", 3600) or 3600),
        )
        self.db.write_audit_log(
            engagement_id=engagement_id,
            operator_id=principal.operator_id,
            target=mission_id or engagement_id,
            tool_or_script=f"expansion:request:{kind}",
            params={
                "expansion_id": record["expansion_id"],
                "approval_id": approval["request_id"],
                "roe_clause": roe_clause,
                "detail": payload,
            },
            status="pending",
            stdout_summary="Expansion request queued for independent approval.",
        )
        return ExpansionResult(
            request_id=record["expansion_id"],
            kind=kind,
            mission_id=mission_id,
            status="pending",
            pending=True,
            detail="Queued for a different approver; nothing has changed yet.",
        )

    # ------------------------------------------------------------------
    # Validation helpers
    # ------------------------------------------------------------------
    def _pending_count(self, mission_id: str) -> int:
        return sum(
            1
            for row in self.store.list_expansion_requests(mission_id=mission_id, limit=100)
            if row["status"] == "pending"
        )

    def _validate_targets(self, engagement_id: str, targets: list[str]) -> list[str]:
        clean: list[str] = []
        for raw in targets[:8]:
            try:
                normalized = validate_allowlist_entry_syntax(str(raw))
            except ValueError as exc:
                raise ExpansionError(f"Target '{raw}' rejected: {exc}") from exc
            # Scope engine still has the final say (RoE window, rebinding guard).
            decision = self.scope.evaluate_target(engagement_id, normalized, resolve_dns=False)
            if decision.allowed:
                raise ExpansionError(
                    f"Target '{normalized}' is already inside the engagement scope."
                )
            if any(blocked in (decision.reason or "").lower() for blocked in ("metadata", "prohibited")):
                raise ExpansionError(f"Target '{normalized}' is permanently prohibited.")
            if normalized not in clean:
                clean.append(normalized)
        return clean

    def _validate_budget_increase(
        self, mission: dict[str, Any] | None, action_increase: int, seconds_increase: int
    ) -> dict[str, int]:
        cfg = dict(self.policy.get("budget_elevation") or {})
        max_actions_inc = int(cfg.get("max_actions_increase", 32))
        max_seconds_inc = int(cfg.get("max_seconds_increase", 900))
        max_total_actions = int(cfg.get("max_total_actions", 128))
        max_total_seconds = int(cfg.get("max_total_seconds", 3600))
        action_increase, seconds_increase = int(action_increase or 0), int(seconds_increase or 0)
        if action_increase < 0 or seconds_increase < 0:
            raise ExpansionError("Increases must be non-negative.")
        if action_increase > max_actions_inc:
            raise ExpansionError(f"At most {max_actions_inc} extra actions per request.")
        if seconds_increase > max_seconds_inc:
            raise ExpansionError(f"At most {max_seconds_inc} extra seconds per request.")
        if mission:
            new_actions = int(mission["max_actions"]) + action_increase
            new_seconds = int(mission["max_seconds"]) + seconds_increase
            if new_actions > max_total_actions:
                raise ExpansionError(
                    f"Total actions would be {new_actions}; the policy ceiling is {max_total_actions}."
                )
            if new_actions > self._mode_ceiling_actions(mission):
                raise ExpansionError(
                    f"Total actions would exceed the mission mode's ceiling "
                    f"({self._mode_ceiling_actions(mission)})."
                )
            if new_seconds > max_total_seconds:
                raise ExpansionError(
                    f"Total seconds would be {new_seconds}; the policy ceiling is {max_total_seconds}."
                )
        return {"action_increase": action_increase, "seconds_increase": seconds_increase}

    def _validate_quota_increase(self, calls: int, tokens: int) -> dict[str, int]:
        cfg = dict(self.policy.get("quota_elevation") or {})
        calls, tokens = int(calls or 0), int(tokens or 0)
        if calls < 0 or tokens < 0:
            raise ExpansionError("Increases must be non-negative.")
        if calls > int(cfg.get("max_calls_increase", 200)):
            raise ExpansionError(
                f"At most {cfg.get('max_calls_increase', 200)} extra calls per request."
            )
        if tokens > int(cfg.get("max_tokens_increase", 200000)):
            raise ExpansionError(
                f"At most {cfg.get('max_tokens_increase', 200000)} extra tokens per request."
            )
        return {"quota_calls_increase": calls, "quota_tokens_increase": tokens}

    # ------------------------------------------------------------------
    # Decisions
    # ------------------------------------------------------------------
    def decide(
        self,
        *,
        expansion_id: str,
        principal: OperatorPrincipal,
        decision: str,
        note: str = "",
    ) -> dict[str, Any]:
        record = self.store.get_expansion_request(expansion_id)
        if not record:
            raise LookupError("Expansion request not found.")
        if record["status"] != "pending":
            raise ExpansionError(f"Request is already {record['status']}.")
        requester = self.db.get_approval(record["approval_id"])
        if not requester:
            raise ExpansionError("The linked approval record is missing.")
        if requester["requested_by"] == principal.operator_id:
            raise PermissionError("Two-Person Rule: the requester cannot decide their own request.")
        if not principal.can_approve():
            raise PermissionError("Only an approver or admin may decide expansion requests.")
        if not principal.can_access_engagement(record["engagement_id"]):
            raise PermissionError("The approver is not assigned to this engagement.")
        if dt.datetime.fromisoformat(record["expires_at"]) <= _utcnow():
            self.store.finish_expansion(expansion_id, "expired", note="Request TTL elapsed.")
            raise ExpansionError("The expansion request has expired.")

        if decision == "rejected":
            self.db.decide_approval(
                record["approval_id"], principal.operator_id, "rejected", note
            )
            updated = self.store.finish_expansion(expansion_id, "rejected", note=note)
            self.db.write_audit_log(
                engagement_id=record["engagement_id"],
                operator_id=principal.operator_id,
                target=record["mission_id"] or record["engagement_id"],
                tool_or_script=f"expansion:rejected:{record['kind']}",
                params={"expansion_id": expansion_id, "note": note},
                status="rejected",
                rejection_reason=note or "Rejected by approver.",
            )
            return updated

        if decision != "approved":
            raise ExpansionError("Decision must be 'approved' or 'rejected'.")

        self.db.decide_approval(record["approval_id"], principal.operator_id, "approved", note)
        applied = self._apply(record, principal, note)
        updated = self.store.finish_expansion(
            expansion_id, "approved", note=note, applied=applied
        )
        self.db.write_audit_log(
            engagement_id=record["engagement_id"],
            operator_id=principal.operator_id,
            target=record["mission_id"] or record["engagement_id"],
            tool_or_script=f"expansion:approved:{record['kind']}",
            params={"expansion_id": expansion_id, "applied": applied, "note": note},
            status="approved",
            stdout_summary=f"Expansion applied: {json.dumps(applied, sort_keys=True)}"[:1000],
        )
        return updated

    # ------------------------------------------------------------------
    # Application
    # ------------------------------------------------------------------
    def _apply(
        self, record: dict[str, Any], principal: OperatorPrincipal, note: str
    ) -> dict[str, Any]:
        payload = record["payload"]
        kind = record["kind"]
        engagement_id = record["engagement_id"]
        mission_id = record.get("mission_id")
        applied: dict[str, Any] = {"kind": kind}

        if kind == "targets":
            added = []
            for target in payload.get("targets", []):
                self.db.add_allowlist_target(
                    engagement_id,
                    target,
                    f"Approved expansion {record['expansion_id']} ({payload.get('roe_clause')})",
                    principal.operator_id,
                )
                added.append(target)
            applied["targets_added"] = added
            if mission_id:
                self.store.add_expansion_intents(mission_id, added)
                applied["intents_added"] = len(added)

        elif kind == "budget":
            if not mission_id:
                raise ExpansionError("A budget expansion must reference a mission.")
            applied.update(
                self.store.raise_mission_budget(
                    mission_id,
                    action_increase=int(payload.get("action_increase", 0)),
                    seconds_increase=int(payload.get("seconds_increase", 0)),
                )
            )

        elif kind == "quota":
            requester = self.db.get_approval(record["approval_id"])
            owner = requester["requested_by"] if requester else record["requested_by"]
            applied.update(
                self.db.raise_quota(
                    operator_id=owner,
                    calls_delta=int(payload.get("quota_calls_increase", 0)),
                    tokens_delta=int(payload.get("quota_tokens_increase", 0)),
                )
            )
            applied["operator_id"] = owner

        elif kind == "privilege":
            # No capability is granted here. The record is the authorisation
            # proof a human must cite before an elevated action is approved.
            applied["privilege"] = payload.get("privilege")
            applied["note"] = (
                "Recorded authorisation only; elevated actions still need their own approval."
            )
        return applied
