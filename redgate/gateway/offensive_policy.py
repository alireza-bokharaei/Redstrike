"""Posture, consent and high-impact authorisation for the 2.3 offensive surface.

The prompt's control model, implemented literally:

* **Permissive within declared scope.** For an engagement whose posture is
  ``permissive_in_scope``, an action that is not classified high-impact runs
  without per-action approval. Scope (allowlist, RoE window, DNS pinning,
  metadata block) is still enforced for every action — posture changes *approval
  choreography*, never *reachability*.
* **Two-person approval only for high impact.** ``exploitation:proof_of_concept``,
  ``credential:post_exploitation``, ``mass_scan:expanded_budget`` and any tool
  whose policy declares ``two_person`` are the only categories that require a
  second human.
* **Consent is evidence, not a checkbox.** A consent record stores a SHA-256 of
  the exact declaration text shown to the operator. Editing the policy later
  does not extend an earlier consent, because the digest no longer matches.

Nothing in this module can widen scope. It answers one question: "may this
already-in-scope action proceed, and whose signatures does it need?"
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import uuid
from dataclasses import dataclass, field
from typing import Any

import yaml

from gateway.auth import OperatorPrincipal
from gateway.db import Database

CONSENT_LEVELS = ("none", "requester", "operator", "approver", "admin")
_LEVEL_RANK = {name: index for index, name in enumerate(CONSENT_LEVELS)}

# The exhaustive list of categories that need a second human. Anything not here
# is either read-only or bounded-by-policy, and runs under consent alone.
HIGH_IMPACT_POLICIES = frozenset(
    {
        "exploitation:proof_of_concept",
        "credential:post_exploitation",
        "mass_scan:expanded_budget",
    }
)

READ_ONLY_TOOLS = frozenset(
    {"http_headers", "tls_inspect", "dns_lookup", "tcp_port_probe", "pinned_http_request"}
)


class OffensivePolicyError(ValueError):
    """A policy declaration, consent grant or authorisation check failed."""


@dataclass(frozen=True)
class PolicyRecord:
    policy_id: str
    policy_type: str
    name: str
    enabled: bool
    consent_required: str
    risk_level: str
    two_person: bool
    declaration: str
    bounds: dict[str, Any] = field(default_factory=dict)
    source: str = "config"

    @property
    def is_high_impact(self) -> bool:
        return self.two_person or self.policy_id in HIGH_IMPACT_POLICIES

    def describe(self) -> dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "policy_type": self.policy_type,
            "name": self.name,
            "enabled": self.enabled,
            "consent_required": self.consent_required,
            "risk_level": self.risk_level,
            "two_person": self.two_person,
            "high_impact": self.is_high_impact,
            "bounds": self.bounds,
            "declaration": self.declaration,
        }


@dataclass
class ActionDecision:
    """Result of evaluating one action against posture, consent and risk."""

    allowed: bool
    action: str
    posture: str
    risk_level: str
    consent_level_required: str
    consent_met: bool
    two_person_required: bool
    reason: str
    policy_id: str | None = None
    missing_consents: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "action": self.action,
            "posture": self.posture,
            "risk_level": self.risk_level,
            "consent_level_required": self.consent_level_required,
            "consent_met": self.consent_met,
            "two_person_required": self.two_person_required,
            "policy_id": self.policy_id,
            "missing_consents": list(self.missing_consents),
            "reason": self.reason,
        }


def _declaration_digest(statement: str) -> str:
    return hashlib.sha256(statement.strip().encode("utf-8")).hexdigest()


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


class OffensivePolicyEngine:
    """Load ``config/policies.yaml``, persist it, and evaluate actions."""

    def __init__(self, db: Database, manifest: dict[str, Any] | None = None) -> None:
        self.db = db
        self._manifest = dict(manifest or {})
        self._policies: dict[str, PolicyRecord] = {}
        for record in self._parse_manifest(self._manifest):
            self._policies[record.policy_id] = record

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------
    @staticmethod
    def load_manifest(path: str | Any) -> dict[str, Any]:
        from pathlib import Path

        candidate = Path(path)
        if not candidate.exists():
            return {}
        data = yaml.safe_load(candidate.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}

    @staticmethod
    def _parse_row(raw: dict[str, Any], policy_type: str) -> PolicyRecord:
        if not raw.get("policy_id"):
            raise OffensivePolicyError(f"A {policy_type} policy is missing policy_id.")
        consent = str(raw.get("consent_required", "none"))
        if consent not in CONSENT_LEVELS:
            raise OffensivePolicyError(
                f"Policy '{raw['policy_id']}' declares unknown consent level '{consent}'."
            )
        risk = str(raw.get("risk_level", "medium"))
        if risk not in {"low", "medium", "high", "critical"}:
            raise OffensivePolicyError(f"Policy '{raw['policy_id']}' has unknown risk '{risk}'.")
        bounds = dict(raw.get("bounds") or {})
        for key in ("modes", "actions", "allowed_flags", "refused_flags", "forbidden_flags"):
            if key in bounds and not isinstance(bounds[key], list):
                raise OffensivePolicyError(
                    f"Policy '{raw['policy_id']}' bounds.{key} must be a list."
                )
        return PolicyRecord(
            policy_id=str(raw["policy_id"]),
            policy_type=policy_type,
            name=str(raw.get("name", raw["policy_id"])),
            enabled=bool(raw.get("enabled", True)),
            consent_required=consent,
            risk_level=risk,
            two_person=bool(raw.get("two_person", False)),
            declaration=str(raw.get("declaration", "")).strip(),
            bounds=bounds,
            source="config",
        )

    @classmethod
    def _parse_manifest(cls, manifest: dict[str, Any]) -> list[PolicyRecord]:
        out: list[PolicyRecord] = []
        for raw in manifest.get("postures", []) or []:
            out.append(cls._parse_row(raw, "posture"))
        for raw in manifest.get("high_impact", []) or []:
            out.append(cls._parse_row(raw, "exploitation" if "exploit" in str(raw.get("policy_id")) else "credential" if "credential" in str(raw.get("policy_id")) else "mass_scan"))
        for raw in manifest.get("tools", []) or []:
            policy_type = "pwntools" if raw.get("policy_id") == "tool:pwntools" else "tool"
            out.append(cls._parse_row(raw, policy_type))
        return out

    def seed(self) -> int:
        """Persist manifest policies into SQLite (idempotent; runtime edits win)."""
        count = 0
        for record in self._policies.values():
            self.db.upsert_policy(
                policy_id=record.policy_id,
                policy_type=record.policy_type,
                name=record.name,
                enabled=record.enabled,
                consent_required=record.consent_required,
                risk_level=record.risk_level,
                two_person=record.two_person,
                declaration=record.declaration,
                bounds=record.bounds,
                updated_by="config-seed",
                overwrite=False,
            )
            count += 1
        return count

    # ------------------------------------------------------------------
    # Resolution (DB wins over the file so an admin can narrow at runtime)
    # ------------------------------------------------------------------
    def get(self, policy_id: str) -> PolicyRecord | None:
        stored = self.db.get_policy(policy_id)
        if stored:
            return PolicyRecord(
                policy_id=stored["policy_id"],
                policy_type=stored["policy_type"],
                name=stored["name"],
                enabled=bool(stored["enabled"]),
                consent_required=str(stored["consent_required"]),
                risk_level=str(stored["risk_level"]),
                two_person=bool(stored["two_person"]),
                declaration=str(stored["declaration"]),
                bounds=dict(stored["bounds"]),
                source="database",
            )
        return self._policies.get(policy_id)

    def tool_policy(self, tool_name: str) -> PolicyRecord | None:
        return self.get(f"tool:{tool_name}")

    def posture(self, engagement_id: str) -> PolicyRecord:
        posture_id = self.db.get_engagement_posture(engagement_id)
        default = next(
            (p for p in self._policies.values() if p.policy_type == "posture" and p.enabled),
            None,
        )
        if posture_id:
            found = self.get(posture_id)
            if found and found.enabled:
                return found
        if default is None:
            # Fail closed: without a posture declaration nothing is permissive.
            return PolicyRecord(
                policy_id="posture:unset",
                policy_type="posture",
                name="Unset (deny)",
                enabled=False,
                consent_required="admin",
                risk_level="critical",
                two_person=True,
                declaration="No posture is configured.",
            )
        return default

    def set_posture(self, engagement_id: str, posture_id: str, actor: str) -> dict[str, Any]:
        """Bind an engagement to a posture. Approver-only is enforced by the API."""
        policy = self.get(posture_id)
        if policy is None:
            raise OffensivePolicyError(f"Unknown posture '{posture_id}'.")
        if policy.policy_type != "posture":
            raise OffensivePolicyError(f"'{posture_id}' is not a posture.")
        if not policy.enabled:
            raise OffensivePolicyError(f"Posture '{posture_id}' is disabled.")
        self.db.set_engagement_posture(engagement_id, posture_id, actor)
        return {
            "engagement_id": engagement_id,
            "posture_id": posture_id,
            "updated_by": actor,
        }

    def list_policies(self, policy_type: str | None = None) -> list[dict[str, Any]]:
        rows = self.db.list_policies(policy_type)
        if rows:
            return rows
        return [
            p.describe()
            for p in self._policies.values()
            if policy_type is None or p.policy_type == policy_type
        ]

    def consent_requirements(
        self, engagement_id: str, operator_id: str | None = None
    ) -> dict[str, Any]:
        """Which consent levels exist for this engagement and which are still missing."""
        posture = self.posture(engagement_id)
        records = self.db.list_consents(engagement_id=engagement_id)
        live = [r for r in records if not r.get("revoked_at")]
        levels = sorted({str(r["level"]) for r in live}, key=lambda lvl: _LEVEL_RANK.get(lvl, 0))
        met = self.has_consent(
            operator_id=operator_id or "",
            level=posture.consent_required,
            engagement_id=engagement_id,
            policy=posture,
        )
        return {
            "posture": posture.policy_id,
            "required": posture.consent_required,
            "live_levels": levels,
            "missing": [] if met else [posture.consent_required],
        }

    def describe_all(self) -> dict[str, Any]:
        rows = self.db.list_policies()
        if not rows:
            rows = [p.describe() for p in self._policies.values()]
        return {
            "version": str(self._manifest.get("version", "2.3")),
            "policies": rows,
            "high_impact": sorted(HIGH_IMPACT_POLICIES),
            "postures": [r["policy_id"] for r in rows if r.get("policy_type") == "posture"],
        }

    # ------------------------------------------------------------------
    # Consent
    # ------------------------------------------------------------------
    def grant_consent(
        self,
        *,
        principal: OperatorPrincipal,
        level: str,
        engagement_id: str | None = None,
        mission_id: str | None = None,
        policy_id: str | None = None,
        statement: str = "",
        ttl_seconds: int = 12 * 3600,
    ) -> dict[str, Any]:
        """Record an explicit acknowledgement with a hash of what was shown."""
        if level not in {"operator", "approver", "admin"}:
            raise OffensivePolicyError("Consent level must be operator, approver or admin.")
        if level == "approver" and not principal.can_approve():
            raise OffensivePolicyError("Only an approver or admin may grant approver consent.")
        if level == "admin" and not principal.is_admin():
            raise OffensivePolicyError("Only an admin may grant admin consent.")
        if len(statement.strip()) < 20:
            raise OffensivePolicyError("A consent statement must be at least 20 characters.")
        if policy_id:
            policy = self.get(policy_id)
            if policy is None:
                raise OffensivePolicyError(f"Unknown policy '{policy_id}'.")
            required = _LEVEL_RANK[policy.consent_required]
            if _LEVEL_RANK[level] < required:
                raise OffensivePolicyError(
                    f"Policy '{policy_id}' requires '{policy.consent_required}' consent; "
                    f"'{level}' is insufficient."
                )
        if engagement_id and not principal.can_access_engagement(engagement_id):
            raise OffensivePolicyError("The operator is not assigned to this engagement.")
        ttl = max(60, min(int(ttl_seconds), 7 * 24 * 3600))
        now = _now()
        record = {
            "consent_id": f"cns-{uuid.uuid4().hex[:16]}",
            "engagement_id": engagement_id,
            "mission_id": mission_id,
            "operator_id": principal.operator_id,
            "level": level,
            "policy_id": policy_id,
            "declaration_sha256": _declaration_digest(statement),
            "statement": statement.strip()[:2000],
            "granted_at": now.isoformat(),
            "expires_at": (now + dt.timedelta(seconds=ttl)).isoformat(),
        }
        saved = self.db.save_consent(**record)
        self.db.write_audit_log(
            engagement_id=engagement_id or "SYSTEM",
            operator_id=principal.operator_id,
            target=mission_id or engagement_id or policy_id or "-",
            tool_or_script=f"consent:{level}",
            params={
                "policy_id": policy_id,
                "declaration_sha256": record["declaration_sha256"],
                "expires_at": record["expires_at"],
            },
            status="completed",
            stdout_summary=f"Consent '{level}' granted for {policy_id or 'engagement'}.",
        )
        return saved

    def has_consent(
        self,
        *,
        operator_id: str,
        level: str,
        engagement_id: str | None = None,
        policy: PolicyRecord | None = None,
    ) -> bool:
        """True when a live consent record of at least `level` exists.

        When a policy is supplied, the record must also hash the *current*
        declaration text, so editing the policy invalidates older consent.
        """
        if level == "none":
            return True
        records = self.db.list_consents(operator_id=operator_id, engagement_id=engagement_id)
        need = _LEVEL_RANK[level]
        for record in records:
            if record.get("revoked_at"):
                continue
            if _LEVEL_RANK[str(record["level"])] < need:
                continue
            if policy is not None and policy.declaration:
                if record["declaration_sha256"] != _declaration_digest(policy.declaration):
                    continue
                # A consent record also names the policy it was granted for. The
                # engagement posture is the standing consent for everything the
                # policy ranks no stricter; a per-action consent binds only to
                # its own action. Accepting any record with a matching digest
                # would let "I accept the permissive posture" unlock a critical
                # exploit whose declaration happens to have been shown too.
                bound = record.get("policy_id")
                if bound and bound != policy.policy_id and policy.policy_type != "posture":
                    posture = self.posture(engagement_id)
                    if _LEVEL_RANK[policy.consent_required] > _LEVEL_RANK[
                        posture.consent_required
                    ]:
                        continue
            return True
        return False

    def revoke_consent(self, consent_id: str, principal: OperatorPrincipal) -> dict[str, Any]:
        record = self.db.get_consent(consent_id)
        if not record:
            raise LookupError("Consent record not found.")
        if record["operator_id"] != principal.operator_id and not principal.is_admin():
            raise PermissionError("Only the granting operator or an admin may revoke consent.")
        return self.db.revoke_consent(consent_id)

    # ------------------------------------------------------------------
    # Action evaluation
    # ------------------------------------------------------------------
    def evaluate_action(
        self,
        *,
        principal: OperatorPrincipal,
        engagement_id: str,
        action: str,
        tool_name: str | None = None,
        mission_mode: str | None = None,
        policy_id: str | None = None,
    ) -> ActionDecision:
        """Decide whether one already-in-scope action may proceed.

        Scope reachability is NOT evaluated here; the caller must have run the
        scope engine first. This function only answers the approval question.
        """
        posture = self.posture(engagement_id)
        policy = self.get(policy_id) if policy_id else (
            self.tool_policy(tool_name) if tool_name else None
        )

        # Effective risk: a read-only tool cannot be raised above low by posture.
        if tool_name in READ_ONLY_TOOLS and policy is None:
            risk = "low"
            consent_level = "none"
            two_person = False
        elif policy is not None:
            risk = policy.risk_level
            consent_level = policy.consent_required
            two_person = policy.two_person or policy.policy_id in HIGH_IMPACT_POLICIES
            if policy.bounds.get("modes") and mission_mode:
                if mission_mode not in policy.bounds["modes"]:
                    return ActionDecision(
                        allowed=False,
                        action=action,
                        posture=posture.policy_id,
                        risk_level=risk,
                        consent_level_required=consent_level,
                        consent_met=False,
                        two_person_required=two_person,
                        policy_id=policy.policy_id,
                        reason=(
                            f"Policy '{policy.policy_id}' is not available in mode "
                            f"'{mission_mode}'."
                        ),
                    )
        else:
            # Unknown tool: inherit the posture's risk, and never assume low.
            risk = "high" if posture.risk_level in {"high", "critical"} else "medium"
            consent_level = "operator"
            two_person = False

        if posture.policy_id == "posture:strict_readonly" and risk != "low":
            return ActionDecision(
                allowed=False,
                action=action,
                posture=posture.policy_id,
                risk_level=risk,
                consent_level_required="approver",
                consent_met=False,
                two_person_required=True,
                policy_id=policy.policy_id if policy else None,
                reason=(
                    "The engagement is in strict read-only posture; this action must be "
                    "approved individually."
                ),
            )

        # Consent: posture consent is the baseline, policy consent can be stricter.
        needed = consent_level
        if _LEVEL_RANK[posture.consent_required] > _LEVEL_RANK[needed]:
            needed = posture.consent_required
        consent_ok = self.has_consent(
            operator_id=principal.operator_id,
            level=needed,
            engagement_id=engagement_id,
            policy=policy if needed == consent_level else None,
        )
        if not consent_ok:
            return ActionDecision(
                allowed=False,
                action=action,
                posture=posture.policy_id,
                risk_level=risk,
                consent_level_required=needed,
                consent_met=False,
                two_person_required=two_person,
                policy_id=policy.policy_id if policy else None,
                missing_consents=[needed],
                reason=f"Consent level '{needed}' has not been granted for this engagement.",
            )

        return ActionDecision(
            allowed=True,
            action=action,
            posture=posture.policy_id,
            risk_level=risk,
            consent_level_required=needed,
            consent_met=True,
            two_person_required=two_person,
            policy_id=policy.policy_id if policy else None,
            reason=(
                "High-impact action: requires a second human approval."
                if two_person
                else "Permitted by posture within declared scope."
            ),
        )

    # ------------------------------------------------------------------
    # Mass-scan authorisations
    # ------------------------------------------------------------------
    def grant_scan_authorization(
        self,
        *,
        engagement_id: str,
        mission_id: str | None,
        approval_id: str,
        granted_by: str,
        granted_to: str,
        max_hosts: int,
        max_requests: int,
        ttl_seconds: int = 7200,
    ) -> dict[str, Any]:
        policy = self.get("mass_scan:expanded_budget")
        bounds = policy.bounds if policy else {}
        host_cap = int(bounds.get("max_hosts", 4096))
        request_cap = int(bounds.get("max_requests", 1000000))
        if not (1 <= int(max_hosts) <= host_cap):
            raise OffensivePolicyError(f"max_hosts must be 1..{host_cap}.")
        if not (1 <= int(max_requests) <= request_cap):
            raise OffensivePolicyError(f"max_requests must be 1..{request_cap}.")
        now = _now()
        return self.db.save_scan_authorization(
            engagement_id=engagement_id,
            mission_id=mission_id,
            approval_id=approval_id,
            granted_by=granted_by,
            granted_to=granted_to,
            max_hosts=int(max_hosts),
            max_requests=int(max_requests),
            expires_at=(now + dt.timedelta(seconds=max(300, int(ttl_seconds)))).isoformat(),
        )

    def check_scan_budget(
        self, *, engagement_id: str, requested_hosts: int, requested_requests: int
    ) -> dict[str, Any]:
        """Allow only within a live authorisation; otherwise it is 'outside budget'."""
        live = self.db.live_scan_authorization(engagement_id)
        if not live:
            return {
                "allowed": False,
                "reason": (
                    "No live mass-scan authorisation for this engagement. Request "
                    "mass_scan:expanded_budget (two-person approval) first."
                ),
                "authorization_id": None,
            }
        remaining_requests = int(live["max_requests"]) - int(live["requests_used"])
        if requested_hosts > int(live["max_hosts"]):
            return {
                "allowed": False,
                "reason": (
                    f"Requested {requested_hosts} hosts but the authorisation covers "
                    f"{live['max_hosts']}."
                ),
                "authorization_id": live["authorization_id"],
            }
        if requested_requests > remaining_requests:
            return {
                "allowed": False,
                "reason": (
                    f"Requested {requested_requests} requests but only "
                    f"{remaining_requests} remain in the authorisation."
                ),
                "authorization_id": live["authorization_id"],
            }
        return {
            "allowed": True,
            "reason": "Within the authorised scan budget.",
            "authorization_id": live["authorization_id"],
            "remaining_requests": remaining_requests,
            "expires_at": live["expires_at"],
        }

    @staticmethod
    def canonical_json(value: Any) -> str:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
