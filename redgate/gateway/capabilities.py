"""Operational modes, capability resolution and the widened 2.2 policy surface.

The 2.2 control model widens *what a mission may do* while keeping every hard
invariant in force:

* An engagement's signed RoE window and allowlist remain authoritative.
* ``mcp_server.tools`` code-level ban lists cannot be removed by this module.
* Cloud-metadata / DNS-rebinding guards in ``gateway.policy`` are untouched.
* Budget and quota can be *raised* only through a Two-Person approval request.
* A capability name grants nothing on its own; it must also intersect the live
  tool policy, the skill snapshot and the mission ceiling.

Everything here is a pure, side-effect-free evaluation so it can be audited and
unit tested without a container or a network target.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Iterable

import yaml

MODEL_HARD_LIMITS: dict[str, int] = {
    "max_hosts": 8,  # workspace_models.MissionCreateRequest upper bound
    "max_actions": 128,  # 2.2 discretionary ceiling (legacy default remains 64/mission)
    "max_seconds": 3600,
}

CAPABILITY_MODE_POLICY = "redgate_capability_mode"

#: The prompt's sixth mode. Mandatory whenever a target speaks TLS; declared once
#: so the Gateway, the API and the decision engine agree on a single constant.
SSL_TLS_MODE_ID = "ssl_tls_analysis"


class CapabilityError(ValueError):
    """A requested mode, capability or ceiling is not permitted by policy."""


@dataclass(frozen=True)
class ModeCeiling:
    """Validated execution ceiling for one operational mode."""

    max_hosts: int
    max_actions: int
    max_seconds: int
    concurrent_missions: int


@dataclass(frozen=True)
class ModeDefinition:
    """A named operational mode and the capabilities it may exercise."""

    mode_id: str
    label: str
    summary: str
    default_skill: str
    ceiling: ModeCeiling
    capabilities: frozenset[str]
    mandatory_capabilities: frozenset[str] = frozenset()
    expansion_clauses: tuple[str, ...] = ()
    expansion_max: int = 0
    expansion_max_hosts: int = 0
    expansion_requires_approver: bool = True

    def allows(self, capability: str) -> bool:
        return capability in self.capabilities


@dataclass(frozen=True)
class CapabilityDecision:
    """Outcome of resolving one capability request."""

    allowed: bool
    mode: str
    capability: str
    reason: str
    requires_approval: bool = False
    degraded: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)


def _validate_concurrency(value: Any) -> int:
    """Concurrent missions are a system-wide cap, not a per-mission ceiling."""
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise CapabilityError("Ceiling 'concurrent_missions' must be an integer.") from exc
    if not 1 <= parsed <= 8:
        raise CapabilityError(
            f"Ceiling 'concurrent_missions'={parsed} is outside 1..8."
        )
    return parsed


def _clamped(value: Any, name: str, floor: int = 1) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise CapabilityError(f"Ceiling '{name}' must be an integer.") from exc
    hard = MODEL_HARD_LIMITS[name]
    if parsed < floor or parsed > hard:
        raise CapabilityError(f"Ceiling '{name}'={parsed} is outside {floor}..{hard}.")
    return parsed


class CapabilityRegistry:
    """Loads ``config/capabilities.yaml`` and evaluates mode/capability requests."""

    def __init__(self, manifest: dict[str, Any] | None = None) -> None:
        self._manifest = manifest or {}
        self._modes: dict[str, ModeDefinition] = {}
        for raw in self._manifest.get("modes", []) or []:
            mode = self._parse_mode(raw)
            self._modes[mode.mode_id] = mode

    # ------------------------------------------------------------------
    # Construction / introspection
    # ------------------------------------------------------------------
    @classmethod
    def from_file(cls, path: str | os.PathLike[str]) -> CapabilityRegistry:
        from pathlib import Path

        candidate = Path(path)
        if not candidate.exists():
            # Absent manifest means "no widening": only legacy behaviour remains.
            return cls({})
        data = yaml.safe_load(candidate.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise CapabilityError("capabilities.yaml must contain a top-level mapping.")
        return cls(data)

    @property
    def manifest_version(self) -> str:
        return str(self._manifest.get("manifest_version", "0"))

    @property
    def enabled(self) -> bool:
        return bool(self._modes)

    def _parse_mode(self, raw: dict[str, Any]) -> ModeDefinition:
        if not isinstance(raw, dict) or not raw.get("id"):
            raise CapabilityError("Every mode requires an 'id'.")
        ceiling_raw = dict(raw.get("ceiling") or {})
        ceiling = ModeCeiling(
            max_hosts=_clamped(ceiling_raw.get("max_hosts", 8), "max_hosts"),
            max_actions=_clamped(ceiling_raw.get("max_actions", 64), "max_actions", floor=1),
            max_seconds=_clamped(ceiling_raw.get("max_seconds", 1800), "max_seconds", floor=10),
            concurrent_missions=_validate_concurrency(
                ceiling_raw.get("concurrent_missions", 2)
            ),
        )
        capabilities = frozenset(str(c) for c in raw.get("capabilities", []))
        mandatory = frozenset(str(c) for c in raw.get("mandatory_capabilities", []))
        missing = mandatory - capabilities
        if missing:
            raise CapabilityError(
                f"Mode '{raw['id']}' declares mandatory capabilities it does not allow: {sorted(missing)}"
            )
        expansion = dict(raw.get("expansion") or {})
        return ModeDefinition(
            mode_id=str(raw["id"]),
            label=str(raw.get("label", raw["id"])),
            summary=str(raw.get("summary", "")).strip(),
            default_skill=str(raw.get("default_skill", "web-surface-audit")),
            ceiling=ceiling,
            capabilities=capabilities,
            mandatory_capabilities=mandatory,
            expansion_clauses=tuple(str(c) for c in expansion.get("allowed_clauses", [])),
            expansion_max=int(expansion.get("max_per_mission", 0) or 0),
            expansion_max_hosts=int(expansion.get("max_hosts_added", 0) or 0),
            expansion_requires_approver=bool(expansion.get("requires_approver", True)),
        )

    def mode_ids(self) -> list[str]:
        return sorted(self._modes)

    def get_mode(self, mode_id: str) -> ModeDefinition:
        mode = self._modes.get(str(mode_id))
        if mode is None and self.is_composition_alias(mode_id):
            # A declared shorthand resolves to the composed definition; the id it
            # returns is the canonical "a+b" spelling, never the alias.
            return self.compose([str(mode_id)])[0]
        if mode is None:
            raise CapabilityError(
                f"Unknown operational mode '{mode_id}'. Available: {self.mode_ids() or 'none'}."
            )
        return mode

    def describe(self) -> list[dict[str, Any]]:
        return [
            {
                "id": m.mode_id,
                "label": m.label,
                "summary": m.summary,
                "default_skill": m.default_skill,
                "ceiling": {
                    "max_hosts": m.ceiling.max_hosts,
                    "max_actions": m.ceiling.max_actions,
                    "max_seconds": m.ceiling.max_seconds,
                    "concurrent_missions": m.ceiling.concurrent_missions,
                },
                "capabilities": sorted(m.capabilities),
                "mandatory_capabilities": sorted(m.mandatory_capabilities),
                "expansion": {
                    "allowed_clauses": list(m.expansion_clauses),
                    "max_per_mission": m.expansion_max,
                    "max_hosts_added": m.expansion_max_hosts,
                    "requires_approver": m.expansion_requires_approver,
                },
            }
            for m in sorted(self._modes.values(), key=lambda x: x.mode_id)
        ]

    # ------------------------------------------------------------------
    # Mode composition (the prompt's modes are combinable)
    # ------------------------------------------------------------------
    def composition_spec(self) -> dict[str, Any]:
        return dict(self._manifest.get("composition") or {})

    def composition_allowed(self) -> list[dict[str, Any]]:
        rows = self.composition_spec().get("allowed") or []
        return [dict(r) for r in rows if r.get("id") and r.get("base")]

    def is_composition_alias(self, value: str) -> bool:
        """True when ``value`` names one of the declared compositions, not a mode."""
        return any(row["id"] == str(value).strip() for row in self.composition_allowed())

    def _resolve_alias(self, value: str) -> list[str]:
        value = str(value).strip()
        for row in self.composition_allowed():
            if row["id"] == value:
                return [str(row["base"]), *[str(a) for a in row.get("add") or []]]
        return [value]

    def compose(self, mode_ids: list[str]) -> tuple[ModeDefinition, dict[str, Any]]:
        """Merge several modes into one effective definition.

        Composition widens *the set of permitted capabilities*; it never widens
        the ceiling. The narrowest ceiling wins, mandatory capabilities are the
        union (so a composed mode cannot shed an obligation), and expansion
        clauses are intersected, so composing cannot manufacture a widening
        clause the base mode did not declare.
        """
        spec = self.composition_spec()
        if not spec.get("enabled", False):
            raise CapabilityError("Mode composition is not enabled on this Gateway.")
        expanded: list[str] = []
        for raw in mode_ids:
            for part in self._resolve_alias(raw):
                if part not in expanded:
                    expanded.append(part)
        if len(expanded) < 2:
            raise CapabilityError("Composing requires at least two distinct modes.")
        limit = int(spec.get("max_modes", 3) or 3)
        if len(expanded) > limit:
            raise CapabilityError(f"At most {limit} modes may be composed (asked for {len(expanded)}).")

        modes = [self.get_mode(m) for m in expanded]
        remove_raw = [str(r) for r in (spec.get("remove") or [])]
        capabilities: set[str] = set()
        mandatory: set[str] = set()
        for mode in modes:
            capabilities |= set(mode.capabilities)
            mandatory |= set(mode.mandatory_capabilities)
        removed = sorted(capabilities & set(remove_raw))
        capabilities -= set(remove_raw)
        # An obligation cannot be composed away.
        capabilities |= mandatory

        ceiling = ModeCeiling(
            max_hosts=min(m.ceiling.max_hosts for m in modes),
            max_actions=min(m.ceiling.max_actions for m in modes),
            max_seconds=min(m.ceiling.max_seconds for m in modes),
            concurrent_missions=min(m.ceiling.concurrent_missions for m in modes),
        )
        clauses = set(modes[0].expansion_clauses)
        for mode in modes[1:]:
            clauses &= set(mode.expansion_clauses)

        composed = ModeDefinition(
            mode_id="+".join(expanded),
            label=" + ".join(m.label for m in modes),
            summary="Composed mode; the narrowest ceiling of its parts applies.",
            default_skill=modes[0].default_skill,
            ceiling=ceiling,
            capabilities=frozenset(capabilities),
            mandatory_capabilities=frozenset(mandatory),
            expansion_clauses=tuple(sorted(clauses)),
            expansion_max=min(m.expansion_max for m in modes),
            expansion_max_hosts=min(m.expansion_max_hosts for m in modes),
            expansion_requires_approver=any(m.expansion_requires_approver for m in modes),
        )
        audit = {
            "mode_ids": expanded,
            "capabilities_added": sorted(set().union(*[m.capabilities for m in modes]) - set(modes[0].capabilities)),
            "capabilities_removed": removed,
            "mandatory": sorted(mandatory),
            "ceiling": {
                "max_hosts": ceiling.max_hosts,
                "max_actions": ceiling.max_actions,
                "max_seconds": ceiling.max_seconds,
            },
            "expansion_clauses": sorted(clauses),
            "rule": "narrowest ceiling wins; mandatory capabilities cannot be removed",
        }
        return composed, audit

    def parse_mode(self, mode_spec: Any) -> ModeDefinition:
        """Accept ``"pentest"``, ``"pentest+ssl_tls_analysis"`` or a list."""
        if isinstance(mode_spec, (list, tuple)):
            parts = [str(p) for p in mode_spec]
            if len(parts) == 1:
                return self.get_mode(parts[0])
            return self.compose(parts)[0]
        text = str(mode_spec or "").strip()
        if not text:
            raise CapabilityError("A mode id is required.")
        if "+" in text:
            return self.compose([p.strip() for p in text.split("+") if p.strip()])[0]
        return self.get_mode(text)

    # ------------------------------------------------------------------
    # Intelligent Decision Engine
    # ------------------------------------------------------------------
    def decide_approach(
        self,
        *,
        target: str,
        observations: dict[str, Any] | None = None,
        assets: list[dict[str, Any]] | None = None,
        mode_id: str | None = None,
        history: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Propose the next governed action for a target, with a stated basis.

        This is a deterministic rule engine, not a model: every recommendation
        names the observation that triggered it, the catalogue tools it would
        use, and the policy row that governs them. It returns proposals only —
        nothing here executes, expands scope or raises a budget.
        """
        obs = {str(k).lower(): v for k, v in (observations or {}).items()}
        asset_rows = [dict(a) for a in (assets or [])]
        seen = [dict(h) for h in (history or [])]

        def truthy(key: str) -> bool:
            value = obs.get(key)
            if isinstance(value, str):
                return value.strip().lower() in {"1", "true", "yes", "present", "open"}
            return bool(value)

        signals: list[str] = []
        steps: list[dict[str, Any]] = []

        def step(tool: str, policy: str, why: str, priority: int, evidence: str) -> None:
            steps.append(
                {
                    "tool": tool,
                    "policy": policy,
                    "why": why,
                    "priority": priority,
                    "evidence": evidence,
                }
            )

        # TLS first: the prompt makes it mandatory for any TLS target.
        if truthy("tls") or truthy("https") or truthy("port_443_open"):
            signals.append("tls_or_https")
            step("testssl.sh", "tool:testssl.sh", "TLS surface present; deep analysis is mandatory.", 10, "tls_or_https")
            step("tls_inspect", "tool:tls_inspect", "Pinned handshake for protocol and certificate facts.", 11, "tls_or_https")

        if truthy("web") or truthy("http_200") or truthy("server_header"):
            signals.append("web_surface")
            step("whatweb", "tool:whatweb", "HTTP responded; fingerprint the stack before choosing classes.", 20, "web_surface")
            step("nuclei", "tool:nuclei", "Template sweep for known classes on the fingerprinted stack.", 30, "web_surface")

        if truthy("directory_listing") or truthy("robots_disclosed"):
            signals.append("discoverable_paths")
            step("feroxbuster", "tool:feroxbuster", "Paths leaked; enumerate recursively within budget.", 35, "discoverable_paths")

        if truthy("parameters") or truthy("forms"):
            signals.append("input_surface")
            step("arjun", "tool:arjun", "Input surface found; discover hidden parameters first.", 40, "input_surface")
            step("dalfox", "tool:dalfox", "Parameter reflected; test XSS classes cheaply.", 45, "input_surface")

        if truthy("db_error") or truthy("sql_error") or truthy("parameterized_suspect"):
            signals.append("injection_hint")
            step("sqlmap", "tool:sqlmap", "Database error leaks a SQL surface; verify injection.", 50, "injection_hint")

        if truthy("smb_open") or truthy("ldap_open") or truthy("kerberos_open"):
            signals.append("directory_service")
            step("enum4linux", "tool:enum4linux", "Directory service reachable; enumerate before credentialed paths.", 60, "directory_service")

        if truthy("s3_bucket") or truthy("cloud_name"):
            signals.append("cloud_surface")
            step("cloud_enum", "tool:cloud_enum", "Cloud naming observed; check for public storage.", 65, "cloud_surface")

        if not steps:
            signals.append("no_signal")
            step("nmap", "tool:nmap", "Nothing known yet; start with service detection.", 5, "no_signal")

        # Skip anything already done, and say so rather than silently dropping it.
        done = {str(h.get("tool")) for h in seen if h.get("tool")}
        skipped = [s for s in steps if s["tool"] in done]
        steps = [s for s in steps if s["tool"] not in done]
        steps.sort(key=lambda s: s["priority"])

        notes: list[str] = []
        mode_note = None
        if mode_id:
            try:
                mode = self.parse_mode(mode_id)
                mode_note = {
                    "mode_id": mode.mode_id,
                    "ceiling": {
                        "max_hosts": mode.ceiling.max_hosts,
                        "max_actions": mode.ceiling.max_actions,
                        "max_seconds": mode.ceiling.max_seconds,
                    },
                    "mandatory_capabilities": sorted(mode.mandatory_capabilities),
                }
                if SSL_TLS_MODE_ID in mode.mandatory_capabilities and not any(
                    s["tool"] in {"testssl.sh", "tls_inspect", "sslyze", "sslscan"} for s in steps
                ):
                    notes.append(
                        "The active mode makes TLS analysis mandatory; a TLS step is missing "
                        "because it already ran or the target exposes no TLS."
                    )
            except CapabilityError as exc:
                notes.append(f"Mode '{mode_id}' could not be resolved: {exc}")

        return {
            "target": target,
            "signals": signals,
            "recommended": steps,
            "skipped_as_already_run": skipped,
            "asset_count": len(asset_rows),
            "mode": mode_note,
            "notes": notes,
            "advisory_only": True,
            "basis": "deterministic rules over supplied observations; no model call",
            "next_call": (
                f"POST /api/v1/offensive/tools/run with tool={steps[0]['tool']!r}" if steps else None
            ),
        }

    # ------------------------------------------------------------------
    # Toggles held in the SQLite tool_policy table (admin controlled)
    # ------------------------------------------------------------------
    def db_toggle(self, db: Any) -> dict[str, Any]:
        """Read the optional DB toggle row; absence means 'manifest is authoritative'."""
        row = db.get_tool_policy(CAPABILITY_MODE_POLICY)
        if not row:
            return {"enabled": True, "modes": None}
        allowed = dict(row.get("allowed_params") or {})
        modes = allowed.get("modes")
        return {
            "enabled": bool(row.get("enabled")),
            "modes": [str(m) for m in modes] if isinstance(modes, list) else None,
        }

    def mode_enabled(self, db: Any, mode_id: str) -> tuple[bool, str]:
        """A composed mode is enabled only when every participating mode is."""
        toggle = self.db_toggle(db)
        if not toggle["enabled"]:
            return False, "Capability modes are disabled by administrator policy."
        parts = [str(p).strip() for p in str(mode_id).split("+") if p.strip()]
        if toggle["modes"] is not None:
            blocked = [p for p in parts if p not in toggle["modes"]]
            if blocked:
                return False, (
                    f"Mode '{blocked[0]}' is not on the administrator's allow-list"
                    + (f" (composed as '{mode_id}')." if len(parts) > 1 else ".")
                )
        return True, ""

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------
    def enforce_ceiling(
        self,
        db: Any,
        mode_id: str,
        *,
        target_count: int,
        max_actions: int,
        max_seconds: int,
    ) -> ModeDefinition:
        """Validate a mission plan against the mode ceiling and admin toggle."""
        mode = self.parse_mode(mode_id)
        enabled, reason = self.mode_enabled(db, mode_id)
        if not enabled:
            raise CapabilityError(reason)
        if target_count > mode.ceiling.max_hosts:
            raise CapabilityError(
                f"Mode '{mode_id}' allows at most {mode.ceiling.max_hosts} hosts "
                f"(requested {target_count})."
            )
        if max_actions > mode.ceiling.max_actions:
            raise CapabilityError(
                f"Mode '{mode_id}' allows at most {mode.ceiling.max_actions} actions "
                f"(requested {max_actions})."
            )
        if max_seconds > mode.ceiling.max_seconds:
            raise CapabilityError(
                f"Mode '{mode_id}' allows at most {mode.ceiling.max_seconds}s "
                f"(requested {max_seconds})."
            )
        return mode

    def resolve(
        self,
        db: Any,
        mode_id: str,
        capability: str,
        *,
        tool_policy: dict[str, Any] | None = None,
        principal_role: str | None = None,
    ) -> CapabilityDecision:
        """Decide whether `capability` may be used in `mode_id` right now."""
        try:
            mode = self.parse_mode(mode_id)
        except CapabilityError as exc:
            return CapabilityDecision(False, mode_id, capability, str(exc))
        enabled, reason = self.mode_enabled(db, mode_id)
        if not enabled:
            return CapabilityDecision(False, mode_id, capability, reason)
        if not mode.allows(capability):
            return CapabilityDecision(
                False,
                mode_id,
                capability,
                f"Mode '{mode_id}' does not include capability '{capability}'.",
            )
        if tool_policy is not None:
            if not tool_policy.get("enabled"):
                return CapabilityDecision(
                    False, mode_id, capability, "The backing tool is disabled by tool policy."
                )
            if tool_policy.get("requires_approval"):
                return CapabilityDecision(
                    True,
                    mode_id,
                    capability,
                    "Capability is available but every use requires Two-Person approval.",
                    requires_approval=True,
                )
        if capability in {"external_tls_adapters", "binary_hardening_triage"}:
            role = (principal_role or "operator").lower()
            return CapabilityDecision(
                True,
                mode_id,
                capability,
                "Elevated capability; restricted to approver/admin principals.",
                requires_approval=True,
                metadata={"allowed_roles": ["approver", "admin"], "role": role},
            )
        if capability in mode.mandatory_capabilities:
            return CapabilityDecision(
                True,
                mode_id,
                capability,
                "Mandatory capability for this mode; runs during every TLS-bearing mission.",
            )
        return CapabilityDecision(True, mode_id, capability, "Permitted by mode policy.")

    def capabilities_for(self, mode_id: str) -> list[str]:
        return sorted(self.parse_mode(mode_id).capabilities)

    # ------------------------------------------------------------------
    # Static sections
    # ------------------------------------------------------------------
    def layers(self) -> list[dict[str, Any]]:
        return [dict(item) for item in self._manifest.get("layers", []) or []]

    def tls_profile(self) -> dict[str, Any]:
        return dict(self._manifest.get("tls_audit") or {})

    def expansion_policy(self) -> dict[str, Any]:
        return dict(self._manifest.get("expansion") or {})

    def evidence_gate(self) -> dict[str, Any]:
        return dict(self._manifest.get("evidence_gate") or {})

    def session_brief(self, db: Any) -> dict[str, Any]:
        """Session-start protocol payload: scope, modes, layers and TLS status."""
        modes = []
        for mode in sorted(self._modes.values(), key=lambda m: m.mode_id):
            enabled, reason = self.mode_enabled(db, mode.mode_id)
            modes.append(
                {
                    "id": mode.mode_id,
                    "label": mode.label,
                    "enabled": enabled,
                    "disabled_reason": reason,
                    "ceiling": {
                        "max_hosts": mode.ceiling.max_hosts,
                        "max_actions": mode.ceiling.max_actions,
                        "max_seconds": mode.ceiling.max_seconds,
                    },
                    "mandatory_capabilities": sorted(mode.mandatory_capabilities),
                }
            )
        tls = self.tls_profile()
        return {
            "manifest_version": self.manifest_version,
            "modes": modes,
            "layers": self.layers(),
            "tls_audit": {
                "enabled": bool(tls.get("enabled", False)),
                "mandatory_for": [m.mode_id for m in self._modes.values() if "tls_deep_analysis" in m.mandatory_capabilities],
                "protocols": list(tls.get("probe_protocols", [])),
                "minimum_acceptable_protocol": tls.get("minimum_acceptable_protocol"),
                "external_adapters": [
                    str(a.get("id")) for a in tls.get("external_adapters", []) or []
                ],
            },
            "expansion": {
                "enabled": bool(self.expansion_policy().get("enabled", False)),
                "max_pending_per_mission": int(
                    self.expansion_policy().get("max_pending_per_mission", 0) or 0
                ),
                "requires_distinct_approver": bool(
                    self.expansion_policy().get("require_distinct_approver", True)
                ),
            },
            "evidence_gate": {
                "enabled": bool(self.evidence_gate().get("enabled", False)),
                "questions": [
                    {"id": q.get("id"), "prompt": q.get("prompt")}
                    for q in self.evidence_gate().get("questions", []) or []
                ],
            },
        }


def mode_label(registry: CapabilityRegistry, mode_id: str | None) -> str:
    """Human label used in reports; never raises for an unclassified mission."""
    if not mode_id:
        return "unclassified (legacy 2.1 plan)"
    try:
        return registry.get_mode(mode_id).label
    except CapabilityError:
        return f"unknown mode '{mode_id}'"


def summarise_capabilities(decisions: Iterable[CapabilityDecision]) -> dict[str, Any]:
    decisions = list(decisions)
    return {
        "allowed": sorted(d.capability for d in decisions if d.allowed),
        "denied": sorted(d.capability for d in decisions if not d.allowed),
        "approval_required": sorted(
            d.capability for d in decisions if d.allowed and d.requires_approval
        ),
    }
