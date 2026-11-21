"""Hypothesis ranking, budget allocation and pre-report evidence scoring (2.3.1).

The referenced workflow ships an *intel engine* that turns disclosed-report
patterns into ranked vulnerability classes, a test matrix, a budget and an
exhaustion gate. This module implements the same behaviour natively, with three
deliberate differences:

* **Every number states its basis.** A score is a sum of named terms with fixed
  weights, printed next to the result. Nothing is learned behind the operator's
  back and no model is called.
* **Deterministic.** The same inputs produce the same ranking, so a reviewer can
  reproduce a prioritisation decision months later. Adaptive behaviour comes from
  recorded *outcomes* in SQLite, which are inputs, not hidden state.
* **Advisory.** A ranking never executes a tool, approves anything, raises a
  budget or promotes a finding. It orders work; the evidence gate still decides
  what is real.

Nothing here is a copy of the upstream implementation: no source, prompts or
data files were imported. See ``docs/INTEL_ENGINE.md`` for the provenance note.
"""

from __future__ import annotations

import json
import math
import uuid
from typing import Any, Iterable

from gateway.db import Database

# ---------------------------------------------------------------------------
# Vulnerability classes
# ---------------------------------------------------------------------------
#: ``signals`` are the technology/observation markers that raise a class's prior.
#: ``capability_gained`` is what a confirmed instance buys an attacker, which is
#: what the chain planner composes.
VULN_CLASSES: tuple[dict[str, Any], ...] = (
    {
        "id": "xss",
        "display": "Cross-site scripting",
        "phase": "web",
        "base_prior": 0.62,
        "signals": ("forms", "reflected_param", "dom_sink", "rich_text", "spa"),
        "capability_gained": "client_execution",
        "evidence": "rendered payload with a captured callback or DOM state",
    },
    {
        "id": "sqli",
        "display": "SQL injection",
        "phase": "web",
        "base_prior": 0.58,
        "signals": ("db_error", "numeric_param", "search_endpoint", "orm_param"),
        "capability_gained": "db_read",
        "evidence": "boolean/time differential reproduced twice with a stated baseline",
    },
    {
        "id": "idor",
        "display": "Broken object-level authorisation",
        "phase": "web",
        "base_prior": 0.66,
        "signals": ("object_id_in_path", "uuid_param", "no_tenant_check", "api_listing"),
        "capability_gained": "cross_tenant_read",
        "evidence": "two accounts, same object, different owner, both responses stored",
    },
    {
        "id": "ssrf",
        "display": "Server-side request forgery",
        "phase": "web",
        "base_prior": 0.54,
        "signals": ("url_param", "webhook", "image_fetch", "pdf_render"),
        "capability_gained": "internal_reach",
        "evidence": "callback from an operator-controlled listener, or a pinned internal banner",
    },
    {
        "id": "ssti",
        "display": "Server-side template injection",
        "phase": "web",
        "base_prior": 0.42,
        "signals": ("template_param", "report_render", "email_template"),
        "capability_gained": "server_execution",
        "evidence": "arithmetic evaluation in a rendered response, then a bounded proof",
    },
    {
        "id": "xxe",
        "display": "XML external entity",
        "phase": "web",
        "base_prior": 0.40,
        "signals": ("xml_body", "soap", "file_upload_xml", "saml"),
        "capability_gained": "file_read",
        "evidence": "out-of-band fetch from an entity, never an inline guess",
    },
    {
        "id": "rce",
        "display": "Remote code execution",
        "phase": "web",
        "base_prior": 0.35,
        "signals": ("deserialize", "upload_exec", "command_param", "known_cve"),
        "capability_gained": "server_execution",
        "evidence": "a benign marker command's output, reproduced by a second operator",
    },
    {
        "id": "auth_bypass",
        "display": "Authentication bypass",
        "phase": "auth",
        "base_prior": 0.60,
        "signals": ("jwt", "saml", "oauth", "session_param", "password_reset"),
        "capability_gained": "account_takeover",
        "evidence": "authenticated response for an account the tester does not own",
    },
    {
        "id": "race_condition",
        "display": "Race condition",
        "phase": "logic",
        "base_prior": 0.44,
        "signals": ("coupon", "balance", "invite", "quota", "state_machine"),
        "capability_gained": "logic_abuse",
        "evidence": "two committed side effects from one intended single-use action",
    },
    {
        "id": "business_logic",
        "display": "Business-logic abuse",
        "phase": "logic",
        "base_prior": 0.50,
        "signals": ("price_param", "negative_quantity", "role_param", "workflow_step"),
        "capability_gained": "logic_abuse",
        "evidence": "a stated rule, the exact request that violates it, and the resulting state",
    },
    {
        "id": "http_smuggling",
        "display": "HTTP request smuggling",
        "phase": "transport",
        "base_prior": 0.38,
        "signals": ("reverse_proxy", "cdn", "chunked", "keepalive"),
        "capability_gained": "request_integrity",
        "evidence": "desynced response ordering reproduced against a lab endpoint",
    },
    {
        "id": "open_redirect",
        "display": "Open redirect",
        "phase": "web",
        "base_prior": 0.55,
        "signals": ("redirect_param", "return_url", "next_param"),
        "capability_gained": "phishing_vector",
        "evidence": "Location header to an operator-controlled host",
    },
    {
        "id": "subdomain_takeover",
        "display": "Subdomain takeover",
        "phase": "recon",
        "base_prior": 0.52,
        "signals": ("dangling_cname", "unclaimed_bucket", "expired_hosting"),
        "capability_gained": "content_control",
        "evidence": "an operator-controlled page served from the in-scope hostname",
    },
    {
        "id": "tls_misconfiguration",
        "display": "TLS misconfiguration",
        "phase": "transport",
        "base_prior": 0.70,
        "signals": ("legacy_protocol", "weak_cipher", "expiring_cert", "no_hsts"),
        "capability_gained": "traffic_interception",
        "evidence": "a recorded handshake showing the legacy protocol or weak suite",
    },
    {
        "id": "ad_path",
        "display": "Active Directory path abuse",
        "phase": "ad",
        "base_prior": 0.45,
        "signals": ("ldap_open", "kerberos_open", "smb_signing_off", "spn"),
        "capability_gained": "domain_privesc",
        "evidence": "the shortest path and the single certificate or ACL it relies on",
    },
    {
        "id": "cloud_exposure",
        "display": "Cloud storage/identity exposure",
        "phase": "cloud",
        "base_prior": 0.57,
        "signals": ("s3_bucket", "public_acl", "instance_role", "metadata_reach"),
        "capability_gained": "data_read",
        "evidence": "an object listing from a bucket the engagement scope names",
    },
    {
        "id": "memory_corruption",
        "display": "Memory corruption",
        "phase": "binary",
        "base_prior": 0.30,
        "signals": ("unsafe_copy", "no_pie", "no_canary", "binary_artifact"),
        "capability_gained": "controlled_execution",
        "evidence": "a crash with a controlled instruction pointer under a debugger",
    },
)

CLASS_INDEX: dict[str, dict[str, Any]] = {row["id"]: row for row in VULN_CLASSES}

#: Fixed, published weights. Changing one changes every ranking, so they live in
#: one place and are echoed in every response's ``basis``.
WEIGHTS: dict[str, float] = {
    "prior": 1.0,
    "tech_signal": 0.22,
    "hacktivity_roi": 0.30,
    "brain_support": 0.18,
    "brain_refutation": -0.35,
    "outcome_success": 0.25,
    "outcome_failure": -0.20,
    "exhausted": -0.60,
}

#: A class may not be declared exhausted until it has this much recorded work.
EXHAUSTION_FLOOR: dict[str, int] = {
    "attempts": 3,
    "evidence_items": 2,
    "variants_tried": 2,
}


class IntelError(ValueError):
    """A ranking request was malformed or referenced unknown data."""


def _round(value: float) -> float:
    return round(value + 0.0, 3)


# ---------------------------------------------------------------------------
# Ranking: classes
# ---------------------------------------------------------------------------
def rank_classes(
    *,
    tech_stack: Iterable[str] | None = None,
    observations: Iterable[str] | None = None,
    hacktivity: dict[str, float] | None = None,
    brain_signals: Iterable[dict[str, str]] | None = None,
    outcomes: Iterable[dict[str, Any]] | None = None,
    limit: int = 8,
) -> dict[str, Any]:
    """Rank vulnerability classes for a target from stated, inspectable inputs.

    ``hacktivity`` maps a class id to an observed ROI in ``[0, 1]`` (for example
    a normalised average bounty for that class in the program's disclosed
    reports). ``brain_signals`` are prior loop/brain entries for the engagement;
    a ``support`` entry raises a class and a ``refute`` entry lowers it. ``outcomes``
    are recorded hunt results (``{"vuln_class": "xss", "result": "confirmed"}``).
    """
    tech = {str(t).strip().lower() for t in (tech_stack or []) if str(t).strip()}
    obs = {str(o).strip().lower() for o in (observations or []) if str(o).strip()}
    signs = tech | obs
    roi_map = {str(k): float(v) for k, v in (hacktivity or {}).items()}
    unknown = sorted(set(roi_map) - set(CLASS_INDEX))
    if unknown:
        raise IntelError(f"Unknown vulnerability class in hacktivity: {unknown}")

    support: dict[str, int] = {}
    refute: dict[str, int] = {}
    for entry in brain_signals or []:
        cls = str(entry.get("vuln_class") or entry.get("class") or "").strip()
        if cls not in CLASS_INDEX:
            continue
        if str(entry.get("stance", "support")).lower() == "refute":
            refute[cls] = refute.get(cls, 0) + 1
        else:
            support[cls] = support.get(cls, 0) + 1

    won: dict[str, int] = {}
    lost: dict[str, int] = {}
    for row in outcomes or []:
        cls = str(row.get("vuln_class") or "")
        if cls not in CLASS_INDEX:
            continue
        if str(row.get("result")) in {"confirmed", "verified", "accepted"}:
            won[cls] = won.get(cls, 0) + 1
        else:
            lost[cls] = lost.get(cls, 0) + 1

    ranked: list[dict[str, Any]] = []
    for cls in VULN_CLASSES:
        cid = cls["id"]
        matched = sorted(signs & set(cls["signals"]))
        terms: dict[str, float] = {
            "prior": cls["base_prior"],
            "tech_signal": WEIGHTS["tech_signal"] * min(len(matched), 3),
            "hacktivity_roi": WEIGHTS["hacktivity_roi"] * roi_map.get(cid, 0.0),
            "brain_support": WEIGHTS["brain_support"] * min(support.get(cid, 0), 2),
            "brain_refutation": WEIGHTS["brain_refutation"] * min(refute.get(cid, 0), 2),
            "outcome_success": WEIGHTS["outcome_success"] * min(won.get(cid, 0), 3),
            "outcome_failure": WEIGHTS["outcome_failure"] * min(lost.get(cid, 0), 3),
        }
        score = max(0.0, sum(terms.values()))
        reasons = [f"matched signal '{m}'" for m in matched]
        if roi_map.get(cid):
            reasons.append(f"program ROI {roi_map[cid]:.2f} for this class")
        if support.get(cid):
            reasons.append(f"{support[cid]} supporting brain entr(y/ies)")
        if refute.get(cid):
            reasons.append(f"{refute[cid]} refuting brain entr(y/ies)")
        if won.get(cid):
            reasons.append(f"{won[cid]} confirmed outcome(s) on this engagement")
        if lost.get(cid):
            reasons.append(f"{lost[cid]} failed attempt(s) on this engagement")
        if not matched:
            reasons.append("no signal matched; ranked on prior only")
        ranked.append(
            {
                "vuln_class": cid,
                "display": cls["display"],
                "phase": cls["phase"],
                "score": _round(score),
                "terms": {k: _round(v) for k, v in terms.items()},
                "matched_signals": matched,
                "capability_gained": cls["capability_gained"],
                "evidence_required": cls["evidence"],
                "reasons": reasons,
                "exhausted": False,
            }
        )

    ranked.sort(key=lambda r: (-r["score"], r["vuln_class"]))
    return {
        "classes": ranked[: max(1, int(limit))],
        "considered": len(ranked),
        "inputs": {
            "tech_stack": sorted(tech),
            "observations": sorted(obs),
            "hacktivity_classes": sorted(roi_map),
            "brain_signals": len(list(brain_signals or [])),
            "outcomes": len(list(outcomes or [])),
        },
        "weights": WEIGHTS,
        "advisory_only": True,
        "basis": "fixed published weights over caller-supplied signals; no model call",
    }


# ---------------------------------------------------------------------------
# Ranking: candidate surface (endpoints)
# ---------------------------------------------------------------------------
SURFACE_SIGNALS: dict[str, float] = {
    "auth": 0.25,
    "state_changing": 0.22,
    "object_reference": 0.20,
    "file_upload": 0.18,
    "admin": 0.18,
    "payment": 0.16,
    "search": 0.12,
    "redirect": 0.12,
    "deprecated": 0.10,
    "public": -0.05,
    "static": -0.12,
}
SURFACE_BUCKETS: tuple[tuple[float, str], ...] = (
    (0.45, "P1"),
    (0.25, "P2"),
    (0.01, "P3"),
)


def rank_surface(
    endpoints: Iterable[dict[str, Any]], *, kill_below: float = 0.0
) -> dict[str, Any]:
    """Bucket endpoints into P1/P2/P3/Kill from declared surface traits.

    Each endpoint is ``{"endpoint": "/api/v1/orders/{id}", "traits": ["auth",
    "object_reference"]}``. Traits are the operator's own observations; nothing
    is probed here.
    """
    rows: list[dict[str, Any]] = []
    for raw in endpoints:
        endpoint = str(raw.get("endpoint") or "").strip()
        if not endpoint:
            raise IntelError("Every endpoint needs a non-empty 'endpoint' value.")
        traits = [str(t).strip().lower() for t in (raw.get("traits") or [])]
        unknown = [t for t in traits if t not in SURFACE_SIGNALS]
        if unknown:
            raise IntelError(
                f"Unknown surface trait(s) {unknown} for '{endpoint}'. "
                f"Known: {sorted(SURFACE_SIGNALS)}"
            )
        score = sum(SURFACE_SIGNALS[t] for t in traits)
        # A path that embeds an identifier is more interesting than a static one.
        if "{" in endpoint or any(ch.isdigit() for ch in endpoint.rsplit("/", 1)[-1]):
            score += 0.08
        score = max(0.0, min(1.0, score))
        bucket = next((name for floor, name in SURFACE_BUCKETS if score >= floor), "Kill")
        if score < kill_below:
            bucket = "Kill"
        rows.append(
            {
                "endpoint": endpoint,
                "score": _round(score),
                "bucket": bucket,
                "traits": sorted(traits),
                "reasons": [f"{t} (+{SURFACE_SIGNALS[t]:.2f})" for t in sorted(traits)]
                or ["no trait matched"],
            }
        )
    rows.sort(key=lambda r: (-r["score"], r["endpoint"]))
    counts: dict[str, int] = {}
    for row in rows:
        counts[row["bucket"]] = counts.get(row["bucket"], 0) + 1
    return {
        "surface": rows,
        "buckets": counts,
        "advisory_only": True,
        "basis": "declared traits summed with fixed weights; no probing",
    }


# ---------------------------------------------------------------------------
# Budget allocation
# ---------------------------------------------------------------------------
def allocate_budget(
    classes: Iterable[dict[str, Any]],
    *,
    minutes: int = 120,
    tokens: int = 200_000,
    max_per_class: int = 4,
) -> dict[str, Any]:
    """Split a fixed time/token budget across ranked classes, proportional to score."""
    if minutes <= 0 or tokens <= 0:
        raise IntelError("A budget needs a positive minute and token allowance.")
    picked = [c for c in classes if float(c.get("score", 0)) > 0][: max_per_class]
    if not picked:
        return {"allocation": [], "unallocated": {"minutes": minutes, "tokens": tokens},
                "basis": "no class scored above zero"}
    total = sum(float(c["score"]) for c in picked)
    allocation: list[dict[str, Any]] = []
    spent_m = spent_t = 0
    for row in picked:
        share = float(row["score"]) / total
        alloc_m = max(1, int(minutes * share))
        alloc_t = max(1000, int(tokens * share))
        spent_m += alloc_m
        spent_t += alloc_t
        allocation.append(
            {
                "vuln_class": row.get("vuln_class"),
                "share": _round(share),
                "budget_minutes": alloc_m,
                "budget_tokens": alloc_t,
                "score": row.get("score"),
            }
        )
    return {
        "allocation": allocation,
        "unallocated": {"minutes": max(0, minutes - spent_m), "tokens": max(0, tokens - spent_t)},
        "basis": "proportional to rank score; classes at zero receive nothing",
    }


# ---------------------------------------------------------------------------
# Exhaustion gate
# ---------------------------------------------------------------------------
def exhaustion_gate(state: dict[str, Any]) -> dict[str, Any]:
    """Decide whether a class may be declared exhausted (i.e. stop hunting it).

    Saying "exhausted" is a claim about the *search*, not about the target, so it
    needs recorded attempts, recorded evidence and recorded variants. A gate that
    can be satisfied by waiting defeats its own purpose.
    """
    attempts = int(state.get("attempts", 0) or 0)
    evidence = int(state.get("evidence_items", 0) or 0)
    variants = int(state.get("variants_tried", 0) or 0)
    missing: list[str] = []
    if attempts < EXHAUSTION_FLOOR["attempts"]:
        missing.append(f"attempts {attempts}/{EXHAUSTION_FLOOR['attempts']}")
    if evidence < EXHAUSTION_FLOOR["evidence_items"]:
        missing.append(f"evidence_items {evidence}/{EXHAUSTION_FLOOR['evidence_items']}")
    if variants < EXHAUSTION_FLOOR["variants_tried"]:
        missing.append(f"variants_tried {variants}/{EXHAUSTION_FLOOR['variants_tried']}")
    if state.get("unexplained_anomaly"):
        missing.append("an unexplained anomaly is still open")
    ok = not missing
    return {
        "ok": ok,
        "reason": "quality floor met; the search may be closed" if ok
        else "not exhausted: " + ", ".join(missing),
        "floor": EXHAUSTION_FLOOR,
        "advisory_only": True,
    }


# ---------------------------------------------------------------------------
# Chain planning from gained capabilities
# ---------------------------------------------------------------------------
CAPABILITY_EDGES: tuple[dict[str, Any], ...] = (
    {"from": "client_execution", "next": "session_theft", "gained": "account_takeover", "impact": "high"},
    {"from": "account_takeover", "next": "idor", "gained": "cross_tenant_read", "impact": "high"},
    {"from": "cross_tenant_read", "next": "business_logic", "gained": "logic_abuse", "impact": "high"},
    {"from": "db_read", "next": "auth_bypass", "gained": "account_takeover", "impact": "critical"},
    {"from": "file_read", "next": "credential_harvest", "gained": "privilege_escalation", "impact": "critical"},
    {"from": "internal_reach", "next": "cloud_exposure", "gained": "data_read", "impact": "high"},
    {"from": "server_execution", "next": "ad_path", "gained": "domain_privesc", "impact": "critical"},
    {"from": "domain_privesc", "next": "memory_corruption", "gained": "controlled_execution", "impact": "critical"},
    {"from": "logic_abuse", "next": "business_logic", "gained": "logic_abuse", "impact": "medium"},
    {"from": "traffic_interception", "next": "auth_bypass", "gained": "account_takeover", "impact": "high"},
    {"from": "content_control", "next": "client_execution", "gained": "client_execution", "impact": "medium"},
)


def chain_plan(capabilities: Iterable[str], *, limit: int = 6) -> dict[str, Any]:
    """Suggest the next bug given the capabilities already proven.

    The graph encodes *capability* progression, not tool order: ``db_read`` →
    ``auth_bypass`` is a real escalation, whereas "run sqlmap then ffuf" is just a
    checklist. Every edge names what it buys and how much it would matter.
    """
    held = {str(c).strip() for c in capabilities if str(c).strip()}
    rows: list[dict[str, Any]] = []
    for edge in CAPABILITY_EDGES:
        if edge["from"] in held:
            rows.append(
                {
                    "from_capability": edge["from"],
                    "next": edge["next"],
                    "gained_capability": edge["gained"],
                    "terminal_impact": edge["impact"],
                    "priority": {"critical": 10, "high": 20, "medium": 30}[edge["impact"]],
                }
            )
    rows.sort(key=lambda r: (r["priority"], r["next"]))
    return {
        "chain": rows[: max(1, int(limit))],
        "held_capabilities": sorted(held),
        "unmatched": sorted(held - {e["from"] for e in CAPABILITY_EDGES}),
        "advisory_only": True,
        "basis": "static capability graph; a suggestion is a hypothesis, not a finding",
    }


# ---------------------------------------------------------------------------
# Evidence sufficiency before a report is drafted
# ---------------------------------------------------------------------------
def evidence_score(finding: dict[str, Any]) -> dict[str, Any]:
    """Score a bundle of evidence before it is submitted as a report.

    This is the *pre-report* gate. It does not replace the 7-Question Gate: that
    gate decides whether a finding may be called confirmed. This one asks a
    narrower question — would a triager accept the write-up as it stands?
    """
    checks: list[dict[str, Any]] = []

    def check(name: str, passed: bool, weight: float, note: str) -> None:
        checks.append({"check": name, "passed": bool(passed), "weight": weight, "note": note})

    steps = finding.get("reproduction") or finding.get("steps") or []
    check("reproduction_steps", len(list(steps)) >= 2, 0.20, "at least two ordered steps")
    check(
        "request_response_captured",
        bool(finding.get("request") and finding.get("response")),
        0.20,
        "request and response captured verbatim",
    )
    check("impact_stated", bool(str(finding.get("impact") or "").strip()), 0.15,
          "concrete impact, not 'security issue'")
    check("remediation_stated", bool(str(finding.get("remediation") or "").strip()), 0.10,
          "testable remediation")
    check("scope_attested", bool(finding.get("in_scope")), 0.15,
          "asset inside the signed scope at test time")
    check("redacted", bool(finding.get("redacted", False)) or not finding.get("contains_secret"),
          0.10, "no live secret or personal data in the write-up")
    check(
        "independent_reproduction",
        bool(finding.get("reproduced_by")),
        0.10,
        "a second operator reproduced it",
    )

    score = sum(c["weight"] for c in checks if c["passed"])
    failed = [c["check"] for c in checks if not c["passed"]]
    if score >= 0.85:
        decision = "submit"
    elif score >= 0.60:
        decision = "submit_with_gaps"
    else:
        decision = "do_not_submit"
    return {
        "score": _round(score),
        "decision": decision,
        "failed": failed,
        "checks": checks,
        "notes": [
            "score is the sum of satisfied checks; a failed check names exactly what a "
            "triager would ask for",
            "this gate is advisory and cannot promote a finding; the 7-Question Gate does that",
        ],
    }


# ---------------------------------------------------------------------------
# CVSS 3.1 base score (version-guarded)
# ---------------------------------------------------------------------------
CVSS31_METRICS: dict[str, dict[str, float]] = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {"N": 0.85, "L": 0.62, "H": 0.27},
    "UI": {"N": 0.85, "R": 0.62},
    "S": {"U": 0.0, "C": 1.0},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
#: PR changes when Scope is Changed; kept separate so the table stays readable.
CVSS31_PR_CHANGED: dict[str, float] = {"N": 0.85, "L": 0.68, "H": 0.5}
SUPPORTED_CVSS_VERSIONS = ("3.1",)


def _roundup(value: float) -> float:
    """CVSS v3.1 Appendix A round-up: smallest one-decimal number >= input."""
    as_int = int(round(value * 100000))
    return as_int / 100000.0 if as_int % 10000 == 0 else (math.floor(as_int / 10000) + 1) / 10.0


def cvss_base(vector: str) -> dict[str, Any]:
    """Compute a CVSS v3.1 base score from a vector string.

    v4.0 and v2 vectors are **refused** rather than approximated: a silently
    wrong severity is worse than an honest refusal, and a triager reads the score
    before reading the prose.
    """
    text = str(vector or "").strip()
    if text.upper().startswith("CVSS:4"):
        raise IntelError("CVSS v4.0 is not scored here; supply a v3.1 vector or the v4 calculator.")
    if text.upper().startswith("CVSS:2"):
        raise IntelError("CVSS v2 is not scored here; supply a v3.1 vector.")
    if text.upper().startswith("CVSS:3.0"):
        raise IntelError("CVSS v3.0 is not scored here; v3.1 is the supported version.")
    prefix = "CVSS:3.1"
    body = text[len(prefix):] if text.upper().startswith(prefix) else text
    parts = [p for p in body.split("/") if p]
    if not parts:
        raise IntelError("Empty CVSS vector.")
    parsed: dict[str, str] = {}
    for part in parts:
        if ":" not in part:
            raise IntelError(f"Malformed vector component '{part}'.")
        key, value = part.split(":", 1)
        key, value = key.upper(), value.upper()
        if key not in CVSS31_METRICS:
            raise IntelError(f"Unknown CVSS metric '{key}'.")
        if value not in CVSS31_METRICS[key]:
            raise IntelError(f"Invalid value '{value}' for metric '{key}'.")
        parsed[key] = value
    missing = [m for m in ("AV", "AC", "PR", "UI", "S", "C", "I", "A") if m not in parsed]
    if missing:
        raise IntelError(f"CVSS base vector is missing {missing}.")

    scope_changed = parsed["S"] == "C"
    iss = 1 - (
        (1 - CVSS31_METRICS["C"][parsed["C"]])
        * (1 - CVSS31_METRICS["I"][parsed["I"]])
        * (1 - CVSS31_METRICS["A"][parsed["A"]])
    )
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    pr = (CVSS31_PR_CHANGED if scope_changed else CVSS31_METRICS["PR"])[parsed["PR"]]
    exploitability = (
        8.22
        * CVSS31_METRICS["AV"][parsed["AV"]]
        * CVSS31_METRICS["AC"][parsed["AC"]]
        * pr
        * CVSS31_METRICS["UI"][parsed["UI"]]
    )
    if impact <= 0:
        score = 0.0
    elif scope_changed:
        score = _roundup(min(1.08 * (impact + exploitability), 10.0))
    else:
        score = _roundup(min(impact + exploitability, 10.0))

    severity = (
        "none" if score == 0 else "low" if score < 4.0 else "medium" if score < 7.0
        else "high" if score < 9.0 else "critical"
    )
    return {
        "vector": "CVSS:3.1/" + "/".join(f"{k}:{v}" for k, v in parsed.items()),
        "version": "3.1",
        "base_score": round(score, 1),
        "severity": severity,
        "impact_subscore": round(impact, 1),
        "exploitability_subscore": round(exploitability, 1),
        "scope_changed": scope_changed,
        "basis": "CVSS v3.1 base equation (Appendix A round-up); temporal/environmental not evaluated",
    }


# ---------------------------------------------------------------------------
# Outcome telemetry (the only state the ranking may learn from)
# ---------------------------------------------------------------------------
class OutcomeStore:
    """Append-only hunt outcomes; the adaptive input to ``rank_classes``."""

    def __init__(self, db: Database) -> None:
        self.db = db

    def record(
        self,
        *,
        engagement_id: str,
        vuln_class: str,
        result: str,
        note: str = "",
        evidence_id: str | None = None,
        operator_id: str = "",
    ) -> dict[str, Any]:
        if vuln_class not in CLASS_INDEX:
            raise IntelError(f"Unknown vulnerability class '{vuln_class}'.")
        if result not in {"confirmed", "rejected", "inconclusive", "blocked"}:
            raise IntelError(
                "result must be one of confirmed / rejected / inconclusive / blocked."
            )
        outcome_id = f"int-{uuid.uuid4().hex[:12]}"
        with self.db.transaction() as conn:
            conn.execute(
                """INSERT INTO intel_outcomes
                   (outcome_id, engagement_id, vuln_class, result, evidence_id, note,
                    operator_id, created_at)
                   VALUES (?,?,?,?,?,?,?, datetime('now'))""",
                (outcome_id, engagement_id, vuln_class, result, evidence_id,
                 note[:500], operator_id),
            )
        return self.get(outcome_id) or {"outcome_id": outcome_id}

    def get(self, outcome_id: str) -> dict[str, Any] | None:
        with self.db.connection() as conn:
            row = conn.execute(
                "SELECT * FROM intel_outcomes WHERE outcome_id=?", (outcome_id,)
            ).fetchone()
        return dict(row) if row else None

    def list(self, engagement_id: str, limit: int = 200) -> list[dict[str, Any]]:
        with self.db.connection() as conn:
            rows = conn.execute(
                """SELECT * FROM intel_outcomes WHERE engagement_id=?
                   ORDER BY created_at DESC LIMIT ?""",
                (engagement_id, limit),
            ).fetchall()
        return [dict(r) for r in rows]

    def summary(self, engagement_id: str) -> dict[str, Any]:
        with self.db.connection() as conn:
            rows = conn.execute(
                """SELECT vuln_class, result, COUNT(*) AS n FROM intel_outcomes
                   WHERE engagement_id=? GROUP BY vuln_class, result""",
                (engagement_id,),
            ).fetchall()
        table: dict[str, dict[str, int]] = {}
        for row in rows:
            table.setdefault(row["vuln_class"], {})[row["result"]] = int(row["n"])
        return {
            "engagement_id": engagement_id,
            "by_class": table,
            "classes_with_history": sorted(table),
        }


def brain_signals_from_entries(entries: Iterable[dict[str, Any]]) -> list[dict[str, str]]:
    """Map brain entries onto ranking signals without inventing structure.

    A brain row is ``kind``/``content``/``verdict``. It only counts as a signal when
    its ``content`` names a vulnerability class (``vuln_class``/``class`` in JSON
    content, or the class id as a bare word) **and** its ``verdict`` says whether the
    class was supported or refuted. Anything else is ignored rather than guessed at:
    a ranking built on half-parsed notes would be worse than no ranking.
    """
    out: list[dict[str, str]] = []
    for entry in entries:
        verdict = str(entry.get("verdict") or "").strip().lower()
        if verdict not in {"supported", "support", "refuted", "refute"}:
            continue
        stance = "support" if verdict.startswith("support") else "refute"
        content = str(entry.get("content") or "")
        payload: dict[str, Any] = {}
        try:
            loaded = json.loads(content)
            if isinstance(loaded, dict):
                payload = loaded
        except ValueError:
            payload = {}
        cls = str(payload.get("vuln_class") or payload.get("class") or "").strip()
        if cls not in CLASS_INDEX:
            words = {word.strip(".,;:()[]").lower() for word in content.split()}
            cls = next((cid for cid in CLASS_INDEX if cid in words), "")
        if cls not in CLASS_INDEX:
            continue
        out.append({"vuln_class": cls, "stance": stance})
    return out
