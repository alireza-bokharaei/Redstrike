"""Seven-question evidence gate for confirming findings in 2.2.

The gate exists to stop the failure mode where a language model's summary is
mistaken for a verified defect. It is *deterministic*: the same finding and
context always produce the same verdict, so a confirmation can be replayed in
an audit. Model text is never an input that can pass a question on its own.

Verdicts
--------
``confirmed``
    All seven questions pass. The finding may be reported as confirmed.
``candidate``
    At least five pass and none of the *blocking* questions failed. It must be
    presented to the analyst as unverified.
``rejected``
    A blocking question failed: no evidence, out of scope, not a security
    defect, already accepted by design, model-only provenance, or disproved by
    the adversarial review. A rejected observation must not be reported as a
    finding; it may still be stored as an analyst target note.

Only ``actionable_remediation`` is non-blocking, so ``candidate`` means "every
validity question passed but the write-up is incomplete".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

# A blocking failure makes the observation invalid, not merely unconfirmed: it
# may not be presented as a candidate finding either. Only remediation quality is
# non-blocking, which is what makes "candidate" a meaningful middle state.
BLOCKING_QUESTIONS = frozenset(
    {
        "reproducible_evidence",
        "in_scope",
        "security_impact",
        "not_by_design",
        "independent_validation",
        "adversarial_review",
    }
)

# Observation sources that count as deterministic, re-runnable checks.
DETERMINISTIC_SOURCES = frozenset(
    {
        "tool:http_headers",
        "tool:tls_inspect",
        "tool:dns_lookup",
        "tool:tcp_port_probe",
        "tool:nmap",
        "tls_deep_analysis",
        "http_evidence",
        "binary_hardening_triage",
        "sandbox_script",
    }
)

MODEL_ONLY_SOURCES = frozenset({"llm", "llm:triage", "model", "synthesis"})

_STYLE_ONLY_KEY_HINTS = ("style", "cosmetic", "naming", "formatting", "typo")


def default_questions() -> list[dict[str, str]]:
    """Fallback question list when the manifest is unavailable."""
    return [
        {"id": "reproducible_evidence", "prompt": "Is there stored, hashed evidence?"},
        {"id": "in_scope", "prompt": "Was the asset in signed scope at check time?"},
        {"id": "security_impact", "prompt": "Is this a security defect, not a style issue?"},
        {"id": "not_by_design", "prompt": "Was the by-design / memory check applied?"},
        {"id": "independent_validation", "prompt": "Was it produced by a deterministic check?"},
        {"id": "adversarial_review", "prompt": "Did the devil's advocate fail to disprove it?"},
        {"id": "actionable_remediation", "prompt": "Is there a concrete remediation?"},
    ]


@dataclass
class GateResult:
    """Outcome of the seven-question gate for one finding."""

    finding_key: str
    status: str
    passed: list[str] = field(default_factory=list)
    failed: list[dict[str, str]] = field(default_factory=list)
    blocking_failures: list[str] = field(default_factory=list)
    confidence: float = 0.0
    rationale: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_key": self.finding_key,
            "status": self.status,
            "passed": list(self.passed),
            "failed": list(self.failed),
            "blocking_failures": list(self.blocking_failures),
            "confidence": round(self.confidence, 3),
            "rationale": self.rationale,
        }


class EvidenceGate:
    """Deterministic seven-question evaluation of candidate findings."""

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        cfg = dict(config or {})
        self.enabled = bool(cfg.get("enabled", True))
        self.min_confidence = float(cfg.get("min_confidence_for_candidate", 0.4))
        self.require_dual = bool(cfg.get("require_dual_verification", False))
        questions = cfg.get("questions") or default_questions()
        self.questions = [
            {"id": str(q.get("id")), "prompt": str(q.get("prompt", ""))} for q in questions
        ]

    # ------------------------------------------------------------------
    def _check(self, question_id: str, finding: dict[str, Any], context: dict[str, Any]) -> tuple[bool, str]:
        key = str(finding.get("finding_key", ""))
        severity = str(finding.get("severity", "info"))
        source = str(context.get("source") or finding.get("source") or "").lower()
        evidence = str(finding.get("evidence") or "").strip()
        confidence = float(finding.get("ai_confidence", 0.0) or 0.0)

        if question_id == "reproducible_evidence":
            if not context.get("evidence_available", True):
                return False, "No stored, hashed evidence accompanies the observation."
            if not evidence:
                return False, "The finding has an empty evidence description."
            return True, "Evidence text is present and the artifact is hashed."

        if question_id == "in_scope":
            if not context.get("engagement_id"):
                return False, "No engagement is bound to the observation."
            if context.get("in_scope") is False:
                return False, "The asset was outside the signed scope at check time."
            return True, "Asset resolved inside the engagement allowlist."

        if question_id == "security_impact":
            if any(hint in key.lower() for hint in _STYLE_ONLY_KEY_HINTS):
                return False, "The observation describes style rather than security impact."
            if severity not in {"critical", "high", "medium", "low", "info"}:
                return False, f"Unknown severity '{severity}'."
            if severity == "info":
                return True, "Informational observation; impact recorded but not asserted."
            return True, "Severity maps to a defensive control gap."

        if question_id == "not_by_design":
            if finding.get("suppressed_by_memory"):
                return False, "A stored analyst memory marks this class as by-design."
            if context.get("known_by_design"):
                return False, "The context flags this behaviour as accepted by design."
            return True, "No memory rule or design waiver suppressed it."

        if question_id == "independent_validation":
            if source in MODEL_ONLY_SOURCES:
                return False, "The claim originates from model text, not an executed check."
            if source and source not in DETERMINISTIC_SOURCES:
                return (
                    True,
                    f"Source '{source}' is not a model synthesis; treated as tool output.",
                )
            if self.require_dual and not finding.get("dual_verified"):
                return False, "Policy requires dual verification and it is absent."
            return True, "Produced by a deterministic, re-runnable check."

        if question_id == "adversarial_review":
            # Devil's advocate: look for the cheapest reasons the claim is wrong.
            if confidence < self.min_confidence:
                return (
                    False,
                    f"Confidence {confidence:.2f} is below the candidate floor "
                    f"{self.min_confidence:.2f}.",
                )
            if context.get("refuted"):
                return False, "The devil's-advocate role supplied a counter-observation."
            return True, "Adversarial review found no counter-evidence."

        if question_id == "actionable_remediation":
            if not str(finding.get("remediation") or "").strip():
                return False, "No remediation text is attached."
            return True, "A concrete remediation is recorded."

        return False, f"Unknown gate question '{question_id}'."

    # ------------------------------------------------------------------
    def evaluate(self, finding: dict[str, Any], context: dict[str, Any] | None = None) -> GateResult:
        context = dict(context or {})
        result = GateResult(finding_key=str(finding.get("finding_key", "")), status="rejected")
        if not self.enabled:
            # Gate disabled still never claims more than "candidate".
            result.status = "candidate"
            result.rationale = "Evidence gate disabled by policy; nothing may be auto-confirmed."
            return result

        for question in self.questions:
            ok, reason = self._check(question["id"], finding, context)
            if ok:
                result.passed.append(question["id"])
            else:
                result.failed.append({"id": question["id"], "reason": reason})
                if question["id"] in BLOCKING_QUESTIONS:
                    result.blocking_failures.append(question["id"])

        total = max(1, len(self.questions))
        result.confidence = len(result.passed) / total
        if result.blocking_failures:
            result.status = "rejected"
            result.rationale = (
                "Blocking question(s) failed: " + ", ".join(sorted(result.blocking_failures))
            )
        elif len(result.passed) == total:
            result.status = "confirmed"
            result.rationale = "All seven questions passed with deterministic evidence."
        elif len(result.passed) >= 5:
            result.status = "candidate"
            result.rationale = "Partial pass; present to the analyst as unverified."
        else:
            result.status = "rejected"
            result.rationale = "Fewer than five questions passed."
        return result

    def evaluate_many(
        self, findings: Iterable[dict[str, Any]], context: dict[str, Any] | None = None
    ) -> list[dict[str, Any]]:
        return [self.evaluate(f, context).to_dict() for f in findings]

    def summary(self, results: Iterable[dict[str, Any]]) -> dict[str, Any]:
        results = list(results)
        counts = {"confirmed": 0, "candidate": 0, "rejected": 0}
        for item in results:
            counts[item["status"]] = counts.get(item["status"], 0) + 1
        return {
            "total": len(results),
            "status_counts": counts,
            "confirmed_ratio": round(counts["confirmed"] / len(results), 3) if results else 0.0,
            "questions": [q["id"] for q in self.questions],
        }
