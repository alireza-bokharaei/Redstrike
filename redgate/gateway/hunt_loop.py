"""Agent hunt loops, the 7-Question Gate, and the persistent brain (2.3).

Adapted from the pentest-agents workflow: a role does not "find" a vulnerability,
it opens a *hypothesis*, tests it, and must survive seven questions before the
result is promoted to a candidate finding. Two ideas are worth stating plainly
because they are what makes the loop useful rather than decorative:

* **A loop can lose.** ``killed`` is a first-class outcome, recorded with a
  reason. A roster that only ever produces findings is not testing anything.
* **The brain is append-only.** A corrected belief is a new entry, never an edit,
  so the reasoning trail survives a session and a reviewer can see why a target
  was abandoned.

The questions are deliberately answerable from stored evidence. If a question
cannot be answered, the loop must say so — "unknown" blocks promotion exactly
like "no". That is the difference between a gate and a formality.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from typing import Any

from gateway.agents_registry import AGENT_ROLES, get_role
from gateway.auth import OperatorPrincipal
from gateway.db import Database

MAX_HYPOTHESIS_CHARS = 2000
MAX_CONTENT_CHARS = 8000
OPEN_STATES = ("open", "testing", "advanced")

#: The 7-Question Gate. Each question has an id, the exact thing it asks, and the
#: evidence field that can answer it. ``blocks`` says what an unanswered question
#: prevents (kept short so a refusal message is readable).
SEVEN_QUESTIONS: tuple[dict[str, str], ...] = (
    {
        "id": "q1_reproducible",
        "question": "Can a second person reproduce this from the stored PoC and steps alone?",
        "evidence": "exploit_id/poc digest + reproduction steps",
        "blocks": "promotion to a candidate finding",
    },
    {
        "id": "q2_in_scope",
        "question": "Is the affected asset inside the signed scope at the time of testing?",
        "evidence": "scope decision captured in the audit log",
        "blocks": "any external claim",
    },
    {
        "id": "q3_security_impact",
        "question": "What can an attacker actually do that they could not do before?",
        "evidence": "impact statement tied to an observed capability",
        "blocks": "severity above informational",
    },
    {
        "id": "q4_not_by_design",
        "question": "Is this behaviour intended, documented, or an accepted risk?",
        "evidence": "spec, documentation, or client confirmation",
        "blocks": "reporting as a vulnerability",
    },
    {
        "id": "q5_independent_validation",
        "question": "Did someone other than the author confirm it independently?",
        "evidence": "verification record from a different operator",
        "blocks": "the 'Confirmed' label",
    },
    {
        "id": "q6_adversarial_review",
        "question": "What is the strongest argument that this is not a real finding?",
        "evidence": "devil's-advocate note and why it fails",
        "blocks": "promotion past candidate",
    },
    {
        "id": "q7_blast_radius",
        "question": "What is the blast radius of proving it, and is that proportional?",
        "evidence": "PoC scope: single request, single record, no persistence",
        "blocks": "execution of the PoC",
    },
)

QUESTION_IDS = tuple(q["id"] for q in SEVEN_QUESTIONS)


class HuntLoopError(ValueError):
    """The hunt-loop request is malformed or violates the gate."""


def _utcnow() -> str:
    import datetime as dt

    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def _norm_verdict(raw: Any) -> str:
    text = str(raw).strip().lower()
    if text in {"yes", "y", "true", "pass", "passed"}:
        return "yes"
    if text in {"no", "n", "false", "fail", "failed"}:
        return "no"
    if text in {"unknown", "n/a", "na", "unverified", "?"}:
        return "unknown"
    raise HuntLoopError(f"Answer must be yes/no/unknown, got '{raw}'.")


@dataclass
class GateResult:
    passed: bool
    answers: dict[str, str]
    blocking: list[dict[str, str]]
    unanswered: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "answers": self.answers,
            "blocking": self.blocking,
            "unanswered": self.unanswered,
            "questions": [dict(q) for q in SEVEN_QUESTIONS],
        }


def evaluate_gate(answers: dict[str, Any] | None) -> GateResult:
    """Apply the 7-Question Gate.

    Any ``no`` or ``unknown`` blocks. Question 7 (blast radius) is special: a
    ``no`` there means the PoC itself is disproportionate, which is worse than an
    incomplete answer, so it is surfaced first in the blocking list.
    """
    supplied = {k: _norm_verdict(v) for k, v in (answers or {}).items() if k in QUESTION_IDS}
    blocking: list[dict[str, str]] = []
    unanswered: list[str] = []
    for question in SEVEN_QUESTIONS:
        qid = question["id"]
        verdict = supplied.get(qid)
        if verdict is None:
            unanswered.append(qid)
            blocking.append(
                {"question_id": qid, "verdict": "unanswered", "detail": question["question"], "blocks": question["blocks"]}
            )
        elif verdict != "yes":
            blocking.append(
                {
                    "question_id": qid,
                    "verdict": verdict,
                    "detail": question["question"],
                    "blocks": question["blocks"],
                }
            )
    blocking.sort(key=lambda b: 0 if b["question_id"] == "q7_blast_radius" else 1)
    return GateResult(passed=not blocking, answers=supplied, blocking=blocking, unanswered=unanswered)


class HuntLoopService:
    """Loops, gate application and the append-only brain."""

    def __init__(self, *, db: Database) -> None:
        self.db = db

    # ------------------------------------------------------------------
    # Loops
    # ------------------------------------------------------------------
    def open_loop(
        self,
        *,
        principal: OperatorPrincipal,
        engagement_id: str,
        role_id: str,
        hypothesis: str,
        mission_id: str | None = None,
        max_iterations: int = 8,
    ) -> dict[str, Any]:
        try:
            role = get_role(role_id)
        except KeyError as exc:
            raise HuntLoopError(str(exc)) from exc
        text = hypothesis.strip()
        if len(text) < 12:
            raise HuntLoopError("A hypothesis must be a testable sentence, not a label.")
        if len(text) > MAX_HYPOTHESIS_CHARS:
            raise HuntLoopError(f"Hypothesis exceeds {MAX_HYPOTHESIS_CHARS} characters.")
        if not principal.can_access_engagement(engagement_id):
            raise PermissionError("The operator is not assigned to this engagement.")
        if not (1 <= int(max_iterations) <= 64):
            raise HuntLoopError("max_iterations must be 1..64.")

        loop_id = f"loop-{uuid.uuid4().hex[:12]}"
        now = _utcnow()
        with self.db._write_lock, self.db.connection() as conn:  # noqa: SLF001
            conn.execute(
                """INSERT INTO hunt_loops
                     (loop_id, engagement_id, mission_id, role_id, hypothesis, status,
                      iteration, max_iterations, requested_by, payload_json, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, 'open', 0, ?, ?, ?, ?, ?)""",
                (
                    loop_id,
                    engagement_id,
                    mission_id,
                    role.role_id,
                    text,
                    int(max_iterations),
                    principal.operator_id,
                    json.dumps({"role_title": role.title, "refutation": role.refutation}),
                    now,
                    now,
                ),
            )
        self.append_brain(
            principal=principal,
            engagement_id=engagement_id,
            kind="hypothesis",
            content=text,
            loop_id=loop_id,
            role_id=role.role_id,
            mission_id=mission_id,
        )
        return self.get_loop(loop_id)

    def iterate(
        self,
        *,
        principal: OperatorPrincipal,
        loop_id: str,
        note: str,
        status: str | None = None,
    ) -> dict[str, Any]:
        loop = self.get_loop(loop_id)
        if loop["status"] not in OPEN_STATES:
            raise HuntLoopError(f"Loop is '{loop['status']}' and cannot iterate further.")
        if loop["iteration"] >= loop["max_iterations"]:
            raise HuntLoopError(
                f"Loop reached its {loop['max_iterations']}-iteration budget. Kill it with a "
                "reason, or open a new loop with a sharper hypothesis."
            )
        new_status = status or "testing"
        if new_status not in ("testing", "advanced", "blocked"):
            raise HuntLoopError("Iteration status must be testing, advanced, or blocked.")
        with self.db._write_lock, self.db.connection() as conn:  # noqa: SLF001
            conn.execute(
                "UPDATE hunt_loops SET iteration=iteration+1, status=?, updated_at=? WHERE loop_id=?",
                (new_status, _utcnow(), loop_id),
            )
        self.append_brain(
            principal=principal,
            engagement_id=loop["engagement_id"],
            kind="note",
            content=note,
            loop_id=loop_id,
            role_id=loop["role_id"],
            mission_id=loop["mission_id"],
        )
        return self.get_loop(loop_id)

    def kill_loop(
        self, *, principal: OperatorPrincipal, loop_id: str, reason: str
    ) -> dict[str, Any]:
        loop = self.get_loop(loop_id)
        if not reason.strip():
            raise HuntLoopError("A killed loop needs a reason; dead ends are evidence too.")
        with self.db._write_lock, self.db.connection() as conn:  # noqa: SLF001
            conn.execute(
                "UPDATE hunt_loops SET status='killed', kill_reason=?, updated_at=? WHERE loop_id=?",
                (reason.strip()[:1000], _utcnow(), loop_id),
            )
        self.append_brain(
            principal=principal,
            engagement_id=loop["engagement_id"],
            kind="lesson",
            content=reason.strip(),
            loop_id=loop_id,
            role_id=loop["role_id"],
            verdict="killed",
            mission_id=loop["mission_id"],
        )
        return self.get_loop(loop_id)

    def apply_gate(
        self,
        *,
        principal: OperatorPrincipal,
        loop_id: str,
        answers: dict[str, Any],
        evidence_ref: str = "",
    ) -> dict[str, Any]:
        """Apply the gate and record every answer in the brain, pass or fail."""
        loop = self.get_loop(loop_id)
        result = evaluate_gate(answers)
        with self.db._write_lock, self.db.connection() as conn:  # noqa: SLF001
            conn.execute(
                "UPDATE hunt_loops SET status=?, updated_at=? WHERE loop_id=?",
                ("advanced" if result.passed else "blocked", _utcnow(), loop_id),
            )
        for qid, verdict in result.answers.items():
            self.append_brain(
                principal=principal,
                engagement_id=loop["engagement_id"],
                kind="question",
                content=next(q["question"] for q in SEVEN_QUESTIONS if q["id"] == qid),
                loop_id=loop_id,
                role_id=loop["role_id"],
                question_id=qid,
                verdict=verdict,
                evidence_ref=evidence_ref,
                mission_id=loop["mission_id"],
            )
        self.append_brain(
            principal=principal,
            engagement_id=loop["engagement_id"],
            kind="verdict",
            content=(
                "Gate passed: the hypothesis may be promoted to a candidate finding."
                if result.passed
                else "Gate blocked: " + "; ".join(b["question_id"] for b in result.blocking)
            ),
            loop_id=loop_id,
            role_id=loop["role_id"],
            verdict="passed" if result.passed else "blocked",
            mission_id=loop["mission_id"],
        )
        self.db.write_audit_log(
            engagement_id=loop["engagement_id"],
            operator_id=principal.operator_id,
            target=loop_id,
            tool_or_script="hunt:gate",
            params={
                "loop_id": loop_id,
                "passed": result.passed,
                "blocking": [b["question_id"] for b in result.blocking],
            },
            status="completed",
            stdout_summary=(
                f"7-Question Gate {'passed' if result.passed else 'blocked'} for {loop_id}."
            ),
        )
        return {"loop_id": loop_id, "status": "advanced" if result.passed else "blocked", **result.to_dict()}

    def get_loop(self, loop_id: str) -> dict[str, Any]:
        with self.db.connection() as conn:
            row = conn.execute("SELECT * FROM hunt_loops WHERE loop_id=?", (loop_id,)).fetchone()
        if not row:
            raise HuntLoopError("Unknown hunt loop.")
        data = dict(row)
        data["payload"] = json.loads(data.pop("payload_json") or "{}")
        return data

    def list_loops(
        self, engagement_id: str, *, status: str | None = None, limit: int = 100
    ) -> list[dict[str, Any]]:
        clauses = ["engagement_id=?"]
        params: list[Any] = [engagement_id]
        if status:
            clauses.append("status=?")
            params.append(status)
        params.append(max(1, min(limit, 500)))
        with self.db.connection() as conn:
            rows = conn.execute(
                f"""SELECT loop_id, mission_id, role_id, hypothesis, status, iteration,
                           max_iterations, kill_reason, created_at, updated_at
                      FROM hunt_loops WHERE {' AND '.join(clauses)}
                     ORDER BY updated_at DESC LIMIT ?""",
                params,
            ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Brain
    # ------------------------------------------------------------------
    def append_brain(
        self,
        *,
        principal: OperatorPrincipal,
        engagement_id: str,
        kind: str,
        content: str,
        loop_id: str | None = None,
        role_id: str = "",
        question_id: str = "",
        verdict: str = "",
        evidence_ref: str = "",
        mission_id: str | None = None,
    ) -> dict[str, Any]:
        if kind not in ("hypothesis", "question", "evidence", "verdict", "lesson", "note"):
            raise HuntLoopError(f"Unknown brain entry kind '{kind}'.")
        text = content.strip()
        if not text:
            raise HuntLoopError("A brain entry needs content.")
        entry_id = f"brain-{uuid.uuid4().hex[:12]}"
        now = _utcnow()
        with self.db._write_lock, self.db.connection() as conn:  # noqa: SLF001
            conn.execute(
                """INSERT INTO brain_entries
                     (entry_id, engagement_id, mission_id, loop_id, role_id, kind,
                      question_id, content, verdict, evidence_ref, author, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    entry_id,
                    engagement_id,
                    mission_id,
                    loop_id,
                    role_id,
                    kind,
                    question_id,
                    text[:MAX_CONTENT_CHARS],
                    verdict,
                    evidence_ref[:400],
                    principal.operator_id,
                    now,
                ),
            )
        return {
            "entry_id": entry_id,
            "kind": kind,
            "loop_id": loop_id,
            "created_at": now,
        }

    def recall(
        self, engagement_id: str, *, loop_id: str | None = None, limit: int = 200
    ) -> list[dict[str, Any]]:
        """Read the brain back, oldest first, so a session can resume reasoning."""
        clauses = ["engagement_id=?"]
        params: list[Any] = [engagement_id]
        if loop_id:
            clauses.append("loop_id=?")
            params.append(loop_id)
        params.append(max(1, min(limit, 1000)))
        with self.db.connection() as conn:
            rows = conn.execute(
                f"""SELECT entry_id, mission_id, loop_id, role_id, kind, question_id,
                           content, verdict, evidence_ref, author, created_at
                      FROM brain_entries WHERE {' AND '.join(clauses)}
                     ORDER BY created_at, entry_id LIMIT ?""",
                params,
            ).fetchall()
        return [dict(r) for r in rows]

    def brain_summary(self, engagement_id: str) -> dict[str, Any]:
        """What was tried, what was killed, what is still open."""
        with self.db.connection() as conn:
            kinds = conn.execute(
                "SELECT kind, COUNT(*) AS n FROM brain_entries WHERE engagement_id=? GROUP BY kind",
                (engagement_id,),
            ).fetchall()
            loops = conn.execute(
                "SELECT status, COUNT(*) AS n FROM hunt_loops WHERE engagement_id=? GROUP BY status",
                (engagement_id,),
            ).fetchall()
            lessons = conn.execute(
                """SELECT content, role_id, created_at FROM brain_entries
                    WHERE engagement_id=? AND kind='lesson' ORDER BY created_at DESC LIMIT 10""",
                (engagement_id,),
            ).fetchall()
        return {
            "engagement_id": engagement_id,
            "entries_by_kind": {r["kind"]: r["n"] for r in kinds},
            "loops_by_status": {r["status"]: r["n"] for r in loops},
            "recent_lessons": [dict(r) for r in lessons],
            "note": (
                "The brain is append-only. 'killed' loops are dead ends worth reading before "
                "spending budget on the same idea."
            ),
        }

    # ------------------------------------------------------------------
    def roster(self, *, phases: list[str] | None = None) -> dict[str, Any]:
        roles = [r for r in AGENT_ROLES if not phases or r.phase in phases]
        return {
            "count": len(roles),
            "total_roles": len(AGENT_ROLES),
            "phases": sorted({r.phase for r in AGENT_ROLES}),
            "roles": [r.to_dict() for r in roles],
        }
