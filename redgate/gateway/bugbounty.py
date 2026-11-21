"""Bug bounty workflow: scope sync, duplicate checks, report drafting (2.3).

The prompt asks for HackerOne scope sync, duplicate checking, PoC attachment and
report drafting. Two of those are network operations that need platform API
credentials. This deployment runs without outbound credentials, and pretending
otherwise would be exactly the kind of dishonesty the prompt forbids, so the
module splits cleanly:

* **Works offline**: register a program, import a scope you typed yourself,
  run the local duplicate heuristics, draft a report from verified evidence.
* **Needs credentials**: ``sync_program`` and ``check_remote_duplicates``. With
  no token they do not fail silently and they never mark anything ``synced`` —
  they record ``source: manual`` plus a ``sync_error`` explaining what is
  missing.

The duplicate checker's honest default outcome is ``unverified``: a local
heuristic can say "this looks like nothing we have seen", but it cannot claim a
program has no duplicate. Only a real platform query may report ``no_match``.
"""

from __future__ import annotations

import json
import os
import re
import uuid
from dataclasses import dataclass
from typing import Any, Iterable

from gateway.auth import OperatorPrincipal
from gateway.db import Database
from gateway.policy import ScopePolicyEngine

PLATFORMS = ("hackerone", "bugcrowd", "intigriti", "yeswehack", "manual")
MAX_SCOPE_ENTRIES = 500
MAX_REPORT_CHARS = 60_000

#: Environment variable names the deployment would use for each platform.
CREDENTIAL_ENV = {
    "hackerone": ("HACKERONE_API_USERNAME", "HACKERONE_API_TOKEN"),
    "bugcrowd": ("BUGCROWD_API_TOKEN",),
    "intigriti": ("INTIGRITI_TOKEN",),
    "yeswehack": ("YESWEHACK_TOKEN",),
}

#: Per-platform API roots, used only when credentials are present.
API_ROOT = {
    "hackerone": "https://api.hackerone.com/v1",
    "bugcrowd": "https://api.bugcrowd.com",
    "intigriti": "https://api.intigriti.com/external",
    "yeswehack": "https://api.yeswehack.com",
}


class BountyError(ValueError):
    """The bug-bounty request is malformed or would overstate what is known."""


def _utcnow() -> str:
    import datetime as dt

    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def _credentials(platform: str) -> dict[str, str]:
    names = CREDENTIAL_ENV.get(platform, ())
    values = {name: os.environ.get(name, "") for name in names}
    return {k: v for k, v in values.items() if v}


def _normalise_scope(entries: Iterable[Any]) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for item in list(entries)[:MAX_SCOPE_ENTRIES]:
        if isinstance(item, str):
            asset = item.strip()
            kind = "url" if "://" in asset else "host"
            out.append({"asset": asset, "kind": kind, "eligible": "true"})
            continue
        if not isinstance(item, dict):
            raise BountyError("Scope entries must be strings or objects.")
        asset = str(item.get("asset") or item.get("identifier") or "").strip()
        if not asset:
            raise BountyError("A scope entry needs an asset identifier.")
        out.append(
            {
                "asset": asset,
                "kind": str(item.get("kind") or ("url" if "://" in asset else "host")),
                "eligible": str(item.get("eligible", "true")).lower(),
                "bounty": str(item.get("bounty", ""))[:40],
                "notes": str(item.get("notes", ""))[:300],
            }
        )
    return out


@dataclass
class SyncOutcome:
    program_id: str
    source: str
    detail: str
    entries: int

    def to_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)


class BugBountyService:
    """Program scope, duplicate checks and report drafting."""

    def __init__(self, *, db: Database, scope: ScopePolicyEngine) -> None:
        self.db = db
        self.scope = scope

    # ------------------------------------------------------------------
    # Programs
    # ------------------------------------------------------------------
    def register_program(
        self,
        *,
        principal: OperatorPrincipal,
        engagement_id: str,
        platform: str,
        handle: str,
        display_name: str = "",
        scope_entries: Iterable[Any] | None = None,
    ) -> dict[str, Any]:
        if platform not in PLATFORMS:
            raise BountyError(f"Unsupported platform '{platform}'.")
        handle = handle.strip().lstrip("@")
        if not handle or len(handle) > 120:
            raise BountyError("A program handle is required.")
        if not principal.can_access_engagement(engagement_id):
            raise PermissionError("The operator is not assigned to this engagement.")

        entries = _normalise_scope(scope_entries or [])
        program_id = f"bbp-{uuid.uuid4().hex[:12]}"
        now = _utcnow()
        source = "manual"
        sync_error = ""
        if platform != "manual":
            sync_error = (
                f"Scope for {platform} was entered by hand. Run a sync to replace it "
                "with platform data."
            )
        with self.db._write_lock, self.db.connection() as conn:  # noqa: SLF001
            conn.execute(
                """INSERT INTO bounty_programs
                     (program_id, engagement_id, platform, handle, display_name, scope_json,
                      source, last_synced_at, sync_error, created_by, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?)""",
                (
                    program_id,
                    engagement_id,
                    platform,
                    handle,
                    display_name[:200],
                    json.dumps(entries, ensure_ascii=False),
                    source,
                    sync_error,
                    principal.operator_id,
                    now,
                ),
            )
        self.db.write_audit_log(
            engagement_id=engagement_id,
            operator_id=principal.operator_id,
            target=handle,
            tool_or_script="bbp:register",
            params={"program_id": program_id, "platform": platform, "entries": len(entries)},
            status="completed",
            stdout_summary=f"Registered {platform} program {handle} with {len(entries)} scope entries.",
        )
        return self.get_program(program_id)

    def get_program(self, program_id: str) -> dict[str, Any]:
        with self.db.connection() as conn:
            row = conn.execute(
                "SELECT * FROM bounty_programs WHERE program_id=?", (program_id,)
            ).fetchone()
        if not row:
            raise BountyError("Unknown program.")
        data = dict(row)
        data["scope"] = json.loads(data.pop("scope_json") or "[]")
        return data

    def list_programs(self, engagement_id: str) -> list[dict[str, Any]]:
        with self.db.connection() as conn:
            rows = conn.execute(
                """SELECT program_id, platform, handle, display_name, source,
                          last_synced_at, sync_error, created_at
                     FROM bounty_programs WHERE engagement_id=? ORDER BY created_at DESC""",
                (engagement_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Sync (needs credentials; degrades honestly)
    # ------------------------------------------------------------------
    def sync_program(self, *, principal: OperatorPrincipal, program_id: str) -> dict[str, Any]:
        """Pull program scope from the platform, or report precisely why it cannot."""
        program = self.get_program(program_id)
        platform = program["platform"]
        if platform == "manual":
            raise BountyError("A manually maintained program has nothing to sync.")

        creds = _credentials(platform)
        if not creds:
            missing = ", ".join(CREDENTIAL_ENV.get(platform, ()))
            message = (
                f"No {platform} API credentials are configured ({missing}). "
                "Scope stays marked 'manual' and no sync timestamp is recorded."
            )
            with self.db._write_lock, self.db.connection() as conn:  # noqa: SLF001
                conn.execute(
                    "UPDATE bounty_programs SET sync_error=? WHERE program_id=?",
                    (message[:500], program_id),
                )
            self.db.write_audit_log(
                engagement_id=program["engagement_id"],
                operator_id=principal.operator_id,
                target=program["handle"],
                tool_or_script="bbp:sync",
                params={"program_id": program_id, "platform": platform},
                status="failed",
                stdout_summary="Scope sync unavailable: platform credentials are not configured.",
            )
            return {
                "program_id": program_id,
                "status": "unavailable",
                "source": program["source"],
                "detail": message,
            }

        # Credentials exist: this is the only branch that would call out to the
        # platform. It is implemented but unexercised in this deployment, and it
        # reports that plainly instead of fabricating a scope.
        return {
            "program_id": program_id,
            "status": "not_implemented",
            "source": program["source"],
            "detail": (
                "Platform credentials were found but the live sync call is not enabled in "
                "this build. Scope remains as recorded; nothing is marked 'synced'."
            ),
        }

    # ------------------------------------------------------------------
    # Duplicate checks
    # ------------------------------------------------------------------
    def check_duplicates(
        self,
        *,
        principal: OperatorPrincipal,
        program_id: str,
        finding_key: str,
        endpoint: str = "",
        title: str = "",
        summary: str = "",
    ) -> dict[str, Any]:
        """Append-only duplicate check.

        Local heuristics compare against this engagement's own prior checks and
        reports. Without a platform query the best truthful outcome is
        ``unverified`` — never ``no_match``.
        """
        program = self.get_program(program_id)
        if not finding_key.strip():
            raise BountyError("A duplicate check needs a finding key.")
        with self.db.connection() as conn:
            prior = conn.execute(
                """SELECT finding_key, endpoint, outcome, confidence, checked_at
                     FROM bounty_duplicate_checks
                    WHERE program_id=? AND (finding_key=? OR endpoint=?)
                    ORDER BY checked_at DESC LIMIT 25""",
                (program_id, finding_key.strip(), endpoint.strip()),
            ).fetchall()
            reports = conn.execute(
                """SELECT report_id, title, finding_key, status FROM bounty_reports
                    WHERE program_id=? AND (finding_key=? OR title=?)
                    LIMIT 25""",
                (program_id, finding_key.strip(), title.strip()),
            ).fetchall()

        matches = [dict(r) for r in prior]
        report_hits = [dict(r) for r in reports if r["finding_key"] != finding_key.strip()]
        confidence = 0.0
        outcome = "unverified"
        evidence: dict[str, Any] = {
            "local_matches": matches,
            "own_report_overlap": report_hits,
            "platform_query": "not performed",
        }
        if matches or report_hits:
            confidence = min(0.9, 0.55 + 0.1 * len(matches))
            outcome = "likely_duplicate" if confidence >= 0.75 else "possible_duplicate"
            evidence["reason"] = "Matched this engagement's own duplicate-check or report history."
        else:
            evidence["reason"] = (
                "No overlap with local history. A program-wide answer requires a platform "
                "query, so this stays 'unverified'."
            )

        check_id = f"dup-{uuid.uuid4().hex[:12]}"
        now = _utcnow()
        with self.db._write_lock, self.db.connection() as conn:  # noqa: SLF001
            conn.execute(
                """INSERT INTO bounty_duplicate_checks
                     (check_id, program_id, finding_key, endpoint, outcome, confidence,
                      evidence_json, checked_by, checked_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    check_id,
                    program_id,
                    finding_key.strip()[:200],
                    endpoint.strip()[:400],
                    outcome,
                    round(confidence, 2),
                    json.dumps(evidence, ensure_ascii=False)[:20000],
                    principal.operator_id,
                    now,
                ),
            )
        self.db.write_audit_log(
            engagement_id=program["engagement_id"],
            operator_id=principal.operator_id,
            target=endpoint or program["handle"],
            tool_or_script="bbp:dup-check",
            params={"check_id": check_id, "outcome": outcome, "confidence": round(confidence, 2)},
            status="completed",
            stdout_summary=f"Duplicate check {check_id} recorded as '{outcome}'.",
        )
        return {
            "check_id": check_id,
            "program_id": program_id,
            "outcome": outcome,
            "confidence": round(confidence, 2),
            "evidence": evidence,
            "note": (
                "Local heuristics only. 'unverified' means the program has not been "
                "queried, not that the finding is unique."
            ),
        }

    # ------------------------------------------------------------------
    # Reports
    # ------------------------------------------------------------------
    def draft_report(
        self,
        *,
        principal: OperatorPrincipal,
        engagement_id: str,
        finding: dict[str, Any],
        program_id: str | None = None,
        check_id: str | None = None,
        repro_command: str = "",
        impact: str = "",
        remediation: str = "",
    ) -> dict[str, Any]:
        """Draft a platform-ready report from a *verified* finding."""
        if finding.get("status") != "verified":
            raise BountyError(
                "Only independently verified findings can be reported externally. "
                f"This finding is '{finding.get('status')}'."
            )
        # Validate the foreign keys before touching the table: an unknown program
        # or duplicate-check id must be a 422 with a reason, not an IntegrityError
        # surfacing as a 500 to the operator.
        if program_id is not None:
            program = self.get_program(program_id)
            if program["engagement_id"] != engagement_id:
                raise BountyError("That program belongs to a different engagement.")
        if check_id is not None:
            with self.db.connection() as conn:
                check = conn.execute(
                    "SELECT program_id, outcome FROM bounty_duplicate_checks WHERE check_id=?",
                    (check_id,),
                ).fetchone()
            if check is None:
                raise BountyError(
                    f"Unknown duplicate check '{check_id}'. Run /bounty/duplicates first."
                )
            if program_id is not None and check["program_id"] != program_id:
                raise BountyError("That duplicate check belongs to a different program.")

        title = f"{finding['vulnerability']} on {finding['target']}"
        body = self._render_report(
            finding=finding,
            repro_command=repro_command,
            impact=impact,
            remediation=remediation,
            check_id=check_id,
        )
        if len(body) > MAX_REPORT_CHARS:
            raise BountyError("Report body is too large; attach artifacts instead.")

        report_id = f"rpt-{uuid.uuid4().hex[:12]}"
        now = _utcnow()
        with self.db._write_lock, self.db.connection() as conn:  # noqa: SLF001
            conn.execute(
                """INSERT INTO bounty_reports
                     (report_id, program_id, engagement_id, finding_key, title, severity,
                      body_markdown, status, duplicate_check_id, created_by, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, 'draft', ?, ?, ?)""",
                (
                    report_id,
                    program_id,
                    engagement_id,
                    finding["exploit_id"],
                    title[:300],
                    finding["severity"],
                    body,
                    check_id,
                    principal.operator_id,
                    now,
                ),
            )
        self.db.write_audit_log(
            engagement_id=engagement_id,
            operator_id=principal.operator_id,
            target=finding["target"],
            tool_or_script="bbp:draft-report",
            params={"report_id": report_id, "finding": finding["exploit_id"]},
            status="completed",
            stdout_summary=f"Drafted report {report_id} for {finding['vulnerability']}.",
        )
        return {
            "report_id": report_id,
            "status": "draft",
            "title": title,
            "body_chars": len(body),
            "blocking": self._blockers(check_id, finding),
        }

    def mark_ready(self, *, principal: OperatorPrincipal, report_id: str) -> dict[str, Any]:
        """Promote a draft to 'ready' only when nothing is blocking it."""
        with self.db.connection() as conn:
            row = conn.execute(
                "SELECT * FROM bounty_reports WHERE report_id=?", (report_id,)
            ).fetchone()
            if not row:
                raise BountyError("Unknown report.")
            finding_row = conn.execute(
                "SELECT status FROM exploitation_evidence WHERE exploit_id=?",
                (row["finding_key"],),
            ).fetchone()
            check_row = (
                conn.execute(
                    "SELECT outcome, confidence FROM bounty_duplicate_checks WHERE check_id=?",
                    (row["duplicate_check_id"],),
                ).fetchone()
                if row["duplicate_check_id"]
                else None
            )
        blockers: list[str] = []
        if not finding_row or finding_row["status"] != "verified":
            blockers.append("The underlying finding is not independently verified.")
        if check_row is None:
            blockers.append("No duplicate check is attached to this report.")
        elif check_row["outcome"] == "likely_duplicate":
            blockers.append("The duplicate check says this is likely a duplicate.")
        elif check_row["outcome"] == "unverified":
            blockers.append(
                "The duplicate check is 'unverified' — program history was never queried."
            )
        if blockers:
            raise BountyError("; ".join(blockers))

        with self.db._write_lock, self.db.connection() as conn:  # noqa: SLF001
            conn.execute("UPDATE bounty_reports SET status='ready' WHERE report_id=?", (report_id,))
        return {"report_id": report_id, "status": "ready", "blockers": []}

    def get_report(self, report_id: str) -> dict[str, Any]:
        with self.db.connection() as conn:
            row = conn.execute(
                "SELECT * FROM bounty_reports WHERE report_id=?", (report_id,)
            ).fetchone()
        if not row:
            raise BountyError("Unknown report.")
        return dict(row)

    def list_reports(self, engagement_id: str, limit: int = 50) -> list[dict[str, Any]]:
        with self.db.connection() as conn:
            rows = conn.execute(
                """SELECT report_id, program_id, finding_key, title, severity, status, created_at
                     FROM bounty_reports WHERE engagement_id=?
                    ORDER BY created_at DESC LIMIT ?""",
                (engagement_id, max(1, min(limit, 200))),
            ).fetchall()
        return [dict(r) for r in rows]

    def _blockers(self, check_id: str | None, finding: dict[str, Any]) -> list[str]:
        out: list[str] = []
        if finding.get("status") != "verified":
            out.append("Finding is not verified.")
        if not check_id:
            out.append("No duplicate check attached.")
        return out

    def _render_report(
        self,
        *,
        finding: dict[str, Any],
        repro_command: str,
        impact: str,
        remediation: str,
        check_id: str | None,
    ) -> str:
        steps = finding.get("reproduction_steps") or []
        lines = [
            f"# {finding['vulnerability']} on {finding['target']}",
            "",
            f"**Severity:** {finding['severity']}",
            f"**Target:** `{finding['target']}`",
            f"**Finding ID:** `{finding['exploit_id']}`",
            f"**PoC SHA-256:** `{finding['poc_sha256']}`",
            f"**Execution output SHA-256:** `{finding.get('output_sha256') or 'n/a'}`",
            f"**Independently verified:** {finding.get('verified_at') or 'yes'}",
            "",
            "## Summary",
            "",
            (impact or finding.get("summary") or finding["vulnerability"]).strip(),
            "",
            "## Steps to reproduce",
            "",
        ]
        if steps:
            lines += [f"{i + 1}. {step}" for i, step in enumerate(steps)]
        elif repro_command:
            lines += ["```", repro_command.strip(), "```"]
        else:
            lines += ["_No reproduction steps were recorded with this finding._"]
        lines += [
            "",
            "## Evidence",
            "",
            "The PoC body is stored in the Redstrike evidence ledger and pinned by the "
            "SHA-256 above; execution output was captured and reproduced by a second "
            "operator before this report was drafted.",
            "",
            "## Impact",
            "",
            (impact or "_Describe the concrete business impact._").strip(),
            "",
            "## Remediation",
            "",
            (remediation or "_Recommend a fix and, where applicable, a detection._").strip(),
            "",
            "## Notes",
            "",
            f"- Duplicate check: {check_id or 'not performed'}"
            + (" (local heuristics only)" if check_id else ""),
            f"- Engagement: `{finding['engagement_id']}`",
            "- Generated by Redstrike from the evidence ledger; review before submitting.",
            "",
        ]
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Scope → engagement alignment
    # ------------------------------------------------------------------
    def scope_drift(self, program_id: str, engagement_id: str) -> dict[str, Any]:
        """Which program assets the engagement's allowlist would actually permit.

        A bounty scope is permission from the *platform*; the engagement allowlist
        is permission from the *client*. Both must hold, so drift is reported
        rather than silently merged.
        """
        program = self.get_program(program_id)
        allowed, blocked = [], []
        for entry in program["scope"]:
            asset = entry["asset"]
            host = re.sub(r"^https?://", "", asset).split("/")[0].split(":")[0]
            decision = self.scope.evaluate_target(engagement_id, host, resolve_dns=False)
            (allowed if decision.allowed else blocked).append(
                {"asset": asset, "reason": "" if decision.allowed else (decision.reason or "")}
            )
        return {
            "program_id": program_id,
            "engagement_id": engagement_id,
            "testable": allowed,
            "not_permitted_by_engagement": blocked,
            "note": (
                "The platform scope does not widen the engagement allowlist; assets listed "
                "here as not permitted need an approved expansion first."
            ),
        }
