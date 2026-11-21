"""Persistence for the 2.3 offensive surface.

Kept separate from ``db.py`` so the original governance layer stays readable.
Every method takes an explicit ``Database`` and reuses its transaction helpers,
so the append-only audit chain and WAL behaviour are unchanged.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from typing import Any

from gateway.db import Database, utc_now_iso


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:20]}"


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


class OffensiveStore:
    """Typed accessors for policies, consent, BBP sync, chains and investigations."""

    def __init__(self, db: Database) -> None:
        self.db = db

    # ------------------------------------------------------------------
    # Policies
    # ------------------------------------------------------------------
    def upsert_policy(
        self,
        *,
        policy_id: str,
        policy_type: str,
        name: str,
        enabled: bool,
        consent_required: str,
        risk_level: str,
        two_person: bool,
        declaration: str,
        bounds: dict[str, Any],
        updated_by: str,
        overwrite: bool = True,
    ) -> dict[str, Any]:
        now = utc_now_iso()
        with self.db.transaction() as conn:
            existing = conn.execute(
                "SELECT policy_id FROM policies WHERE policy_id=?", (policy_id,)
            ).fetchone()
            if existing and not overwrite:
                return self.get_policy(policy_id) or {}
            conn.execute(
                """INSERT INTO policies (policy_id, policy_type, name, enabled, consent_required,
                       risk_level, two_person, declaration_json, updated_by, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(policy_id) DO UPDATE SET
                       name=excluded.name, enabled=excluded.enabled,
                       consent_required=excluded.consent_required,
                       risk_level=excluded.risk_level, two_person=excluded.two_person,
                       declaration_json=excluded.declaration_json,
                       updated_by=excluded.updated_by, updated_at=excluded.updated_at""",
                (
                    policy_id,
                    policy_type,
                    name,
                    int(enabled),
                    consent_required,
                    risk_level,
                    int(two_person),
                    _json({"declaration": declaration, "bounds": bounds}),
                    updated_by,
                    now,
                ),
            )
        return self.get_policy(policy_id) or {}

    def get_policy(self, policy_id: str) -> dict[str, Any] | None:
        with self.db.connection() as conn:
            row = conn.execute(
                "SELECT * FROM policies WHERE policy_id=?", (policy_id,)
            ).fetchone()
        return self._policy(row) if row else None

    def list_policies(self, policy_type: str | None = None) -> list[dict[str, Any]]:
        sql = "SELECT * FROM policies"
        args: list[Any] = []
        if policy_type:
            sql += " WHERE policy_type=?"
            args.append(policy_type)
        sql += " ORDER BY policy_id"
        with self.db.connection() as conn:
            rows = conn.execute(sql, args).fetchall()
        return [self._policy(r) for r in rows]

    @staticmethod
    def _policy(row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        payload = json.loads(item.pop("declaration_json") or "{}")
        item["declaration"] = payload.get("declaration", "")
        item["bounds"] = payload.get("bounds", {}) or {}
        item["enabled"] = bool(item["enabled"])
        item["two_person"] = bool(item["two_person"])
        return item

    def set_engagement_posture(self, engagement_id: str, posture_id: str, actor: str) -> None:
        with self.db.transaction() as conn:
            conn.execute(
                """INSERT INTO engagement_postures (engagement_id, posture_id, updated_by, updated_at)
                   VALUES (?, ?, ?, ?)
                   ON CONFLICT(engagement_id) DO UPDATE SET
                       posture_id=excluded.posture_id, updated_by=excluded.updated_by,
                       updated_at=excluded.updated_at""",
                (engagement_id, posture_id, actor, utc_now_iso()),
            )

    def get_engagement_posture(self, engagement_id: str) -> str | None:
        with self.db.connection() as conn:
            row = conn.execute(
                "SELECT posture_id FROM engagement_postures WHERE engagement_id=?",
                (engagement_id,),
            ).fetchone()
        return str(row["posture_id"]) if row else None

    # ------------------------------------------------------------------
    # Consent
    # ------------------------------------------------------------------
    def save_consent(
        self,
        *,
        consent_id: str,
        engagement_id: str | None,
        mission_id: str | None,
        operator_id: str,
        level: str,
        policy_id: str | None,
        declaration_sha256: str,
        statement: str,
        granted_at: str,
        expires_at: str,
    ) -> dict[str, Any]:
        with self.db.transaction() as conn:
            conn.execute(
                """INSERT INTO consent_records (consent_id, engagement_id, mission_id, operator_id,
                       level, policy_id, declaration_sha256, statement, granted_at, expires_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    consent_id,
                    engagement_id,
                    mission_id,
                    operator_id,
                    level,
                    policy_id,
                    declaration_sha256,
                    statement,
                    granted_at,
                    expires_at,
                ),
            )
        return self.get_consent(consent_id) or {}

    def get_consent(self, consent_id: str) -> dict[str, Any] | None:
        with self.db.connection() as conn:
            row = conn.execute(
                "SELECT * FROM consent_records WHERE consent_id=?", (consent_id,)
            ).fetchone()
        return dict(row) if row else None

    def list_consents(
        self,
        *,
        operator_id: str | None = None,
        engagement_id: str | None = None,
        include_expired: bool = False,
    ) -> list[dict[str, Any]]:
        clauses, args = [], []
        if operator_id:
            clauses.append("operator_id=?")
            args.append(operator_id)
        if engagement_id:
            # Engagement-scoped consent, plus global (NULL) consent.
            clauses.append("(engagement_id=? OR engagement_id IS NULL)")
            args.append(engagement_id)
        if not include_expired:
            clauses.append("expires_at > ?")
            args.append(utc_now_iso())
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with self.db.connection() as conn:
            rows = conn.execute(
                f"SELECT * FROM consent_records {where} ORDER BY granted_at DESC LIMIT 200",
                args,
            ).fetchall()
        return [dict(r) for r in rows]

    def revoke_consent(self, consent_id: str) -> dict[str, Any]:
        with self.db.transaction() as conn:
            conn.execute(
                "UPDATE consent_records SET revoked_at=? WHERE consent_id=? AND revoked_at IS NULL",
                (utc_now_iso(), consent_id),
            )
        return self.get_consent(consent_id) or {}

    # ------------------------------------------------------------------
    # Exploitation evidence
    # ------------------------------------------------------------------
    def save_exploit(
        self,
        *,
        engagement_id: str,
        mission_id: str | None,
        target: str,
        vulnerability: str,
        severity: str,
        requested_by: str,
        language: str,
        poc_body: str,
        poc_sha256: str,
        reproduction_steps: list[str],
        approval_id: str | None = None,
        approved_by: str | None = None,
        status: str = "drafted",
    ) -> dict[str, Any]:
        exploit_id = _new_id("exp")
        with self.db.transaction() as conn:
            conn.execute(
                """INSERT INTO exploitation_evidence
                   (exploit_id, engagement_id, mission_id, target, vulnerability, severity,
                    requested_by, approved_by, approval_id, language, poc_body, poc_sha256,
                    reproduction_steps_json, status, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    exploit_id,
                    engagement_id,
                    mission_id,
                    target,
                    vulnerability,
                    severity,
                    requested_by,
                    approved_by,
                    approval_id,
                    language,
                    poc_body,
                    poc_sha256,
                    _json(reproduction_steps),
                    status,
                    utc_now_iso(),
                ),
            )
        return self.get_exploit(exploit_id) or {}

    def get_exploit(self, exploit_id: str) -> dict[str, Any] | None:
        with self.db.connection() as conn:
            row = conn.execute(
                "SELECT * FROM exploitation_evidence WHERE exploit_id=?", (exploit_id,)
            ).fetchone()
        return self._exploit(row) if row else None

    def list_exploits(
        self,
        engagement_id: str,
        *,
        mission_id: str | None = None,
        status: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        clauses, args = ["engagement_id=?"], [engagement_id]
        if mission_id:
            clauses.append("mission_id=?")
            args.append(mission_id)
        if status:
            clauses.append("status=?")
            args.append(status)
        with self.db.connection() as conn:
            rows = conn.execute(
                f"SELECT * FROM exploitation_evidence WHERE {' AND '.join(clauses)} "
                "ORDER BY created_at DESC, exploit_id LIMIT ?",
                [*args, max(1, min(limit, 200))],
            ).fetchall()
        return [self._exploit(r) for r in rows]

    def mark_exploit_result(
        self,
        exploit_id: str,
        *,
        status: str,
        result: dict[str, Any],
        output_sha256: str | None = None,
    ) -> dict[str, Any]:
        with self.db.transaction() as conn:
            conn.execute(
                "UPDATE exploitation_evidence SET status=?, result_json=?, output_sha256=?, "
                "verified_at=? WHERE exploit_id=?",
                (
                    status,
                    _json(result),
                    output_sha256,
                    utc_now_iso() if status in {"verified", "unverified", "failed"} else None,
                    exploit_id,
                ),
            )
        return self.get_exploit(exploit_id) or {}

    @staticmethod
    def _exploit(row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        item["reproduction_steps"] = json.loads(item.pop("reproduction_steps_json") or "[]")
        item["result"] = json.loads(item.pop("result_json") or "{}")
        return item

    # ------------------------------------------------------------------
    # Attack chains
    # ------------------------------------------------------------------
    def save_chain(
        self,
        *,
        engagement_id: str,
        mission_id: str | None,
        requested_by: str,
        rationale: str,
        weakest_link: str,
        status: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        chain_id = _new_id("chn")
        with self.db.transaction() as conn:
            conn.execute(
                """INSERT INTO attack_chains (chain_id, engagement_id, mission_id, requested_by,
                       rationale, weakest_link, status, payload_json, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    chain_id,
                    engagement_id,
                    mission_id,
                    requested_by,
                    rationale,
                    weakest_link,
                    status,
                    _json(payload),
                    utc_now_iso(),
                ),
            )
        return self.get_chain(chain_id) or {}

    def get_chain(self, chain_id: str) -> dict[str, Any] | None:
        with self.db.connection() as conn:
            row = conn.execute(
                "SELECT * FROM attack_chains WHERE chain_id=?", (chain_id,)
            ).fetchone()
        return self._chain(row) if row else None

    def list_chains(self, engagement_id: str, limit: int = 30) -> list[dict[str, Any]]:
        with self.db.connection() as conn:
            rows = conn.execute(
                "SELECT * FROM attack_chains WHERE engagement_id=? "
                "ORDER BY created_at DESC, chain_id LIMIT ?",
                (engagement_id, max(1, min(limit, 100))),
            ).fetchall()
        return [self._chain(r) for r in rows]

    @staticmethod
    def _chain(row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        item["payload"] = json.loads(item.pop("payload_json") or "{}")
        return item

    # ------------------------------------------------------------------
    # Bug bounty programs
    # ------------------------------------------------------------------
    def upsert_program(
        self,
        *,
        engagement_id: str,
        platform: str,
        handle: str,
        display_name: str,
        scope: list[dict[str, Any]],
        source: str,
        created_by: str,
        sync_error: str = "",
    ) -> dict[str, Any]:
        program_id = _new_id("bbp")
        now = utc_now_iso()
        with self.db.transaction() as conn:
            existing = conn.execute(
                "SELECT program_id FROM bounty_programs "
                "WHERE engagement_id=? AND platform=? AND handle=?",
                (engagement_id, platform, handle),
            ).fetchone()
            if existing:
                program_id = str(existing["program_id"])
                conn.execute(
                    "UPDATE bounty_programs SET display_name=?, scope_json=?, source=?, "
                    "last_synced_at=?, sync_error=? WHERE program_id=?",
                    (
                        display_name,
                        _json(scope),
                        source,
                        now if source == "synced" else None,
                        sync_error[:500],
                        program_id,
                    ),
                )
            else:
                conn.execute(
                    """INSERT INTO bounty_programs (program_id, engagement_id, platform, handle,
                           display_name, scope_json, source, last_synced_at, sync_error,
                           created_by, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        program_id,
                        engagement_id,
                        platform,
                        handle,
                        display_name,
                        _json(scope),
                        source,
                        now if source == "synced" else None,
                        sync_error[:500],
                        created_by,
                        now,
                    ),
                )
        return self.get_program(program_id) or {}

    def get_program(self, program_id: str) -> dict[str, Any] | None:
        with self.db.connection() as conn:
            row = conn.execute(
                "SELECT * FROM bounty_programs WHERE program_id=?", (program_id,)
            ).fetchone()
        return self._program(row) if row else None

    def list_programs(self, engagement_id: str) -> list[dict[str, Any]]:
        with self.db.connection() as conn:
            rows = conn.execute(
                "SELECT * FROM bounty_programs WHERE engagement_id=? ORDER BY created_at DESC",
                (engagement_id,),
            ).fetchall()
        return [self._program(r) for r in rows]

    @staticmethod
    def _program(row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        item["scope"] = json.loads(item.pop("scope_json") or "[]")
        return item

    def save_duplicate_check(
        self,
        *,
        program_id: str,
        finding_key: str,
        endpoint: str,
        outcome: str,
        confidence: float,
        evidence: dict[str, Any],
        checked_by: str,
    ) -> dict[str, Any]:
        check_id = _new_id("dup")
        with self.db.transaction() as conn:
            conn.execute(
                """INSERT INTO bounty_duplicate_checks (check_id, program_id, finding_key,
                       endpoint, outcome, confidence, evidence_json, checked_by, checked_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    check_id,
                    program_id,
                    finding_key,
                    endpoint,
                    outcome,
                    float(confidence),
                    _json(evidence),
                    checked_by,
                    utc_now_iso(),
                ),
            )
        return self.get_duplicate_check(check_id) or {}

    def get_duplicate_check(self, check_id: str) -> dict[str, Any] | None:
        with self.db.connection() as conn:
            row = conn.execute(
                "SELECT * FROM bounty_duplicate_checks WHERE check_id=?", (check_id,)
            ).fetchone()
        if not row:
            return None
        item = dict(row)
        item["evidence"] = json.loads(item.pop("evidence_json") or "{}")
        return item

    def list_duplicate_checks(self, program_id: str, limit: int = 50) -> list[dict[str, Any]]:
        with self.db.connection() as conn:
            rows = conn.execute(
                "SELECT * FROM bounty_duplicate_checks WHERE program_id=? "
                "ORDER BY checked_at DESC LIMIT ?",
                (program_id, max(1, min(limit, 200))),
            ).fetchall()
        out = []
        for row in rows:
            item = dict(row)
            item["evidence"] = json.loads(item.pop("evidence_json") or "{}")
            out.append(item)
        return out

    def save_report(
        self,
        *,
        program_id: str | None,
        engagement_id: str,
        finding_key: str,
        title: str,
        severity: str,
        body_markdown: str,
        status: str,
        duplicate_check_id: str | None,
        created_by: str,
    ) -> dict[str, Any]:
        report_id = _new_id("rpt")
        with self.db.transaction() as conn:
            conn.execute(
                """INSERT INTO bounty_reports (report_id, program_id, engagement_id, finding_key,
                       title, severity, body_markdown, status, duplicate_check_id, created_by,
                       created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    report_id,
                    program_id,
                    engagement_id,
                    finding_key,
                    title,
                    severity,
                    body_markdown,
                    status,
                    duplicate_check_id,
                    created_by,
                    utc_now_iso(),
                ),
            )
        with self.db.connection() as conn:
            row = conn.execute(
                "SELECT * FROM bounty_reports WHERE report_id=?", (report_id,)
            ).fetchone()
        return dict(row) if row else {}

    def list_reports(self, engagement_id: str, limit: int = 50) -> list[dict[str, Any]]:
        with self.db.connection() as conn:
            rows = conn.execute(
                "SELECT * FROM bounty_reports WHERE engagement_id=? "
                "ORDER BY created_at DESC LIMIT ?",
                (engagement_id, max(1, min(limit, 200))),
            ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # pwntools jobs
    # ------------------------------------------------------------------
    def save_pwntools_job(
        self,
        *,
        engagement_id: str,
        mission_id: str | None,
        requested_by: str,
        target: str,
        action: str,
        script_body: str,
        script_sha256: str,
        status: str,
        output: str,
        output_sha256: str,
        pwntools_version: str,
    ) -> dict[str, Any]:
        job_id = _new_id("pwn")
        with self.db.transaction() as conn:
            conn.execute(
                """INSERT INTO pwntools_jobs (job_id, engagement_id, mission_id, requested_by,
                       target, action, script_body, script_sha256, status, output, output_sha256,
                       pwntools_version, created_at, finished_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    job_id,
                    engagement_id,
                    mission_id,
                    requested_by,
                    target,
                    action,
                    script_body,
                    script_sha256,
                    status,
                    output[:65536],
                    output_sha256,
                    pwntools_version,
                    utc_now_iso(),
                    utc_now_iso() if status not in {"pending", "running"} else None,
                ),
            )
        return self.get_pwntools_job(job_id) or {}

    def get_pwntools_job(self, job_id: str) -> dict[str, Any] | None:
        with self.db.connection() as conn:
            row = conn.execute(
                "SELECT * FROM pwntools_jobs WHERE job_id=?", (job_id,)
            ).fetchone()
        return dict(row) if row else None

    def list_pwntools_jobs(self, engagement_id: str, limit: int = 30) -> list[dict[str, Any]]:
        with self.db.connection() as conn:
            rows = conn.execute(
                "SELECT job_id, engagement_id, mission_id, requested_by, target, action, status, "
                "script_sha256, output_sha256, pwntools_version, created_at, finished_at "
                "FROM pwntools_jobs WHERE engagement_id=? ORDER BY created_at DESC LIMIT ?",
                (engagement_id, max(1, min(limit, 100))),
            ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Scan authorisations
    # ------------------------------------------------------------------
    def save_scan_authorization(
        self,
        *,
        engagement_id: str,
        mission_id: str | None,
        approval_id: str,
        granted_by: str,
        granted_to: str,
        max_hosts: int,
        max_requests: int,
        expires_at: str,
    ) -> dict[str, Any]:
        authorization_id = _new_id("scn")
        with self.db.transaction() as conn:
            conn.execute(
                """INSERT INTO scan_authorizations (authorization_id, engagement_id, mission_id,
                       approval_id, granted_by, granted_to, max_hosts, max_requests, expires_at,
                       created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    authorization_id,
                    engagement_id,
                    mission_id,
                    approval_id,
                    granted_by,
                    granted_to,
                    int(max_hosts),
                    int(max_requests),
                    expires_at,
                    utc_now_iso(),
                ),
            )
        return self.get_scan_authorization(authorization_id) or {}

    def get_scan_authorization(self, authorization_id: str) -> dict[str, Any] | None:
        with self.db.connection() as conn:
            row = conn.execute(
                "SELECT * FROM scan_authorizations WHERE authorization_id=?",
                (authorization_id,),
            ).fetchone()
        return dict(row) if row else None

    def live_scan_authorization(self, engagement_id: str) -> dict[str, Any] | None:
        with self.db.connection() as conn:
            row = conn.execute(
                "SELECT * FROM scan_authorizations WHERE engagement_id=? AND expires_at > ? "
                "AND requests_used < max_requests ORDER BY created_at DESC LIMIT 1",
                (engagement_id, utc_now_iso()),
            ).fetchone()
        return dict(row) if row else None

    def consume_scan_budget(self, authorization_id: str, requests: int) -> dict[str, Any]:
        with self.db.transaction() as conn:
            conn.execute(
                "UPDATE scan_authorizations SET requests_used = requests_used + ? "
                "WHERE authorization_id=? AND requests_used + ? <= max_requests",
                (int(requests), authorization_id, int(requests)),
            )
        return self.get_scan_authorization(authorization_id) or {}
