"""SQLite persistence layer with append-only triggers and SHA-256 audit hash chaining.

Designed for clean migration to PostgreSQL (standard SQL types, explicit foreign keys,
serialized append-only audit chain, and database-enforced two-person approval rule).
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

GENESIS_HASH = "0" * 64

SCHEMA_SQL = """
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
PRAGMA busy_timeout = 5000;

CREATE TABLE IF NOT EXISTS engagements (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    valid_from  TEXT NOT NULL,
    valid_until TEXT NOT NULL,
    active      INTEGER NOT NULL DEFAULT 1,
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS allowlist (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id TEXT NOT NULL REFERENCES engagements(id),
    target        TEXT NOT NULL,
    description   TEXT NOT NULL DEFAULT '',
    created_by    TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    active        INTEGER NOT NULL DEFAULT 1,
    UNIQUE(engagement_id, target)
);

CREATE TABLE IF NOT EXISTS tool_policy (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    tool_name           TEXT NOT NULL UNIQUE,
    enabled             INTEGER NOT NULL DEFAULT 0,
    max_timeout         INTEGER NOT NULL DEFAULT 30,
    allowed_params_json TEXT NOT NULL DEFAULT '{}',
    risk_level          TEXT NOT NULL DEFAULT 'high',
    requires_approval   INTEGER NOT NULL DEFAULT 1,
    description         TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS script_policy (
    id                       INTEGER PRIMARY KEY AUTOINCREMENT,
    language                 TEXT NOT NULL UNIQUE,
    enabled                  INTEGER NOT NULL DEFAULT 1,
    allowed_imports_json     TEXT NOT NULL DEFAULT '[]',
    forbidden_imports_json   TEXT NOT NULL DEFAULT '[]',
    forbidden_patterns_json  TEXT NOT NULL DEFAULT '[]',
    max_runtime_sec          INTEGER NOT NULL DEFAULT 15,
    network_egress_allowlist INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS validated_scripts (
    script_id            TEXT PRIMARY KEY,
    engagement_id        TEXT NOT NULL REFERENCES engagements(id),
    operator_id          TEXT NOT NULL,
    target               TEXT NOT NULL,
    language             TEXT NOT NULL,
    script_body          TEXT NOT NULL,
    sha256               TEXT NOT NULL,
    dependencies_json    TEXT NOT NULL DEFAULT '[]',
    expected_runtime_sec INTEGER NOT NULL DEFAULT 10,
    risk_level           TEXT NOT NULL DEFAULT 'low',
    risk_notes           TEXT NOT NULL DEFAULT '',
    validation_json      TEXT NOT NULL DEFAULT '{}',
    source               TEXT NOT NULL DEFAULT 'ai_generated',
    created_at           TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id    TEXT NOT NULL,
    operator_id      TEXT NOT NULL,
    target           TEXT NOT NULL,
    resolved_ips     TEXT NOT NULL DEFAULT '[]',
    tool_or_script   TEXT NOT NULL,
    language         TEXT,
    params           TEXT NOT NULL DEFAULT '{}',
    started_at       TEXT NOT NULL,
    finished_at      TEXT NOT NULL,
    duration_ms      INTEGER NOT NULL DEFAULT 0,
    exit_code        INTEGER,
    stdout_summary   TEXT NOT NULL DEFAULT '',
    status           TEXT NOT NULL,
    rejection_reason TEXT,
    prev_hash        TEXT NOT NULL,
    entry_hash       TEXT NOT NULL
);

-- Enforce strict append-only immutability on audit_log (Core Security Requirement).
CREATE TRIGGER IF NOT EXISTS trg_audit_log_no_update
BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'SECURITY_VIOLATION: audit_log is append-only; UPDATE is prohibited');
END;

CREATE TRIGGER IF NOT EXISTS trg_audit_log_no_delete
BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'SECURITY_VIOLATION: audit_log is append-only; DELETE is prohibited');
END;

CREATE INDEX IF NOT EXISTS idx_audit_operator ON audit_log(operator_id);
CREATE INDEX IF NOT EXISTS idx_audit_engagement ON audit_log(engagement_id);
CREATE INDEX IF NOT EXISTS idx_audit_status ON audit_log(status);
CREATE INDEX IF NOT EXISTS idx_audit_started ON audit_log(started_at DESC);

CREATE TABLE IF NOT EXISTS quota (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    operator_id TEXT NOT NULL,
    period      TEXT NOT NULL,
    period_key  TEXT NOT NULL,
    max_calls   INTEGER NOT NULL,
    used_calls  INTEGER NOT NULL DEFAULT 0,
    max_tokens  INTEGER NOT NULL,
    used_tokens INTEGER NOT NULL DEFAULT 0,
    updated_at  TEXT NOT NULL,
    UNIQUE(operator_id, period, period_key)
);

CREATE TABLE IF NOT EXISTS approval_queue (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id     TEXT NOT NULL UNIQUE,
    engagement_id  TEXT NOT NULL REFERENCES engagements(id),
    request_type   TEXT NOT NULL,
    target         TEXT NOT NULL,
    tool_or_script TEXT NOT NULL,
    payload_json   TEXT NOT NULL,
    requested_by   TEXT NOT NULL,
    requested_at   TEXT NOT NULL,
    approved_by    TEXT,
    approved_at    TEXT,
    decision_note  TEXT NOT NULL DEFAULT '',
    status         TEXT NOT NULL DEFAULT 'pending',
    executed_at    TEXT,
    -- Database-level Two-Person Rule: requester can never approve own request.
    CHECK (approved_by IS NULL OR approved_by != requested_by),
    CHECK (status IN ('pending', 'approved', 'rejected', 'executed', 'failed'))
);

-- ==========================================================================
-- Iteration 2: Personalized Local-AI Agent (Skills, Memory, Recon, Model Hub)
-- ==========================================================================

CREATE TABLE IF NOT EXISTS llm_runtime_config (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    active_provider TEXT NOT NULL DEFAULT 'mock',
    base_url        TEXT NOT NULL DEFAULT 'http://127.0.0.1:11434/v1',
    native_url      TEXT NOT NULL DEFAULT 'http://127.0.0.1:11434',
    active_model    TEXT NOT NULL DEFAULT 'qwen2.5-coder:14b',
    quantization    TEXT NOT NULL DEFAULT 'Q4_K_M',
    context_length  INTEGER NOT NULL DEFAULT 8192,
    updated_by      TEXT NOT NULL DEFAULT 'system',
    updated_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS agent_skills (
    skill_id    TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    version     TEXT NOT NULL DEFAULT '1.0',
    category    TEXT NOT NULL DEFAULT 'custom',
    description TEXT NOT NULL DEFAULT '',
    spec_json   TEXT NOT NULL,
    created_by  TEXT NOT NULL,
    enabled     INTEGER NOT NULL DEFAULT 1,
    is_builtin  INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS agent_memory (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    operator_id   TEXT NOT NULL,
    engagement_id TEXT,
    memory_type   TEXT NOT NULL,
    title         TEXT NOT NULL,
    content       TEXT NOT NULL,
    tags_json     TEXT NOT NULL DEFAULT '[]',
    pattern_key   TEXT,
    active        INTEGER NOT NULL DEFAULT 1,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    CHECK (memory_type IN ('methodology', 'preference', 'false_positive_rule', 'target_note', 'run_summary'))
);

CREATE INDEX IF NOT EXISTS idx_memory_operator ON agent_memory(operator_id, active);
CREATE INDEX IF NOT EXISTS idx_memory_engagement ON agent_memory(engagement_id);

CREATE TABLE IF NOT EXISTS recon_runs (
    run_id                 TEXT PRIMARY KEY,
    engagement_id          TEXT NOT NULL REFERENCES engagements(id),
    operator_id            TEXT NOT NULL,
    root_target            TEXT NOT NULL,
    skill_id               TEXT NOT NULL,
    llm_provider           TEXT NOT NULL,
    llm_model              TEXT NOT NULL,
    status                 TEXT NOT NULL,
    discovered_assets_json TEXT NOT NULL DEFAULT '[]',
    steps_json             TEXT NOT NULL DEFAULT '[]',
    memories_applied_json  TEXT NOT NULL DEFAULT '[]',
    queued_approvals_json  TEXT NOT NULL DEFAULT '[]',
    summary_stats_json     TEXT NOT NULL DEFAULT '{}',
    ai_synthesis           TEXT NOT NULL DEFAULT '',
    report_markdown        TEXT NOT NULL DEFAULT '',
    started_at             TEXT NOT NULL,
    finished_at            TEXT NOT NULL,
    duration_ms            INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS recon_findings (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id                  TEXT NOT NULL REFERENCES recon_runs(run_id),
    engagement_id           TEXT NOT NULL REFERENCES engagements(id),
    asset                   TEXT NOT NULL,
    category                TEXT NOT NULL,
    finding_key             TEXT NOT NULL,
    title                   TEXT NOT NULL,
    severity                TEXT NOT NULL,
    priority_score          INTEGER NOT NULL,
    ai_confidence           REAL NOT NULL,
    dual_verified           INTEGER NOT NULL DEFAULT 0,
    suppressed_by_memory    TEXT,
    evidence                TEXT NOT NULL DEFAULT '',
    remediation             TEXT NOT NULL DEFAULT '',
    requires_human_judgment INTEGER NOT NULL DEFAULT 1,
    human_judgment_reason   TEXT NOT NULL DEFAULT '',
    analyst_verdict         TEXT NOT NULL DEFAULT 'unreviewed',
    analyst_note            TEXT NOT NULL DEFAULT '',
    reviewed_by             TEXT,
    reviewed_at             TEXT,
    created_at              TEXT NOT NULL,
    CHECK (analyst_verdict IN ('unreviewed', 'confirmed', 'false_positive', 'accepted_risk', 'escalated'))
);

CREATE INDEX IF NOT EXISTS idx_findings_run ON recon_findings(run_id, priority_score DESC);
"""


def utc_now_iso() -> str:
    """Return current UTC timestamp in ISO-8601 format."""
    return dt.datetime.now(dt.timezone.utc).isoformat()


def current_period_key(period: str) -> str:
    """Compute quota bucket key (e.g., '2026-11-16' for daily, '2026-11' for monthly)."""
    now = dt.datetime.now(dt.timezone.utc)
    if period == "hourly":
        return now.strftime("%Y-%m-%dT%H")
    if period == "monthly":
        return now.strftime("%Y-%m")
    return now.strftime("%Y-%m-%d")


def _compute_audit_hash(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class Database:
    """Thread-safe SQLite repository enforcing append-only hash-chained audit logs."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._write_lock = threading.Lock()
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=10.0, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA busy_timeout = 5000;")
        return conn

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        conn = self._connect()
        try:
            yield conn
        finally:
            conn.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Serialize a short read-modify-write transaction across gateway subsystems."""
        with self._write_lock, self.connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                yield conn
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise

    def _init_schema(self) -> None:
        with self._write_lock, self.connection() as conn:
            conn.executescript(SCHEMA_SQL)
            conn.execute(
                "CREATE TABLE IF NOT EXISTS schema_migrations "
                "(name TEXT PRIMARY KEY, sha256 TEXT NOT NULL, applied_at TEXT NOT NULL)"
            )
            for path in sorted((Path(__file__).parent / "migrations").glob("*.sql")):
                script = path.read_text(encoding="utf-8")
                digest = hashlib.sha256(script.encode("utf-8")).hexdigest()
                row = conn.execute(
                    "SELECT sha256 FROM schema_migrations WHERE name = ?", (path.name,)
                ).fetchone()
                if row:
                    if row["sha256"] != digest:
                        raise RuntimeError(f"Applied migration was modified: {path.name}")
                    continue
                # executescript does not honor an outer Python transaction. Its
                # BEGIN/COMMIT must be inside the script, including the ledger row.
                name = path.name.replace("'", "''")
                try:
                    conn.executescript(
                        "BEGIN IMMEDIATE;\n" + script + "\n"
                        "INSERT INTO schema_migrations(name, sha256, applied_at) "
                        f"VALUES ('{name}', '{digest}', '{utc_now_iso()}');\nCOMMIT;"
                    )
                except BaseException:
                    if conn.in_transaction:
                        conn.execute("ROLLBACK")
                    raise

    # ------------------------------------------------------------------
    # Seeding & Policy Management
    # ------------------------------------------------------------------

    def upsert_engagement(
        self,
        engagement_id: str,
        name: str,
        description: str,
        valid_from: str,
        valid_until: str,
        active: bool = True,
    ) -> None:
        with self._write_lock, self.connection() as conn:
            conn.execute(
                """
                INSERT INTO engagements (id, name, description, valid_from, valid_until, active, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    name = excluded.name,
                    description = excluded.description,
                    valid_from = excluded.valid_from,
                    valid_until = excluded.valid_until,
                    active = excluded.active
                """,
                (engagement_id, name, description, valid_from, valid_until, int(active), utc_now_iso()),
            )

    def seed_allowlist_target(
        self,
        engagement_id: str,
        target: str,
        description: str,
        created_by: str,
        active: bool = True,
    ) -> int:
        with self._write_lock, self.connection() as conn:
            conn.execute(
                """
                INSERT INTO allowlist (engagement_id, target, description, created_by, created_at, active)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(engagement_id, target) DO NOTHING
                """,
                (engagement_id, target.strip(), description, created_by, utc_now_iso(), int(active)),
            )
            row = conn.execute(
                "SELECT id FROM allowlist WHERE engagement_id = ? AND target = ?",
                (engagement_id, target.strip()),
            ).fetchone()
            return int(row["id"])

    def add_allowlist_target(
        self, engagement_id: str, target: str, description: str, created_by: str
    ) -> dict[str, Any]:
        now = utc_now_iso()
        clean = target.strip()
        with self._write_lock, self.connection() as conn:
            conn.execute(
                """
                INSERT INTO allowlist (engagement_id, target, description, created_by, created_at, active)
                VALUES (?, ?, ?, ?, ?, 1)
                ON CONFLICT(engagement_id, target) DO UPDATE SET
                    description = excluded.description,
                    active = 1
                """,
                (engagement_id, clean, description, created_by, now),
            )
            row = conn.execute(
                "SELECT * FROM allowlist WHERE engagement_id = ? AND target = ?",
                (engagement_id, clean),
            ).fetchone()
            return dict(row)

    def set_allowlist_active(self, entry_id: int, active: bool) -> dict[str, Any] | None:
        with self._write_lock, self.connection() as conn:
            conn.execute("UPDATE allowlist SET active = ? WHERE id = ?", (int(active), entry_id))
            row = conn.execute("SELECT * FROM allowlist WHERE id = ?", (entry_id,)).fetchone()
            return dict(row) if row else None

    def get_engagement(self, engagement_id: str) -> dict[str, Any] | None:
        with self.connection() as conn:
            row = conn.execute("SELECT * FROM engagements WHERE id = ?", (engagement_id,)).fetchone()
            return dict(row) if row else None

    def list_engagements(self) -> list[dict[str, Any]]:
        with self.connection() as conn:
            rows = conn.execute("SELECT * FROM engagements ORDER BY id ASC").fetchall()
            return [dict(r) for r in rows]

    def list_allowlist(
        self, engagement_id: str | None = None, active_only: bool = False
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        args: list[Any] = []
        if engagement_id:
            clauses.append("engagement_id = ?")
            args.append(engagement_id)
        if active_only:
            clauses.append("active = 1")
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with self.connection() as conn:
            rows = conn.execute(
                f"SELECT * FROM allowlist {where} ORDER BY engagement_id ASC, id ASC", args
            ).fetchall()
            return [dict(r) for r in rows]

    def upsert_tool_policy(
        self,
        tool_name: str,
        enabled: bool,
        max_timeout: int,
        allowed_params: dict[str, Any],
        risk_level: str,
        requires_approval: bool,
        description: str = "",
    ) -> None:
        with self._write_lock, self.connection() as conn:
            conn.execute(
                """
                INSERT INTO tool_policy
                    (tool_name, enabled, max_timeout, allowed_params_json, risk_level, requires_approval, description)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(tool_name) DO UPDATE SET
                    enabled = excluded.enabled,
                    max_timeout = excluded.max_timeout,
                    allowed_params_json = excluded.allowed_params_json,
                    risk_level = excluded.risk_level,
                    requires_approval = excluded.requires_approval,
                    description = excluded.description
                """,
                (
                    tool_name,
                    int(enabled),
                    max_timeout,
                    json.dumps(allowed_params),
                    risk_level,
                    int(requires_approval),
                    description,
                ),
            )

    def get_tool_policy(self, tool_name: str) -> dict[str, Any] | None:
        with self.connection() as conn:
            row = conn.execute(
                "SELECT * FROM tool_policy WHERE tool_name = ?", (tool_name,)
            ).fetchone()
            if not row:
                return None
            item = dict(row)
            item["enabled"] = bool(item["enabled"])
            item["requires_approval"] = bool(item["requires_approval"])
            item["allowed_params"] = json.loads(item["allowed_params_json"])
            return item

    def list_tool_policies(self) -> list[dict[str, Any]]:
        with self.connection() as conn:
            rows = conn.execute("SELECT * FROM tool_policy ORDER BY id ASC").fetchall()
            out: list[dict[str, Any]] = []
            for row in rows:
                item = dict(row)
                item["enabled"] = bool(item["enabled"])
                item["requires_approval"] = bool(item["requires_approval"])
                item["allowed_params"] = json.loads(item["allowed_params_json"])
                out.append(item)
            return out

    def update_tool_policy(
        self,
        tool_name: str,
        enabled: bool | None = None,
        requires_approval: bool | None = None,
        max_timeout: int | None = None,
    ) -> dict[str, Any] | None:
        current = self.get_tool_policy(tool_name)
        if not current:
            return None
        new_enabled = current["enabled"] if enabled is None else enabled
        # Critical/high-risk tools always require approval even if admin toggles enabled=True.
        if current["risk_level"] in {"high", "critical"}:
            new_approval = True
        else:
            new_approval = current["requires_approval"] if requires_approval is None else requires_approval
        new_timeout = current["max_timeout"] if max_timeout is None else max_timeout

        with self._write_lock, self.connection() as conn:
            conn.execute(
                """
                UPDATE tool_policy
                SET enabled = ?, requires_approval = ?, max_timeout = ?
                WHERE tool_name = ?
                """,
                (int(new_enabled), int(new_approval), int(new_timeout), tool_name),
            )
        return self.get_tool_policy(tool_name)

    def upsert_script_policy(
        self,
        language: str,
        enabled: bool,
        allowed_imports: list[str],
        forbidden_imports: list[str],
        forbidden_patterns: list[str],
        max_runtime_sec: int,
        network_egress_allowlist: bool,
    ) -> None:
        with self._write_lock, self.connection() as conn:
            conn.execute(
                """
                INSERT INTO script_policy
                    (language, enabled, allowed_imports_json, forbidden_imports_json,
                     forbidden_patterns_json, max_runtime_sec, network_egress_allowlist)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(language) DO UPDATE SET
                    enabled = excluded.enabled,
                    allowed_imports_json = excluded.allowed_imports_json,
                    forbidden_imports_json = excluded.forbidden_imports_json,
                    forbidden_patterns_json = excluded.forbidden_patterns_json,
                    max_runtime_sec = excluded.max_runtime_sec,
                    network_egress_allowlist = excluded.network_egress_allowlist
                """,
                (
                    language,
                    int(enabled),
                    json.dumps(allowed_imports),
                    json.dumps(forbidden_imports),
                    json.dumps(forbidden_patterns),
                    max_runtime_sec,
                    int(network_egress_allowlist),
                ),
            )

    def get_script_policy(self, language: str) -> dict[str, Any] | None:
        with self.connection() as conn:
            row = conn.execute(
                "SELECT * FROM script_policy WHERE language = ?", (language,)
            ).fetchone()
            if not row:
                return None
            return self._hydrate_script_policy(row)

    def list_script_policies(self) -> list[dict[str, Any]]:
        with self.connection() as conn:
            rows = conn.execute("SELECT * FROM script_policy ORDER BY id ASC").fetchall()
            return [self._hydrate_script_policy(r) for r in rows]

    @staticmethod
    def _hydrate_script_policy(row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        item["enabled"] = bool(item["enabled"])
        item["network_egress_allowlist"] = bool(item["network_egress_allowlist"])
        item["allowed_imports"] = json.loads(item["allowed_imports_json"])
        item["forbidden_imports"] = json.loads(item["forbidden_imports_json"])
        item["forbidden_patterns"] = json.loads(item["forbidden_patterns_json"])
        return item

    # ------------------------------------------------------------------
    # Validated Script Registry (prevents TOCTOU tampering before /run)
    # ------------------------------------------------------------------

    def save_validated_script(
        self,
        engagement_id: str,
        operator_id: str,
        target: str,
        language: str,
        script_body: str,
        sha256: str,
        dependencies: list[str],
        expected_runtime_sec: int,
        risk_level: str,
        risk_notes: str,
        validation_dict: dict[str, Any],
        source: str = "ai_generated",
    ) -> dict[str, Any]:
        script_id = f"scr-{uuid.uuid4().hex[:12]}"
        now = utc_now_iso()
        with self._write_lock, self.connection() as conn:
            conn.execute(
                """
                INSERT INTO validated_scripts
                    (script_id, engagement_id, operator_id, target, language, script_body,
                     sha256, dependencies_json, expected_runtime_sec, risk_level, risk_notes,
                     validation_json, source, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    script_id,
                    engagement_id,
                    operator_id,
                    target,
                    language,
                    script_body,
                    sha256,
                    json.dumps(dependencies),
                    expected_runtime_sec,
                    risk_level,
                    risk_notes,
                    json.dumps(validation_dict),
                    source,
                    now,
                ),
            )
        return self.get_validated_script(script_id) or {}

    def get_validated_script(self, script_id: str) -> dict[str, Any] | None:
        with self.connection() as conn:
            row = conn.execute(
                "SELECT * FROM validated_scripts WHERE script_id = ?", (script_id,)
            ).fetchone()
            if not row:
                return None
            item = dict(row)
            item["dependencies"] = json.loads(item["dependencies_json"])
            item["validation"] = json.loads(item["validation_json"])
            return item

    def list_validated_scripts(self, limit: int = 25) -> list[dict[str, Any]]:
        with self.connection() as conn:
            rows = conn.execute(
                """
                SELECT script_id, engagement_id, operator_id, target, language, sha256,
                       expected_runtime_sec, risk_level, risk_notes, source, created_at
                FROM validated_scripts
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (max(1, min(limit, 100)),),
            ).fetchall()
            return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Quota Accounting (Atomic Call + LLM Token Budgeting)
    # ------------------------------------------------------------------

    def get_or_init_quota(
        self, operator_id: str, period: str, max_calls: int, max_tokens: int
    ) -> dict[str, Any]:
        pkey = current_period_key(period)
        with self._write_lock, self.connection() as conn:
            conn.execute(
                """
                INSERT INTO quota
                    (operator_id, period, period_key, max_calls, used_calls, max_tokens, used_tokens, updated_at)
                VALUES (?, ?, ?, ?, 0, ?, 0, ?)
                ON CONFLICT(operator_id, period, period_key) DO NOTHING
                """,
                (operator_id, period, pkey, max_calls, max_tokens, utc_now_iso()),
            )
            row = conn.execute(
                "SELECT * FROM quota WHERE operator_id = ? AND period = ? AND period_key = ?",
                (operator_id, period, pkey),
            ).fetchone()
            return dict(row)

    def check_and_consume_quota(
        self,
        operator_id: str,
        period: str,
        max_calls: int,
        max_tokens: int,
        calls_delta: int = 1,
        estimated_tokens: int = 0,
    ) -> tuple[bool, str, dict[str, Any]]:
        """Atomically verify remaining budget and reserve calls/tokens."""
        pkey = current_period_key(period)
        now = utc_now_iso()
        with self._write_lock, self.connection() as conn:
            conn.execute("BEGIN IMMEDIATE;")
            try:
                conn.execute(
                    """
                    INSERT INTO quota
                        (operator_id, period, period_key, max_calls, used_calls, max_tokens, used_tokens, updated_at)
                    VALUES (?, ?, ?, ?, 0, ?, 0, ?)
                    ON CONFLICT(operator_id, period, period_key) DO NOTHING
                    """,
                    (operator_id, period, pkey, max_calls, max_tokens, now),
                )
                row = conn.execute(
                    "SELECT * FROM quota WHERE operator_id = ? AND period = ? AND period_key = ?",
                    (operator_id, period, pkey),
                ).fetchone()
                q = dict(row)
                if q["used_calls"] + calls_delta > q["max_calls"]:
                    conn.execute("COMMIT;")
                    return (
                        False,
                        f"Call quota exhausted ({q['used_calls']}/{q['max_calls']} for {period} {pkey}).",
                        q,
                    )
                if estimated_tokens > 0 and q["used_tokens"] + estimated_tokens > q["max_tokens"]:
                    conn.execute("COMMIT;")
                    return (
                        False,
                        f"LLM token quota exhausted ({q['used_tokens']}/{q['max_tokens']} for {period} {pkey}).",
                        q,
                    )
                conn.execute(
                    """
                    UPDATE quota
                    SET used_calls = used_calls + ?, used_tokens = used_tokens + ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (calls_delta, estimated_tokens, now, q["id"]),
                )
                updated = conn.execute("SELECT * FROM quota WHERE id = ?", (q["id"],)).fetchone()
                conn.execute("COMMIT;")
                return True, "ok", dict(updated)
            except Exception:
                conn.execute("ROLLBACK;")
                raise

    def record_llm_tokens(self, operator_id: str, period: str, actual_tokens: int) -> None:
        """Record actual completion + prompt tokens reported by the LLM gateway."""
        if actual_tokens <= 0:
            return
        pkey = current_period_key(period)
        with self._write_lock, self.connection() as conn:
            conn.execute(
                """
                UPDATE quota
                SET used_tokens = MIN(max_tokens, used_tokens + ?), updated_at = ?
                WHERE operator_id = ? AND period = ? AND period_key = ?
                """,
                (actual_tokens, utc_now_iso(), operator_id, period, pkey),
            )

    def list_all_quotas(self) -> list[dict[str, Any]]:
        with self.connection() as conn:
            rows = conn.execute(
                "SELECT * FROM quota ORDER BY period_key DESC, operator_id ASC"
            ).fetchall()
            return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Approval Queue (Two-Person Rule)
    # ------------------------------------------------------------------

    def enqueue_approval(
        self,
        engagement_id: str,
        request_type: str,
        target: str,
        tool_or_script: str,
        payload: dict[str, Any],
        requested_by: str,
    ) -> dict[str, Any]:
        request_id = f"apr-{uuid.uuid4().hex[:12]}"
        now = utc_now_iso()
        with self._write_lock, self.connection() as conn:
            conn.execute(
                """
                INSERT INTO approval_queue
                    (request_id, engagement_id, request_type, target, tool_or_script,
                     payload_json, requested_by, requested_at, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending')
                """,
                (
                    request_id,
                    engagement_id,
                    request_type,
                    target,
                    tool_or_script,
                    json.dumps(payload),
                    requested_by,
                    now,
                ),
            )
            row = conn.execute(
                "SELECT * FROM approval_queue WHERE request_id = ?", (request_id,)
            ).fetchone()
            return self._hydrate_approval(row)

    def get_approval(self, request_id: str) -> dict[str, Any] | None:
        with self.connection() as conn:
            row = conn.execute(
                "SELECT * FROM approval_queue WHERE request_id = ?", (request_id,)
            ).fetchone()
            return self._hydrate_approval(row) if row else None

    def list_approvals(self, status: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
        with self.connection() as conn:
            if status:
                rows = conn.execute(
                    "SELECT * FROM approval_queue WHERE status = ? ORDER BY id DESC LIMIT ?",
                    (status, max(1, min(limit, 200))),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM approval_queue ORDER BY id DESC LIMIT ?",
                    (max(1, min(limit, 200)),),
                ).fetchall()
            return [self._hydrate_approval(r) for r in rows]

    def decide_approval(
        self,
        request_id: str,
        approved_by: str,
        decision: str,
        note: str = "",
    ) -> dict[str, Any]:
        if decision not in {"approved", "rejected"}:
            raise ValueError("Decision must be 'approved' or 'rejected'.")
        now = utc_now_iso()
        with self._write_lock, self.connection() as conn:
            row = conn.execute(
                "SELECT * FROM approval_queue WHERE request_id = ?", (request_id,)
            ).fetchone()
            if not row:
                raise LookupError(f"Approval request '{request_id}' not found.")
            if row["status"] != "pending":
                raise ValueError(
                    f"Approval request '{request_id}' is already finalized ({row['status']})."
                )
            if row["requested_by"] == approved_by:
                raise PermissionError(
                    "Two-Person Rule violation: requester cannot approve or reject their own request."
                )
            conn.execute(
                """
                UPDATE approval_queue
                SET approved_by = ?, approved_at = ?, decision_note = ?, status = ?
                WHERE request_id = ?
                """,
                (approved_by, now, note, decision, request_id),
            )
            updated = conn.execute(
                "SELECT * FROM approval_queue WHERE request_id = ?", (request_id,)
            ).fetchone()
            return self._hydrate_approval(updated)

    def mark_approval_executed(self, request_id: str, succeeded: bool) -> None:
        new_status = "executed" if succeeded else "failed"
        with self._write_lock, self.connection() as conn:
            conn.execute(
                "UPDATE approval_queue SET status = ?, executed_at = ? WHERE request_id = ?",
                (new_status, utc_now_iso(), request_id),
            )

    @staticmethod
    def _hydrate_approval(row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        item["payload"] = json.loads(item["payload_json"])
        return item

    # ------------------------------------------------------------------
    # Append-Only, SHA-256 Hash-Chained Audit Log
    # ------------------------------------------------------------------

    def write_audit_log(
        self,
        *,
        engagement_id: str,
        operator_id: str,
        target: str,
        tool_or_script: str,
        status: str,
        language: str | None = None,
        params: dict[str, Any] | None = None,
        resolved_ips: list[str] | None = None,
        started_at: str | None = None,
        finished_at: str | None = None,
        duration_ms: int = 0,
        exit_code: int | None = None,
        stdout_summary: str = "",
        rejection_reason: str | None = None,
    ) -> dict[str, Any]:
        """Append an immutable, cryptographically chained record to audit_log."""
        s_at = started_at or utc_now_iso()
        f_at = finished_at or utc_now_iso()
        params_str = json.dumps(params or {}, sort_keys=True)
        ips_str = json.dumps(resolved_ips or [])
        bounded_stdout = stdout_summary[:4096]

        with self._write_lock, self.connection() as conn:
            conn.execute("BEGIN IMMEDIATE;")
            try:
                last = conn.execute(
                    "SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1"
                ).fetchone()
                prev_hash = str(last["entry_hash"]) if last else GENESIS_HASH

                hash_material = {
                    "engagement_id": engagement_id,
                    "operator_id": operator_id,
                    "target": target,
                    "resolved_ips": ips_str,
                    "tool_or_script": tool_or_script,
                    "language": language,
                    "params": params_str,
                    "started_at": s_at,
                    "finished_at": f_at,
                    "duration_ms": int(duration_ms),
                    "exit_code": exit_code,
                    "stdout_summary": bounded_stdout,
                    "status": status,
                    "rejection_reason": rejection_reason,
                    "prev_hash": prev_hash,
                }
                entry_hash = _compute_audit_hash(hash_material)

                cur = conn.execute(
                    """
                    INSERT INTO audit_log
                        (engagement_id, operator_id, target, resolved_ips, tool_or_script,
                         language, params, started_at, finished_at, duration_ms, exit_code,
                         stdout_summary, status, rejection_reason, prev_hash, entry_hash)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        engagement_id,
                        operator_id,
                        target,
                        ips_str,
                        tool_or_script,
                        language,
                        params_str,
                        s_at,
                        f_at,
                        int(duration_ms),
                        exit_code,
                        bounded_stdout,
                        status,
                        rejection_reason,
                        prev_hash,
                        entry_hash,
                    ),
                )
                row_id = cur.lastrowid
                row = conn.execute("SELECT * FROM audit_log WHERE id = ?", (row_id,)).fetchone()
                conn.execute("COMMIT;")
                return dict(row)
            except Exception:
                conn.execute("ROLLBACK;")
                raise

    def query_audit_log(
        self,
        *,
        engagement_id: str | None = None,
        operator_id: str | None = None,
        status: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        args: list[Any] = []
        if engagement_id:
            clauses.append("engagement_id = ?")
            args.append(engagement_id)
        if operator_id:
            clauses.append("operator_id = ?")
            args.append(operator_id)
        if status:
            clauses.append("status = ?")
            args.append(status)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        args.extend([max(1, min(limit, 500)), max(0, offset)])

        with self.connection() as conn:
            rows = conn.execute(
                f"SELECT * FROM audit_log {where} ORDER BY id DESC LIMIT ? OFFSET ?", args
            ).fetchall()
            return [dict(r) for r in rows]

    def verify_audit_chain(self) -> dict[str, Any]:
        """Recompute every audit_log SHA-256 link from genesis to detect tampering."""
        with self.connection() as conn:
            rows = conn.execute("SELECT * FROM audit_log ORDER BY id ASC").fetchall()

        expected_prev = GENESIS_HASH
        for row in rows:
            if row["prev_hash"] != expected_prev:
                return {
                    "valid": False,
                    "checked_entries": int(row["id"]),
                    "broken_at_id": int(row["id"]),
                    "reason": "prev_hash linkage mismatch",
                }
            recomputed = _compute_audit_hash(
                {
                    "engagement_id": row["engagement_id"],
                    "operator_id": row["operator_id"],
                    "target": row["target"],
                    "resolved_ips": row["resolved_ips"],
                    "tool_or_script": row["tool_or_script"],
                    "language": row["language"],
                    "params": row["params"],
                    "started_at": row["started_at"],
                    "finished_at": row["finished_at"],
                    "duration_ms": int(row["duration_ms"]),
                    "exit_code": row["exit_code"],
                    "stdout_summary": row["stdout_summary"],
                    "status": row["status"],
                    "rejection_reason": row["rejection_reason"],
                    "prev_hash": row["prev_hash"],
                }
            )
            if recomputed != row["entry_hash"]:
                return {
                    "valid": False,
                    "checked_entries": int(row["id"]),
                    "broken_at_id": int(row["id"]),
                    "reason": "entry_hash digest mismatch",
                }
            expected_prev = row["entry_hash"]

        return {
            "valid": True,
            "checked_entries": len(rows),
            "head_hash": expected_prev,
            "append_only_triggers": ["trg_audit_log_no_update", "trg_audit_log_no_delete"],
        }

    # ------------------------------------------------------------------
    # Local LLM Runtime Config (Ollama / LM Studio / OpenAI-Compat / Mock)
    # ------------------------------------------------------------------

    def get_or_init_llm_runtime(
        self,
        default_provider: str = "mock",
        default_base_url: str = "http://127.0.0.1:11434/v1",
        default_native_url: str = "http://127.0.0.1:11434",
        default_model: str = "qwen2.5-coder:14b",
        default_quant: str = "Q4_K_M",
    ) -> dict[str, Any]:
        with self._write_lock, self.connection() as conn:
            conn.execute(
                """
                INSERT INTO llm_runtime_config
                    (id, active_provider, base_url, native_url, active_model, quantization, context_length, updated_by, updated_at)
                VALUES (1, ?, ?, ?, ?, ?, 8192, 'config-seed', ?)
                ON CONFLICT(id) DO NOTHING
                """,
                (
                    default_provider,
                    default_base_url,
                    default_native_url,
                    default_model,
                    default_quant,
                    utc_now_iso(),
                ),
            )
            row = conn.execute("SELECT * FROM llm_runtime_config WHERE id = 1").fetchone()
            return dict(row)

    def update_llm_runtime(
        self,
        *,
        active_provider: str,
        base_url: str,
        native_url: str,
        active_model: str,
        quantization: str,
        context_length: int,
        updated_by: str,
    ) -> dict[str, Any]:
        now = utc_now_iso()
        with self._write_lock, self.connection() as conn:
            conn.execute(
                """
                INSERT INTO llm_runtime_config
                    (id, active_provider, base_url, native_url, active_model, quantization, context_length, updated_by, updated_at)
                VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    active_provider = excluded.active_provider,
                    base_url = excluded.base_url,
                    native_url = excluded.native_url,
                    active_model = excluded.active_model,
                    quantization = excluded.quantization,
                    context_length = excluded.context_length,
                    updated_by = excluded.updated_by,
                    updated_at = excluded.updated_at
                """,
                (
                    active_provider,
                    base_url,
                    native_url,
                    active_model,
                    quantization,
                    context_length,
                    updated_by,
                    now,
                ),
            )
            row = conn.execute("SELECT * FROM llm_runtime_config WHERE id = 1").fetchone()
            return dict(row)

    # ------------------------------------------------------------------
    # Agent Skills Repository
    # ------------------------------------------------------------------

    def upsert_skill(
        self,
        *,
        skill_id: str,
        name: str,
        version: str,
        category: str,
        description: str,
        spec: dict[str, Any],
        created_by: str,
        enabled: bool = True,
        is_builtin: bool = False,
    ) -> dict[str, Any]:
        now = utc_now_iso()
        with self._write_lock, self.connection() as conn:
            conn.execute(
                """
                INSERT INTO agent_skills
                    (skill_id, name, version, category, description, spec_json,
                     created_by, enabled, is_builtin, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(skill_id) DO UPDATE SET
                    name = excluded.name,
                    version = excluded.version,
                    category = excluded.category,
                    description = excluded.description,
                    spec_json = excluded.spec_json,
                    enabled = excluded.enabled,
                    updated_at = excluded.updated_at
                """,
                (
                    skill_id,
                    name,
                    version,
                    category,
                    description,
                    json.dumps(spec),
                    created_by,
                    int(enabled),
                    int(is_builtin),
                    now,
                    now,
                ),
            )
        return self.get_skill(skill_id) or {}

    def get_skill(self, skill_id: str) -> dict[str, Any] | None:
        with self.connection() as conn:
            row = conn.execute(
                "SELECT * FROM agent_skills WHERE skill_id = ?", (skill_id,)
            ).fetchone()
            return self._hydrate_skill(row) if row else None

    def list_skills(self, enabled_only: bool = False) -> list[dict[str, Any]]:
        where = "WHERE enabled = 1" if enabled_only else ""
        with self.connection() as conn:
            rows = conn.execute(
                f"SELECT * FROM agent_skills {where} ORDER BY is_builtin DESC, skill_id ASC"
            ).fetchall()
            return [self._hydrate_skill(r) for r in rows]

    @staticmethod
    def _hydrate_skill(row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        item["enabled"] = bool(item["enabled"])
        item["is_builtin"] = bool(item["is_builtin"])
        item["spec"] = json.loads(item["spec_json"])
        return item

    # ------------------------------------------------------------------
    # Persistent Operator & Engagement Memory Repository
    # ------------------------------------------------------------------

    def add_memory(
        self,
        *,
        operator_id: str,
        engagement_id: str | None,
        memory_type: str,
        title: str,
        content: str,
        tags: list[str],
        pattern_key: str | None = None,
    ) -> dict[str, Any]:
        now = utc_now_iso()
        with self._write_lock, self.connection() as conn:
            cur = conn.execute(
                """
                INSERT INTO agent_memory
                    (operator_id, engagement_id, memory_type, title, content,
                     tags_json, pattern_key, active, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
                """,
                (
                    operator_id,
                    engagement_id,
                    memory_type,
                    title.strip(),
                    content.strip(),
                    json.dumps(tags),
                    pattern_key.strip().lower() if pattern_key else None,
                    now,
                    now,
                ),
            )
            row = conn.execute(
                "SELECT * FROM agent_memory WHERE id = ?", (cur.lastrowid,)
            ).fetchone()
            return self._hydrate_memory(row)

    def list_memories(
        self,
        *,
        operator_id: str,
        engagement_id: str | None = None,
        memory_type: str | None = None,
        active_only: bool = True,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Return operator-global memories plus memories scoped to engagement_id only."""
        clauses = ["operator_id = ?"]
        args: list[Any] = [operator_id]
        if engagement_id:
            clauses.append("(engagement_id IS NULL OR engagement_id = ?)")
            args.append(engagement_id)
        if memory_type:
            clauses.append("memory_type = ?")
            args.append(memory_type)
        if active_only:
            clauses.append("active = 1")
        args.append(max(1, min(limit, 200)))
        with self.connection() as conn:
            rows = conn.execute(
                f"SELECT * FROM agent_memory WHERE {' AND '.join(clauses)} ORDER BY id DESC LIMIT ?",
                args,
            ).fetchall()
            return [self._hydrate_memory(r) for r in rows]

    def set_memory_active(
        self, memory_id: int, operator_id: str, active: bool, allow_override: bool = False
    ) -> dict[str, Any] | None:
        with self._write_lock, self.connection() as conn:
            row = conn.execute("SELECT * FROM agent_memory WHERE id = ?", (memory_id,)).fetchone()
            if not row:
                return None
            if row["operator_id"] != operator_id and not allow_override:
                raise PermissionError("Cannot modify another operator's private memory entry.")
            conn.execute(
                "UPDATE agent_memory SET active = ?, updated_at = ? WHERE id = ?",
                (int(active), utc_now_iso(), memory_id),
            )
            updated = conn.execute("SELECT * FROM agent_memory WHERE id = ?", (memory_id,)).fetchone()
            return self._hydrate_memory(updated)

    @staticmethod
    def _hydrate_memory(row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        item["active"] = bool(item["active"])
        item["tags"] = json.loads(item["tags_json"])
        return item

    # ------------------------------------------------------------------
    # Automated Recon Runs & Human-Reviewed Findings Repository
    # ------------------------------------------------------------------

    def save_recon_run(
        self,
        *,
        run_id: str,
        engagement_id: str,
        operator_id: str,
        root_target: str,
        skill_id: str,
        llm_provider: str,
        llm_model: str,
        status: str,
        discovered_assets: list[dict[str, Any]],
        steps: list[dict[str, Any]],
        memories_applied: list[dict[str, Any]],
        queued_approvals: list[str],
        summary_stats: dict[str, Any],
        ai_synthesis: str,
        report_markdown: str,
        started_at: str,
        finished_at: str,
        duration_ms: int,
        findings: list[dict[str, Any]],
    ) -> dict[str, Any]:
        now = utc_now_iso()
        with self._write_lock, self.connection() as conn:
            conn.execute("BEGIN IMMEDIATE;")
            try:
                conn.execute(
                    """
                    INSERT INTO recon_runs
                        (run_id, engagement_id, operator_id, root_target, skill_id,
                         llm_provider, llm_model, status, discovered_assets_json, steps_json,
                         memories_applied_json, queued_approvals_json, summary_stats_json,
                         ai_synthesis, report_markdown, started_at, finished_at, duration_ms)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        run_id,
                        engagement_id,
                        operator_id,
                        root_target,
                        skill_id,
                        llm_provider,
                        llm_model,
                        status,
                        json.dumps(discovered_assets),
                        json.dumps(steps),
                        json.dumps(memories_applied),
                        json.dumps(queued_approvals),
                        json.dumps(summary_stats),
                        ai_synthesis,
                        report_markdown,
                        started_at,
                        finished_at,
                        duration_ms,
                    ),
                )
                for f in findings:
                    conn.execute(
                        """
                        INSERT INTO recon_findings
                            (run_id, engagement_id, asset, category, finding_key, title,
                             severity, priority_score, ai_confidence, dual_verified,
                             suppressed_by_memory, evidence, remediation,
                             requires_human_judgment, human_judgment_reason, created_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            run_id,
                            engagement_id,
                            f["asset"],
                            f["category"],
                            f["finding_key"],
                            f["title"],
                            f["severity"],
                            int(f["priority_score"]),
                            float(f["ai_confidence"]),
                            int(bool(f.get("dual_verified", False))),
                            f.get("suppressed_by_memory"),
                            f.get("evidence", ""),
                            f.get("remediation", ""),
                            int(bool(f.get("requires_human_judgment", True))),
                            f.get("human_judgment_reason", ""),
                            now,
                        ),
                    )
                conn.execute("COMMIT;")
            except Exception:
                conn.execute("ROLLBACK;")
                raise
        return self.get_recon_run(run_id) or {}

    def get_recon_run(self, run_id: str) -> dict[str, Any] | None:
        with self.connection() as conn:
            row = conn.execute("SELECT * FROM recon_runs WHERE run_id = ?", (run_id,)).fetchone()
            if not row:
                return None
            f_rows = conn.execute(
                "SELECT * FROM recon_findings WHERE run_id = ? ORDER BY priority_score DESC, id ASC",
                (run_id,),
            ).fetchall()
        item = dict(row)
        item["discovered_assets"] = json.loads(item["discovered_assets_json"])
        item["steps"] = json.loads(item["steps_json"])
        item["memories_applied"] = json.loads(item["memories_applied_json"])
        item["queued_approvals"] = json.loads(item["queued_approvals_json"])
        item["summary_stats"] = json.loads(item["summary_stats_json"])
        item["findings"] = [self._hydrate_finding(fr) for fr in f_rows]
        return item

    def list_recon_runs(
        self, engagement_id: str | None = None, limit: int = 25
    ) -> list[dict[str, Any]]:
        args: list[Any] = []
        where = ""
        if engagement_id:
            where = "WHERE engagement_id = ?"
            args.append(engagement_id)
        args.append(max(1, min(limit, 100)))
        with self.connection() as conn:
            rows = conn.execute(
                f"""
                SELECT run_id, engagement_id, operator_id, root_target, skill_id,
                       llm_provider, llm_model, status, summary_stats_json,
                       started_at, finished_at, duration_ms
                FROM recon_runs {where}
                ORDER BY started_at DESC LIMIT ?
                """,
                args,
            ).fetchall()
        out: list[dict[str, Any]] = []
        for r in rows:
            d = dict(r)
            d["summary_stats"] = json.loads(d["summary_stats_json"])
            out.append(d)
        return out

    def get_finding(self, finding_id: int) -> dict[str, Any] | None:
        """Look up a finding without mutating it (authorize before any write)."""
        with self.connection() as conn:
            row = conn.execute("SELECT * FROM recon_findings WHERE id = ?", (finding_id,)).fetchone()
        return self._hydrate_finding(row) if row else None

    def review_finding(
        self,
        *,
        finding_id: int,
        verdict: str,
        note: str,
        reviewed_by: str,
    ) -> dict[str, Any] | None:
        with self._write_lock, self.connection() as conn:
            conn.execute(
                """
                UPDATE recon_findings
                SET analyst_verdict = ?, analyst_note = ?, reviewed_by = ?, reviewed_at = ?
                WHERE id = ?
                """,
                (verdict, note.strip(), reviewed_by, utc_now_iso(), finding_id),
            )
            row = conn.execute(
                "SELECT * FROM recon_findings WHERE id = ?", (finding_id,)
            ).fetchone()
            return self._hydrate_finding(row) if row else None

    @staticmethod
    def _hydrate_finding(row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        item["dual_verified"] = bool(item["dual_verified"])
        item["requires_human_judgment"] = bool(item["requires_human_judgment"])
        return item

    # ------------------------------------------------------------------
    # 2.2 Capability surface: quota elevation support
    # ------------------------------------------------------------------

    def raise_quota(
        self, *, operator_id: str, calls_delta: int = 0, tokens_delta: int = 0
    ) -> dict[str, Any]:
        """Raise the CURRENT period's quota ceilings for an operator.

        Called only from an approved expansion request. Historical periods keep
        their original ceilings so the audit trail shows when a limit moved.
        """
        calls_delta, tokens_delta = max(0, int(calls_delta)), max(0, int(tokens_delta))
        if not calls_delta and not tokens_delta:
            raise ValueError("A quota elevation must raise calls and/or tokens.")
        with self._write_lock, self.connection() as conn:
            conn.execute("BEGIN IMMEDIATE;")
            try:
                rows = conn.execute(
                    "SELECT * FROM quota WHERE operator_id = ? AND "
                    "period_key = (SELECT MAX(period_key) FROM quota WHERE operator_id = ?) "
                    "ORDER BY id DESC LIMIT 1",
                    (operator_id, operator_id),
                ).fetchone()
                if not rows:
                    conn.execute("COMMIT;")
                    raise ValueError(f"No quota row exists yet for operator '{operator_id}'.")
                before = dict(rows)
                conn.execute(
                    "UPDATE quota SET max_calls = max_calls + ?, max_tokens = max_tokens + ?, "
                    "updated_at = ? WHERE id = ?",
                    (calls_delta, tokens_delta, utc_now_iso(), before["id"]),
                )
                after = conn.execute(
                    "SELECT * FROM quota WHERE id = ?", (before["id"],)
                ).fetchone()
                conn.execute("COMMIT;")
                return {
                    "quota_before": {
                        "max_calls": before["max_calls"],
                        "max_tokens": before["max_tokens"],
                    },
                    "quota_after": {
                        "max_calls": after["max_calls"],
                        "max_tokens": after["max_tokens"],
                    },
                }
            except Exception:
                if conn.in_transaction:
                    conn.execute("ROLLBACK;")
                raise

    # ------------------------------------------------------------------
    # 2.3 offensive surface — delegated to OffensiveStore
    # ------------------------------------------------------------------
    @property
    def offensive(self):
        """Lazy accessor for the 2.3 offensive-surface store.

        Kept lazy so importing ``gateway.db`` stays free of a cycle with
        ``gateway.offensive_store``.
        """
        from gateway.offensive_store import OffensiveStore

        store = getattr(self, "_offensive_store", None)
        if store is None:
            store = OffensiveStore(self)
            self._offensive_store = store
        return store

    def upsert_policy(self, **kwargs):
        return self.offensive.upsert_policy(**kwargs)

    def get_policy(self, policy_id: str):
        return self.offensive.get_policy(policy_id)

    def list_policies(self, policy_type: str | None = None):
        return self.offensive.list_policies(policy_type)

    def set_engagement_posture(self, engagement_id: str, posture_id: str, actor: str) -> None:
        return self.offensive.set_engagement_posture(engagement_id, posture_id, actor)

    def get_engagement_posture(self, engagement_id: str):
        return self.offensive.get_engagement_posture(engagement_id)

    def save_consent(self, **kwargs):
        return self.offensive.save_consent(**kwargs)

    def get_consent(self, consent_id: str):
        return self.offensive.get_consent(consent_id)

    def list_consents(self, **kwargs):
        return self.offensive.list_consents(**kwargs)

    def revoke_consent(self, consent_id: str):
        return self.offensive.revoke_consent(consent_id)

    def save_scan_authorization(self, **kwargs):
        return self.offensive.save_scan_authorization(**kwargs)

    def get_scan_authorization(self, authorization_id: str):
        return self.offensive.get_scan_authorization(authorization_id)

    def live_scan_authorization(self, engagement_id: str):
        return self.offensive.live_scan_authorization(engagement_id)

    def consume_scan_budget(self, authorization_id: str, requests: int):
        return self.offensive.consume_scan_budget(authorization_id, requests)
