"""Durable mission, asset, evidence and retest storage for Redstrike 2.1.

Graphs are projections of authoritative rows, not a second, drifting copy of
findings. All identities and deduplication keys are computed by the application.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import ipaddress
import json
import sqlite3
import uuid
from typing import Any

from gateway.db import Database, utc_now_iso

TERMINAL_STATES = frozenset({"cancelled", "completed", "failed", "budget_exhausted"})
ACTIVE_STATES = ("running", "pausing", "cancelling")


class WorkspaceConflict(ValueError):
    """A concurrent request or an invalid lifecycle transition was refused."""


class MissionBudgetExceeded(ValueError):
    """A finite action budget or absolute mission deadline was reached."""


def canonical_json(value: Any) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    )


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:20]}"


class WorkspaceStore:
    def __init__(self, db: Database) -> None:
        self.db = db

    @staticmethod
    def _asset(
        conn: sqlite3.Connection,
        engagement_id: str,
        kind: str,
        locator: str,
        host: str,
        parent_id: str | None = None,
    ) -> str:
        digest = hashlib.sha256(f"{engagement_id}\0{kind}\0{locator}".encode()).hexdigest()[:24]
        asset_id = f"ast-{digest}"
        now = utc_now_iso()
        conn.execute(
            """INSERT INTO workspace_assets
               (asset_id, engagement_id, kind, locator, host, parent_id, first_seen, last_seen)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(engagement_id, kind, locator) DO UPDATE SET last_seen=excluded.last_seen""",
            (asset_id, engagement_id, kind, locator, host, parent_id, now, now),
        )
        return asset_id

    @staticmethod
    def host_kind(host: str) -> str:
        try:
            ipaddress.ip_address(host)
            return "ip"
        except ValueError:
            return "domain"

    def create_mission(
        self,
        *,
        engagement_id: str,
        requested_by: str,
        name: str,
        goal: str,
        targets: list[str],
        skill: dict[str, Any],
        http: dict[str, Any],
        capture_evidence: bool,
        max_actions: int,
        max_seconds: int,
    ) -> dict[str, Any]:
        mission_id, now = new_id("msn"), utc_now_iso()
        with self.db.transaction() as conn:
            conn.execute(
                """INSERT INTO missions
                   (mission_id, engagement_id, requested_by, name, goal, skill_id, skill_snapshot_json,
                    http_json, capture_evidence, max_actions, max_seconds, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    mission_id,
                    engagement_id,
                    requested_by,
                    name,
                    goal,
                    skill["skill_id"],
                    canonical_json(skill),
                    canonical_json(http),
                    int(capture_evidence),
                    max_actions,
                    max_seconds,
                    now,
                    now,
                ),
            )
            for position, host in enumerate(targets):
                asset_id = self._asset(conn, engagement_id, self.host_kind(host), host, host)
                conn.execute(
                    """INSERT INTO mission_intents (intent_id, mission_id, asset_id, position, target)
                       VALUES (?, ?, ?, ?, ?)""",
                    (new_id("int"), mission_id, asset_id, position, host),
                )
        return self.get_mission(mission_id) or {}

    @staticmethod
    def _mission(row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        item["skill_snapshot"] = json.loads(item.pop("skill_snapshot_json"))
        item["http"] = json.loads(item.pop("http_json"))
        item["capture_evidence"] = bool(item["capture_evidence"])
        # 2.2 columns are nullable on legacy rows; normalise for every reader.
        item.setdefault("mode_id", None)
        raw_ceiling = item.pop("mode_ceiling_json", None) or "{}"
        try:
            item["mode_ceiling"] = json.loads(raw_ceiling) if raw_ceiling else {}
        except ValueError:
            item["mode_ceiling"] = {}
        return item

    def get_mission(self, mission_id: str) -> dict[str, Any] | None:
        with self.db.connection() as conn:
            row = conn.execute(
                "SELECT * FROM missions WHERE mission_id=?", (mission_id,)
            ).fetchone()
            if not row:
                return None
            intents = conn.execute(
                "SELECT * FROM mission_intents WHERE mission_id=? ORDER BY position", (mission_id,)
            ).fetchall()
        item = self._mission(row)
        item["intents"] = [dict(r) for r in intents]
        return item

    def list_missions(
        self, engagement_id: str, limit: int = 30, offset: int = 0
    ) -> list[dict[str, Any]]:
        with self.db.connection() as conn:
            rows = conn.execute(
                """SELECT m.mission_id, m.engagement_id, m.requested_by, m.name, m.goal, m.skill_id,
                          m.status, m.max_actions, m.used_actions, m.max_seconds, m.deadline_at,
                          m.created_at, m.updated_at, m.error, COUNT(i.intent_id) AS total_intents,
                          SUM(CASE WHEN i.status='completed' THEN 1 ELSE 0 END) AS completed_intents
                   FROM missions m LEFT JOIN mission_intents i ON i.mission_id=m.mission_id
                   WHERE m.engagement_id=? GROUP BY m.mission_id
                   ORDER BY m.created_at DESC, m.mission_id LIMIT ? OFFSET ?""",
                (engagement_id, limit, offset),
            ).fetchall()
        return [dict(r) for r in rows]

    def start_mission(self, mission_id: str) -> dict[str, Any]:
        with self.db.transaction() as conn:
            row = conn.execute(
                "SELECT * FROM missions WHERE mission_id=?", (mission_id,)
            ).fetchone()
            if not row or row["status"] not in {"draft", "paused"}:
                raise WorkspaceConflict("Only draft or paused missions can be started.")
            now = dt.datetime.now(dt.timezone.utc)
            if row["deadline_at"] and dt.datetime.fromisoformat(row["deadline_at"]) <= now:
                raise MissionBudgetExceeded(
                    "The mission deadline has expired; create a new mission."
                )
            active = conn.execute(
                "SELECT requested_by FROM missions WHERE status IN ('running','pausing','cancelling')"
            ).fetchall()
            if len(active) >= 2 or any(r["requested_by"] == row["requested_by"] for r in active):
                raise WorkspaceConflict(
                    "At most two missions globally and one per operator may run at once."
                )
            deadline = (
                row["deadline_at"] or (now + dt.timedelta(seconds=row["max_seconds"])).isoformat()
            )
            conn.execute(
                """UPDATE missions SET status='running', deadline_at=?, started_at=COALESCE(started_at,?),
                   updated_at=?, error='' WHERE mission_id=?""",
                (deadline, now.isoformat(), now.isoformat(), mission_id),
            )
        return self.get_mission(mission_id) or {}

    def control(self, mission_id: str, action: str) -> dict[str, Any]:
        with self.db.transaction() as conn:
            row = conn.execute(
                "SELECT status FROM missions WHERE mission_id=?", (mission_id,)
            ).fetchone()
            if not row or row["status"] in TERMINAL_STATES:
                raise WorkspaceConflict(
                    "A terminal mission cannot be changed; create a new mission."
                )
            current = row["status"]
            if action == "pause":
                if current == "cancelling":
                    raise WorkspaceConflict("Cancellation is already in progress.")
                next_status = "pausing" if current in {"running", "pausing"} else "paused"
            elif action == "cancel":
                next_status = "cancelling" if current in ACTIVE_STATES else "cancelled"
                if next_status == "cancelled":
                    conn.execute(
                        "UPDATE mission_intents SET status='cancelled', finished_at=? "
                        "WHERE mission_id=? AND status='pending'",
                        (utc_now_iso(), mission_id),
                    )
            else:
                raise WorkspaceConflict("Unsupported mission action.")
            now = utc_now_iso()
            conn.execute(
                "UPDATE missions SET status=?, updated_at=?, finished_at=? WHERE mission_id=?",
                (next_status, now, now if next_status == "cancelled" else None, mission_id),
            )
        return self.get_mission(mission_id) or {}

    def finish(self, mission_id: str, status: str, error: str = "") -> None:
        if status not in TERMINAL_STATES | {"paused"}:
            raise ValueError("Invalid completion status.")
        now = utc_now_iso()
        with self.db.transaction() as conn:
            conn.execute(
                "UPDATE missions SET status=?, error=?, updated_at=?, finished_at=? WHERE mission_id=?",
                (status, error[:500], now, None if status == "paused" else now, mission_id),
            )
            if status == "cancelled":
                conn.execute(
                    "UPDATE mission_intents SET status='cancelled', finished_at=? "
                    "WHERE mission_id=? AND status IN ('pending','running')",
                    (now, mission_id),
                )

    def reserve_action(self, mission_id: str) -> None:
        """Reserve BEFORE I/O, under BEGIN IMMEDIATE; failures never refund attempts."""
        with self.db.transaction() as conn:
            row = conn.execute(
                "SELECT * FROM missions WHERE mission_id=?", (mission_id,)
            ).fetchone()
            if not row or row["status"] not in {"running", "pausing"}:
                raise WorkspaceConflict("Mission is no longer executable.")
            if row["used_actions"] >= row["max_actions"]:
                raise MissionBudgetExceeded("Mission action budget exhausted.")
            if not row["deadline_at"] or dt.datetime.fromisoformat(
                row["deadline_at"]
            ) <= dt.datetime.now(dt.timezone.utc):
                raise MissionBudgetExceeded("Mission deadline exceeded.")
            conn.execute(
                "UPDATE missions SET used_actions=used_actions+1, updated_at=? WHERE mission_id=?",
                (utc_now_iso(), mission_id),
            )

    def start_intent(self, intent_id: str) -> None:
        with self.db.transaction() as conn:
            changed = conn.execute(
                "UPDATE mission_intents SET status='running', attempts=attempts+1, started_at=?, error='' "
                "WHERE intent_id=? AND status='pending'",
                (utc_now_iso(), intent_id),
            ).rowcount
            if changed != 1:
                raise WorkspaceConflict("This intent is already claimed.")

    def finish_intent(
        self, intent_id: str, status: str, *, run_id: str | None = None, error: str = ""
    ) -> None:
        if status not in {"completed", "failed", "pending", "cancelled"}:
            raise ValueError("Invalid intent status.")
        with self.db.transaction() as conn:
            conn.execute(
                "UPDATE mission_intents SET status=?, run_id=COALESCE(?,run_id), error=?, finished_at=? "
                "WHERE intent_id=? AND status='running'",
                (
                    status,
                    run_id,
                    error[:500],
                    None if status == "pending" else utc_now_iso(),
                    intent_id,
                ),
            )

    def checkpoint_run(self, intent_id: str, run_id: str) -> None:
        with self.db.transaction() as conn:
            conn.execute(
                "UPDATE mission_intents SET run_id=? WHERE intent_id=? AND status='running'",
                (run_id, intent_id),
            )

    def recover_interrupted(self) -> list[dict[str, Any]]:
        """Restart is fail-closed: never resume target contact without an operator."""
        with self.db.transaction() as conn:
            rows = conn.execute(
                "SELECT mission_id, engagement_id, status FROM missions "
                "WHERE status IN ('running','pausing','cancelling')"
            ).fetchall()
            for row in rows:
                mission_id = row["mission_id"]
                state = "cancelled" if row["status"] == "cancelling" else "paused"
                conn.execute(
                    "UPDATE missions SET status=?, updated_at=?, error=? WHERE mission_id=?",
                    (
                        state,
                        utc_now_iso(),
                        "Gateway restarted; explicit resume required.",
                        mission_id,
                    ),
                )
                conn.execute(
                    """UPDATE mission_intents SET status=CASE
                         WHEN run_id IS NOT NULL THEN 'completed'
                         WHEN ?='cancelled' THEN 'cancelled' ELSE 'pending' END,
                       error='Interrupted by gateway restart; action reservations retained.'
                       WHERE mission_id=? AND status='running'""",
                    (state, mission_id),
                )
                if state == "cancelled":
                    conn.execute(
                        "UPDATE mission_intents SET status='cancelled' WHERE mission_id=? AND status='pending'",
                        (mission_id,),
                    )
        return [dict(r) for r in rows]

    def ingest_run(self, run: dict[str, Any]) -> None:
        """Called only after successful scope checks by the recon agent."""
        engagement_id, run_id = str(run["engagement_id"]), str(run["run_id"])
        with self.db.transaction() as conn:
            for entry in run.get("discovered_assets", []):
                if not entry.get("in_scope"):
                    continue
                host = str(entry["asset"])
                asset_id = self._asset(conn, engagement_id, self.host_kind(host), host, host)
                # Merely discovering a subdomain is not proof that it was tested.
                if host == run["root_target"] and any(
                    s.get("status") == "completed" for s in run.get("steps", [])
                ):
                    conn.execute(
                        "INSERT OR IGNORE INTO asset_runs VALUES (?,?)", (asset_id, run_id)
                    )
            root = str(run["root_target"])
            root_id = self._asset(conn, engagement_id, self.host_kind(root), root, root)
            host_part = f"[{root}]" if ":" in root else root
            for port in run.get("summary_stats", {}).get("open_ports", [])[:10]:
                service_id = self._asset(
                    conn, engagement_id, "service", f"tcp://{host_part}:{int(port)}", root, root_id
                )
                conn.execute("INSERT OR IGNORE INTO asset_runs VALUES (?,?)", (service_id, run_id))

    def list_assets(
        self, engagement_id: str, limit: int = 200, offset: int = 0
    ) -> list[dict[str, Any]]:
        with self.db.connection() as conn:
            rows = conn.execute(
                """SELECT a.*,
                     (SELECT COUNT(*) FROM asset_runs r WHERE r.asset_id=a.asset_id) AS run_count,
                     (SELECT COUNT(*) FROM http_evidence e WHERE e.asset_id=a.asset_id) AS evidence_count
                   FROM workspace_assets a WHERE a.engagement_id=?
                   ORDER BY a.first_seen, a.asset_id LIMIT ? OFFSET ?""",
                (engagement_id, limit, offset),
            ).fetchall()
        return [dict(r) for r in rows]

    def coverage(self, engagement_id: str) -> dict[str, int]:
        with self.db.connection() as conn:
            row = conn.execute(
                """SELECT COUNT(*) AS total, COALESCE(SUM(CASE WHEN
                   EXISTS(SELECT 1 FROM asset_runs r WHERE r.asset_id=a.asset_id) OR
                   EXISTS(SELECT 1 FROM http_evidence e WHERE e.asset_id=a.asset_id)
                   THEN 1 ELSE 0 END),0) AS tested
                   FROM workspace_assets a WHERE a.engagement_id=?""",
                (engagement_id,),
            ).fetchone()
        total, tested = int(row["total"]), int(row["tested"])
        return {"total": total, "tested": tested, "untested": total - tested}

    def save_evidence(
        self,
        *,
        engagement_id: str,
        captured_by: str,
        target: str,
        payload: dict[str, Any],
        mission_id: str | None = None,
        run_id: str | None = None,
    ) -> dict[str, Any]:
        evidence_id, now = new_id("evd"), utc_now_iso()
        raw = canonical_json(payload)
        digest = hashlib.sha256(raw.encode()).hexdigest()
        with self.db.transaction() as conn:
            for table, key, value in (
                ("missions", "mission_id", mission_id),
                ("recon_runs", "run_id", run_id),
            ):
                if value is not None:
                    row = conn.execute(
                        f"SELECT engagement_id FROM {table} WHERE {key}=?", (value,)
                    ).fetchone()
                    if not row or row["engagement_id"] != engagement_id:
                        raise ValueError("Evidence reference belongs to another engagement.")
            parent = self._asset(conn, engagement_id, self.host_kind(target), target, target)
            asset_id = self._asset(conn, engagement_id, "endpoint", payload["url"], target, parent)
            conn.execute(
                """INSERT INTO http_evidence
                   (evidence_id, engagement_id, asset_id, mission_id, run_id, captured_by,
                    target, payload_json, sha256, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (
                    evidence_id,
                    engagement_id,
                    asset_id,
                    mission_id,
                    run_id,
                    captured_by,
                    target,
                    raw,
                    digest,
                    now,
                ),
            )
        return self.get_evidence(evidence_id) or {}

    @staticmethod
    def _evidence(row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        raw = item.pop("payload_json")
        item["payload"] = json.loads(raw)
        item["integrity_valid"] = hmac.compare_digest(
            hashlib.sha256(raw.encode()).hexdigest(), item["sha256"]
        )
        return item

    def get_evidence(self, evidence_id: str) -> dict[str, Any] | None:
        with self.db.connection() as conn:
            row = conn.execute(
                "SELECT * FROM http_evidence WHERE evidence_id=?", (evidence_id,)
            ).fetchone()
        return self._evidence(row) if row else None

    def list_evidence(
        self,
        engagement_id: str,
        *,
        mission_id: str | None = None,
        run_id: str | None = None,
        limit: int = 30,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        where, args = ["engagement_id=?"], [engagement_id]
        for column, value in (("mission_id", mission_id), ("run_id", run_id)):
            if value is not None:
                where.append(f"{column}=?")
                args.append(value)
        with self.db.connection() as conn:
            rows = conn.execute(
                f"SELECT * FROM http_evidence WHERE {' AND '.join(where)} ORDER BY created_at DESC, evidence_id LIMIT ? OFFSET ?",
                [*args, limit, offset],
            ).fetchall()
        return [self._evidence(r) for r in rows]

    def save_retest(
        self,
        *,
        finding_id: int,
        engagement_id: str,
        requested_by: str,
        evidence_id: str,
        outcome: str,
        note: str,
    ) -> dict[str, Any]:
        item = dict(
            retest_id=new_id("rts"),
            finding_id=finding_id,
            engagement_id=engagement_id,
            requested_by=requested_by,
            evidence_id=evidence_id,
            outcome=outcome,
            note=note,
            created_at=utc_now_iso(),
        )
        with self.db.transaction() as conn:
            rows = [
                conn.execute(
                    f"SELECT engagement_id FROM {table} WHERE {key}=?", (value,)
                ).fetchone()
                for table, key, value in (
                    ("recon_findings", "id", finding_id),
                    ("http_evidence", "evidence_id", evidence_id),
                )
            ]
            if any(r is None or r["engagement_id"] != engagement_id for r in rows):
                raise ValueError("Retest references must belong to the same engagement.")
            conn.execute(
                "INSERT INTO finding_retests VALUES (:retest_id,:finding_id,:engagement_id,:requested_by,:evidence_id,:outcome,:note,:created_at)",
                item,
            )
        return item

    def list_retests(self, finding_id: int) -> list[dict[str, Any]]:
        with self.db.connection() as conn:
            rows = conn.execute(
                "SELECT * FROM finding_retests WHERE finding_id=? ORDER BY created_at DESC LIMIT 100",
                (finding_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # 2.2 — Mode binding, deep TLS records, expansion requests, gate results
    # ------------------------------------------------------------------

    def bind_mode(self, mission_id: str, mode_id: str, ceiling: dict[str, Any]) -> None:
        """Attach an operational mode + frozen ceiling to a mission row."""
        with self.db.transaction() as conn:
            conn.execute(
                "UPDATE missions SET mode_id=?, mode_ceiling_json=?, updated_at=? "
                "WHERE mission_id=?",
                (mode_id, canonical_json(ceiling), utc_now_iso(), mission_id),
            )

    @staticmethod
    def get_tls_audit(self, audit_id: str) -> dict[str, Any] | None:
        with self.db.connection() as conn:
            row = conn.execute(
                "SELECT * FROM tls_audits WHERE audit_id=?", (audit_id,)
            ).fetchone()
        return self._tls_audit(row) if row else None

    def list_tls_audits(
        self,
        engagement_id: str,
        *,
        mission_id: str | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        where, args = ["engagement_id=?"], [engagement_id]
        if mission_id is not None:
            where.append("mission_id=?")
            args.append(mission_id)
        with self.db.connection() as conn:
            rows = conn.execute(
                f"SELECT * FROM tls_audits WHERE {' AND '.join(where)} "
                "ORDER BY created_at DESC, audit_id LIMIT ? OFFSET ?",
                [*args, max(1, min(limit, 100)), max(0, offset)],
            ).fetchall()
        return [self._tls_audit(r) for r in rows]

    @staticmethod
    def _tls_audit(row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        item["payload"] = json.loads(item.pop("payload_json"))
        return item

    def save_expansion_request(
        self,
        *,
        engagement_id: str,
        mission_id: str | None,
        kind: str,
        requested_by: str,
        approval_id: str,
        roe_clause: str,
        justification: str,
        payload: dict[str, Any],
        ttl_seconds: int,
    ) -> dict[str, Any]:
        expansion_id = new_id("xpn")
        now = dt.datetime.now(dt.timezone.utc)
        with self.db.transaction() as conn:
            conn.execute(
                """INSERT INTO expansion_requests
                   (expansion_id, engagement_id, mission_id, kind, requested_by, approval_id,
                    roe_clause, justification, payload_json, status, expires_at, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)""",
                (
                    expansion_id,
                    engagement_id,
                    mission_id,
                    kind,
                    requested_by,
                    approval_id,
                    roe_clause,
                    justification,
                    canonical_json(payload),
                    (now + dt.timedelta(seconds=max(60, int(ttl_seconds)))).isoformat(),
                    now.isoformat(),
                ),
            )
        return self.get_expansion_request(expansion_id) or {}

    def get_expansion_request(self, expansion_id: str) -> dict[str, Any] | None:
        with self.db.connection() as conn:
            row = conn.execute(
                "SELECT * FROM expansion_requests WHERE expansion_id=?", (expansion_id,)
            ).fetchone()
        return self._expansion(row) if row else None

    def list_expansion_requests(
        self,
        *,
        engagement_id: str | None = None,
        mission_id: str | None = None,
        status: str | None = None,
        limit: int = 30,
    ) -> list[dict[str, Any]]:
        where, args = [], []
        for column, value in (
            ("engagement_id", engagement_id),
            ("mission_id", mission_id),
            ("status", status),
        ):
            if value is not None:
                where.append(f"{column}=?")
                args.append(value)
        clause = f"WHERE {' AND '.join(where)}" if where else ""
        with self.db.connection() as conn:
            rows = conn.execute(
                f"SELECT * FROM expansion_requests {clause} "
                "ORDER BY created_at DESC, expansion_id LIMIT ?",
                [*args, max(1, min(limit, 200))],
            ).fetchall()
        return [self._expansion(r) for r in rows]

    def finish_expansion(
        self,
        expansion_id: str,
        status: str,
        *,
        note: str = "",
        applied: dict[str, Any] | None = None,
        decided_by: str | None = None,
    ) -> dict[str, Any]:
        if status not in {"approved", "rejected", "expired", "withdrawn"}:
            raise ValueError("Invalid expansion terminal status.")
        with self.db.transaction() as conn:
            row = conn.execute(
                "SELECT status FROM expansion_requests WHERE expansion_id=?", (expansion_id,)
            ).fetchone()
            if not row:
                raise KeyError("Expansion request not found.")
            if row["status"] in {"approved", "rejected", "expired", "withdrawn"}:
                raise WorkspaceConflict(f"Expansion request is already {row['status']}.")
            conn.execute(
                "UPDATE expansion_requests SET status=?, applied_json=?, decided_by=?, "
                "decided_at=?, note=? WHERE expansion_id=?",
                (
                    status,
                    canonical_json(applied or {}),
                    decided_by,
                    utc_now_iso(),
                    note[:500],
                    expansion_id,
                ),
            )
        return self.get_expansion_request(expansion_id) or {}

    @staticmethod
    def _expansion(row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        item["payload"] = json.loads(item.pop("payload_json"))
        item["applied"] = json.loads(item.pop("applied_json", "{}") or "{}")
        return item

    def add_expansion_intents(self, mission_id: str, hosts: list[str]) -> int:
        """Append approved hosts as new pending intents (never replays old ones)."""
        if not hosts:
            return 0
        now = utc_now_iso()
        with self.db.transaction() as conn:
            mission = conn.execute(
                "SELECT engagement_id FROM missions WHERE mission_id=?", (mission_id,)
            ).fetchone()
            if not mission:
                raise KeyError("Mission not found.")
            position = conn.execute(
                "SELECT COALESCE(MAX(position) + 1, 0) AS nxt FROM mission_intents WHERE mission_id=?",
                (mission_id,),
            ).fetchone()["nxt"]
            added = 0
            for offset, host in enumerate(hosts):
                asset_id = self._asset(
                    conn, mission["engagement_id"], self.host_kind(host), host, host
                )
                existing = conn.execute(
                    "SELECT 1 FROM mission_intents WHERE mission_id=? AND target=?",
                    (mission_id, host),
                ).fetchone()
                if existing:
                    continue
                conn.execute(
                    "INSERT INTO mission_intents (intent_id, mission_id, asset_id, position, target) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (new_id("int"), mission_id, asset_id, int(position) + offset, host),
                )
                added += 1
            conn.execute(
                "UPDATE missions SET updated_at=? WHERE mission_id=?", (now, mission_id)
            )
        return added

    def raise_mission_budget(
        self, mission_id: str, *, action_increase: int, seconds_increase: int
    ) -> dict[str, Any]:
        """Extend a live mission's budget and shift its deadline by the same delta.

        The absolute deadline is *extended*, never reset: a paused mission does
        not gain free time, and finished missions cannot be revived.
        """
        action_increase, seconds_increase = max(0, int(action_increase)), max(0, int(seconds_increase))
        with self.db.transaction() as conn:
            row = conn.execute(
                "SELECT * FROM missions WHERE mission_id=?", (mission_id,)
            ).fetchone()
            if not row:
                raise KeyError("Mission not found.")
            if row["status"] in TERMINAL_STATES:
                raise WorkspaceConflict("A terminal mission cannot receive more budget.")
            new_actions = int(row["max_actions"]) + action_increase
            new_seconds = int(row["max_seconds"]) + seconds_increase
            if new_actions > 128:
                raise MissionBudgetExceeded("Total action ceiling would exceed 128.")
            deadline = row["deadline_at"]
            if deadline is None and seconds_increase:
                base = dt.datetime.now(dt.timezone.utc)
                deadline = (base + dt.timedelta(seconds=new_seconds)).isoformat()
            elif deadline is not None and seconds_increase:
                deadline = (
                    dt.datetime.fromisoformat(deadline) + dt.timedelta(seconds=seconds_increase)
                ).isoformat()
            conn.execute(
                "UPDATE missions SET max_actions=?, max_seconds=?, deadline_at=?, updated_at=? "
                "WHERE mission_id=?",
                (new_actions, new_seconds, deadline, utc_now_iso(), mission_id),
            )
        return {
            "mission_id": mission_id,
            "max_actions_before": int(row["max_actions"]),
            "max_actions_after": new_actions,
            "max_seconds_before": int(row["max_seconds"]),
            "max_seconds_after": new_seconds,
            "deadline_at": deadline,
        }

    def save_gate_results(
        self,
        *,
        engagement_id: str,
        mission_id: str | None,
        target: str,
        results: list[dict[str, Any]],
    ) -> int:
        """Append evidence-gate verdicts (append-only; never updated)."""
        if not results:
            return 0
        now = utc_now_iso()
        with self.db.transaction() as conn:
            for result in results:
                conn.execute(
                    """INSERT INTO evidence_gate_results
                       (gate_id, engagement_id, mission_id, finding_key, target, status,
                        payload_json, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        new_id("gat"),
                        engagement_id,
                        mission_id,
                        str(result.get("finding_key", "")),
                        target,
                        str(result.get("status", "candidate")),
                        canonical_json(result),
                        now,
                    ),
                )
        return len(results)

    def list_gate_results(
        self, engagement_id: str, *, mission_id: str | None = None, limit: int = 50
    ) -> list[dict[str, Any]]:
        where, args = ["engagement_id=?"], [engagement_id]
        if mission_id is not None:
            where.append("mission_id=?")
            args.append(mission_id)
        with self.db.connection() as conn:
            rows = conn.execute(
                f"SELECT * FROM evidence_gate_results WHERE {' AND '.join(where)} "
                "ORDER BY created_at DESC, gate_id LIMIT ?",
                [*args, max(1, min(limit, 200))],
            ).fetchall()
        out = []
        for row in rows:
            item = dict(row)
            item["payload"] = json.loads(item.pop("payload_json"))
            out.append(item)
        return out

    def save_tls_audit(
        self,
        *,
        engagement_id: str,
        target: str,
        port: int,
        requested_by: str,
        mission_id: str | None,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        """Persist an immutable, hashed deep-TLS audit record."""
        audit_id = new_id("tls")
        body = canonical_json(payload)
        digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
        now = utc_now_iso()
        with self.db.transaction() as conn:
            conn.execute(
                """INSERT INTO tls_audits
                   (audit_id, engagement_id, mission_id, target, port, requested_by,
                    payload_json, sha256, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    audit_id,
                    engagement_id,
                    mission_id,
                    target,
                    int(port),
                    requested_by,
                    body,
                    digest,
                    now,
                ),
            )
        return {
            "audit_id": audit_id,
            "engagement_id": engagement_id,
            "mission_id": mission_id,
            "target": target,
            "port": int(port),
            "requested_by": requested_by,
            "sha256": digest,
            "created_at": now,
            "payload": payload,
        }
