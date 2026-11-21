"""Additive upgrade, transaction and IP safety regressions for existing v2 data."""

from __future__ import annotations

import socket
import sqlite3
from pathlib import Path

import pytest

from gateway.db import Database, SCHEMA_SQL
from gateway.policy import normalize_target_input, validate_allowlist_entry_syntax


def test_additive_migration_preserves_old_records_and_is_idempotent(tmp_path):
    path = tmp_path / "legacy.sqlite"
    with sqlite3.connect(path) as legacy:
        legacy.executescript(SCHEMA_SQL)  # v2 schema, without workspace tables/ledger.
        legacy.execute(
            "INSERT INTO engagements VALUES ('ENG-OLD','Previous assessment','Keep me','2026-01-01','2027-01-01',0,'2026-01-01')"
        )
        legacy.execute(
            "INSERT INTO recon_runs(run_id,engagement_id,operator_id,root_target,skill_id,llm_provider,llm_model,status,started_at,finished_at) VALUES ('rcn-old','ENG-OLD','old-operator','192.0.2.8','old-skill','mock','old-model','completed','2026-01-01','2026-01-01')"
        )
    first = Database(path)
    assert first.get_engagement("ENG-OLD")["description"] == "Keep me"
    assert first.get_recon_run("rcn-old")["root_target"] == "192.0.2.8"
    audit = first.write_audit_log(
        engagement_id="ENG-OLD",
        operator_id="old-operator",
        target="192.0.2.8",
        tool_or_script="fixture",
        status="completed",
    )
    second = Database(path)
    assert second.get_recon_run("rcn-old") == first.get_recon_run("rcn-old")
    assert second.query_audit_log()[0] == audit
    with second.connection() as conn:
        assert conn.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0] >= 1
        assert conn.execute("SELECT COUNT(*) FROM missions").fetchone()[0] == 0
        assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    assert second.verify_audit_chain()["valid"]


def test_applied_migration_digest_drift_fails_closed(tmp_path):
    path = tmp_path / "drift.sqlite"
    db = Database(path)
    with db.transaction() as conn:
        conn.execute("UPDATE schema_migrations SET sha256=?", ("0" * 64,))
    with pytest.raises(RuntimeError, match="Applied migration was modified"):
        Database(path)


def test_failed_migration_rolls_back_ddl_and_ledger_and_can_retry(tmp_path, monkeypatch):
    path = tmp_path / "partial.sqlite"
    migration = (Path(__file__).parents[1] / "gateway/migrations/002_workspace.sql").resolve()
    original_read = Path.read_text

    def broken_script(file, *args, **kwargs):
        text = original_read(file, *args, **kwargs)
        return text + "\nTHIS_IS_INVALID_SQL;\n" if file.resolve() == migration else text

    with monkeypatch.context() as patch:
        patch.setattr(Path, "read_text", broken_script)
        with pytest.raises(sqlite3.OperationalError):
            Database(path)
    with sqlite3.connect(path) as conn:
        names = {row[0] for row in conn.execute("SELECT name FROM sqlite_master")}
        assert "schema_migrations" in names
        assert not names.intersection(
            {
                "missions",
                "workspace_assets",
                "http_evidence",
                "evidence_no_update",
                "tls_audits",
                "expansion_requests",
            }
        )
        assert conn.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0] == 0
        assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    # No manually deleted objects/ledger rows are needed to retry a clean source.
    retried = Database(path)
    with retried.connection() as conn:
        # Every shipped migration is applied exactly once on the retry; the count
        # is not hardcoded so an additive migration does not mask a real failure.
        applied = conn.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0]
        expected = len(list((Path(__file__).parents[1] / "gateway/migrations").glob("*.sql")))
        assert applied == expected >= 1
        assert conn.execute("SELECT COUNT(*) FROM missions").fetchone()[0] == 0


def test_short_transactions_roll_back_all_changes(isolated_store):
    db, _ = isolated_store
    with pytest.raises(RuntimeError):
        with db.transaction() as conn:
            conn.execute("UPDATE engagements SET active=0")
            raise RuntimeError("Abort test transaction")
    assert all(eng["active"] for eng in db.list_engagements())


@pytest.mark.parametrize(
    "destination", ["::ffff:169.254.169.254", "::ffff:169.254.170.2", "::ffff:100.100.100.200"]
)
def test_mapped_ipv6_metadata_is_never_allowlistable(destination, isolated_store, monkeypatch):
    db, scope = isolated_store
    with pytest.raises(ValueError, match="metadata"):
        validate_allowlist_entry_syntax(destination)
    with pytest.raises(ValueError, match="metadata"):
        validate_allowlist_entry_syntax(destination + "/128")
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", (destination, 0, 0, 0))
        ],
    )
    result = scope.evaluate_target("ENG-2026-001", "example.com")
    assert not result.allowed and "metadata" in result.reason


def test_mapped_loopback_dns_requires_an_explicit_ip_rule(isolated_store, monkeypatch):
    db, scope = isolated_store
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::ffff:127.0.0.1", 0, 0, 0))
        ],
    )
    result = scope.evaluate_target("ENG-2026-001", "example.com")
    assert not result.allowed and "loopback" in result.reason
    db.add_allowlist_target("ENG-2026-001", "127.0.0.1", "Explicit local fixture", "fixture")
    assert scope.evaluate_target("ENG-2026-001", "example.com").allowed


def test_unspecified_and_noncanonical_ips_do_not_hide_destinations(isolated_store):
    db, scope = isolated_store
    assert normalize_target_input("2001:0db8:0000::1") == "2001:db8::1"
    for target in ("0.0.0.0", "::", "::ffff:0.0.0.0"):
        db.add_allowlist_target("ENG-2026-001", target, "Fixture", "fixture")
        assert not scope.evaluate_target("ENG-2026-001", target).allowed
