"""Unit tests for allowlist policy, DNS rebinding guard, append-only audit log,
SHA-256 hash chaining, quota enforcement, LLM secret scrubbing, and Two-Person approval.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from gateway.config_loader import load_platform_config, seed_database_from_config
from gateway.db import Database
from gateway.llm_proxy import LLMProxyError, LLMProxyGateway
from gateway.policy import ScopePolicyEngine, validate_allowlist_entry_syntax
from mcp_server.tools import ToolParamValidationError, validate_tool_params

CONFIG_DIR = Path(__file__).resolve().parent.parent / "config"


@pytest.fixture()
def seeded_db(tmp_path: Path) -> tuple[Database, ScopePolicyEngine]:
    cfg = load_platform_config(CONFIG_DIR)
    db = Database(tmp_path / "test_redgate.db")
    seed_database_from_config(db, cfg)
    scope = ScopePolicyEngine(db, cfg.allowlist.get("dns_security"))
    return db, scope


def test_allowlist_ip_cidr_wildcard_and_engagement_isolation(
    seeded_db: tuple[Database, ScopePolicyEngine],
) -> None:
    _, scope = seeded_db

    # Allowed inside CIDR 192.0.2.0/24
    res_cidr = scope.evaluate_target("ENG-2026-001", "192.0.2.42", resolve_dns=False)
    assert res_cidr.allowed is True
    assert res_cidr.matched_rule == "192.0.2.0/24"

    # Allowed wildcard subdomain *.lab.example (not bare lab.example, not evil-lab.example)
    assert scope.evaluate_target("ENG-2026-001", "api.lab.example", resolve_dns=False).allowed is True
    assert scope.evaluate_target("ENG-2026-001", "lab.example", resolve_dns=False).allowed is False
    assert scope.evaluate_target("ENG-2026-001", "evil-lab.example", resolve_dns=False).allowed is False

    # Engagement scope bleed check: 127.0.0.1 is in ENG-LOCAL-LAB, NOT in ENG-2026-001
    assert scope.evaluate_target("ENG-LOCAL-LAB", "127.0.0.1", resolve_dns=False).allowed is True
    assert scope.evaluate_target("ENG-2026-001", "127.0.0.1", resolve_dns=False).allowed is False

    # Out-of-scope public IP and cloud metadata IP always denied
    assert scope.evaluate_target("ENG-2026-001", "203.0.113.55", resolve_dns=False).allowed is False
    meta = scope.evaluate_target("ENG-2026-001", "169.254.169.254", resolve_dns=False)
    assert meta.allowed is False
    assert "metadata" in (meta.reason or "").lower()

    # Admin cannot add cloud metadata IP or overly broad /8 CIDR
    with pytest.raises(ValueError, match="metadata"):
        validate_allowlist_entry_syntax("169.254.169.254")
    with pytest.raises(ValueError, match="/16"):
        validate_allowlist_entry_syntax("10.0.0.0/8")


def test_expired_engagement_window_rejected(seeded_db: tuple[Database, ScopePolicyEngine]) -> None:
    db, scope = seeded_db
    db.upsert_engagement(
        engagement_id="ENG-EXPIRED",
        name="Past Engagement",
        description="Expired RoE",
        valid_from="2024-01-01T00:00:00Z",
        valid_until="2024-02-01T00:00:00Z",
        active=True,
    )
    db.seed_allowlist_target("ENG-EXPIRED", "192.0.2.99", "old host", "admin-kaveh")
    res = scope.evaluate_target("ENG-EXPIRED", "192.0.2.99", resolve_dns=False)
    assert res.allowed is False
    assert "window" in (res.reason or "").lower()


def test_audit_log_append_only_triggers_and_hash_chain(
    seeded_db: tuple[Database, ScopePolicyEngine],
) -> None:
    db, _ = seeded_db
    e1 = db.write_audit_log(
        engagement_id="ENG-2026-001",
        operator_id="op-alice",
        target="198.51.100.10",
        tool_or_script="tool:http_headers",
        status="completed",
        exit_code=0,
        stdout_summary="HTTP 200 OK",
    )
    e2 = db.write_audit_log(
        engagement_id="ENG-2026-001",
        operator_id="op-alice",
        target="203.0.113.1",
        tool_or_script="tool:nmap",
        status="rejected",
        rejection_reason="Target out of allowlist",
    )
    assert e2["prev_hash"] == e1["entry_hash"]

    verification = db.verify_audit_chain()
    assert verification["valid"] is True
    assert verification["checked_entries"] == 2
    assert verification["head_hash"] == e2["entry_hash"]

    # Attempt direct SQL UPDATE and DELETE — both must fail via DB trigger!
    with db.connection() as conn:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            conn.execute("UPDATE audit_log SET status = 'tampered' WHERE id = ?", (e1["id"],))
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            conn.execute("DELETE FROM audit_log WHERE id = ?", (e1["id"],))


def test_two_person_approval_and_quota_exhaustion(
    seeded_db: tuple[Database, ScopePolicyEngine],
) -> None:
    db, _ = seeded_db

    apr = db.enqueue_approval(
        engagement_id="ENG-2026-001",
        request_type="tool_scan",
        target="198.51.100.10",
        tool_or_script="nmap",
        payload={"tool_name": "nmap", "params": {"flags": ["-sV", "-T2"], "ports": "80"}},
        requested_by="op-alice",
    )
    # Self-approval forbidden
    with pytest.raises(PermissionError, match="Two-Person Rule"):
        db.decide_approval(apr["request_id"], approved_by="op-alice", decision="approved")

    # Separate approver succeeds
    decided = db.decide_approval(
        apr["request_id"], approved_by="lead-sara", decision="approved", note="RoE verified"
    )
    assert decided["status"] == "approved"
    assert decided["approved_by"] == "lead-sara"

    # Quota exhaustion test
    ok1, _, _ = db.check_and_consume_quota("op-temp", "daily", max_calls=2, max_tokens=500, calls_delta=2)
    assert ok1 is True
    ok2, reason, _ = db.check_and_consume_quota("op-temp", "daily", max_calls=2, max_tokens=500, calls_delta=1)
    assert ok2 is False
    assert "exhausted" in reason.lower()


def test_mcp_param_whitelist_and_llm_secret_scrubber() -> None:
    # Valid low-noise nmap passes and preserves -T2
    clean = validate_tool_params("nmap", {"flags": ["-sV", "-T2", "--open"], "ports": "80,443"})
    assert clean["flags"] == ["-sV", "-T2", "--open"]

    # Aggressive nmap -T4 sits outside the default policy row, so it is refused
    # until an engagement opts into tool:nmap_aggressive.
    with pytest.raises(ToolParamValidationError):
        validate_tool_params("nmap", {"flags": ["-sV", "-T4"], "ports": "80"})
    assert validate_tool_params(
        "nmap", {"flags": ["-sV", "-T4"], "ports": "80"},
        {"allowed_flags": ["-sV", "-T4"]},
    )["flags"] == ["-sV", "-T4"]

    # sqlmap --os-shell is refused outright: no posture reaches it.
    with pytest.raises(ToolParamValidationError, match="refused"):
        validate_tool_params("sqlmap", {"flags": ["--batch", "--os-shell"]})
    with pytest.raises(ToolParamValidationError, match="refused"):
        validate_tool_params(
            "sqlmap", {"flags": ["--os-shell"]}, {"allowed_flags": ["--os-shell"]}
        )

    # LLM secret scrubbing & exploit objective guard
    cfg = load_platform_config(CONFIG_DIR)
    proxy = LLMProxyGateway(cfg.llm_proxy)
    dummy_key = "sk-" + "dummyScrubFixtureOnly123456"
    dummy_pw = "DummyFixture99!"
    raw = f"Check headers using api_key={dummy_key} and password={dummy_pw}"
    scrubbed, rules = proxy.scrub_secrets(raw)
    assert "sk-abcdef" not in scrubbed
    assert "SuperSecret99" not in scrubbed
    assert "[REDACTED_SECRET]" in scrubbed
    assert len(rules) >= 1

    with pytest.raises(LLMProxyError, match="non-exploitation"):
        proxy.check_objective_policy("Write a reverse shell payload to evade EDR")
