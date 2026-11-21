"""2.3.1: widened catalogue, hunting roster, intel engine, coverage and diffing.

Nothing in this module contacts a network target or executes a tool. The point of
the suite is that every new claim is checkable *without* a live engagement:
refused flags are refused by the builder, an uninstalled binary is `unavailable`,
a coverage record without a check is rejected, and a CVSS v4 vector is refused
rather than approximated.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest
import yaml

from gateway.agents_registry import AGENT_ROLES, get_role, roles_for_capabilities
from gateway.coverage import (
    CoverageError,
    CoverageLedger,
    ResponseTracker,
    shape_of,
)
from gateway.db import Database
from gateway.intel_engine import (
    CLASS_INDEX,
    VULN_CLASSES,
    IntelError,
    OutcomeStore,
    allocate_budget,
    brain_signals_from_entries,
    chain_plan,
    cvss_base,
    evidence_score,
    exhaustion_gate,
    rank_classes,
    rank_surface,
)
from gateway.skills import validate_skill_spec
from mcp_server.catalog import (
    BASELINE_REFUSED_FLAGS,
    CATALOG,
    ArgvBuildError,
    build_argv,
    category_counts,
    get_entry,
    takes_artifact,
)

ROOT = Path(__file__).resolve().parents[1]
ENG = "ENG-2026-001"


@pytest.fixture()
def db() -> Database:
    path = Path(tempfile.mkdtemp()) / "t.db"
    database = Database(path)
    with database.transaction() as conn:
        conn.execute(
            """INSERT OR IGNORE INTO engagements
               (id, name, description, valid_from, valid_until, active, created_at)
               VALUES (?,?,?,?,?,1,?)""",
            (
                ENG, "test", "test", "2026-01-01T00:00:00Z",
                "2027-12-31T23:59:59Z", "2026-01-01T00:00:00Z",
            ),
        )
    return database


# ---------------------------------------------------------------------------
# Catalogue: 39 new tools, all governed
# ---------------------------------------------------------------------------
NEW_FAMILIES = {
    "mobile": 9,
    "wireless": 14,
    "forensics": 16,
}


def test_the_three_named_surfaces_are_now_in_the_catalogue():
    counts = category_counts()
    for family, expected in NEW_FAMILIES.items():
        assert counts.get(family) == expected, f"{family}: {counts.get(family)} != {expected}"
    assert len(CATALOG) == 183
    assert len(CATALOG) == sum(counts.values())


def test_new_tool_families_take_artifacts_or_listed_devices_not_hosts():
    # An image or an APK is a file. Passing a hostname to binwalk is a category
    # error, and it must be refused as one rather than scope-checked.
    for name in ("binwalk", "volatility3", "bulk_extractor", "apktool", "jadx", "aapt"):
        assert takes_artifact(get_entry(name)) is True, name
    for name in ("adb", "frida", "airodump-ng", "bettercap"):
        assert takes_artifact(get_entry(name)) is False, name
    with pytest.raises(ArgvBuildError, match="artifact root"):
        build_argv("binwalk", "../../etc/passwd", flags=[], allowed_flags=[], refused_flags=[])


def test_wireless_misuse_flags_are_refused_before_any_policy_question():
    cases = {
        "aireplay-ng": "--deauth",
        "mdk4": "d",
        "eaphammer": "--hostile-portal",
        "adb": "install",
        "frida": "--spawn",
    }
    for tool, flag in cases.items():
        refused = BASELINE_REFUSED_FLAGS[tool]
        with pytest.raises(ArgvBuildError):
            build_argv(
                tool,
                "artifact.bin" if takes_artifact(get_entry(tool)) else "198.51.100.10",
                flags=[flag],
                allowed_flags=[flag],
                refused_flags=list(refused),
            )


def test_wireless_tools_are_marked_root_dependent():
    for name in ("airmon-ng", "airodump-ng", "wifite", "bettercap", "hostapd-wpe"):
        assert get_entry(name).requires_root is True, name


def test_no_new_entry_is_writable_text_that_pretends_to_run():
    # Every entry names either a binary, an in-process implementation or a python
    # library; none is a shell string.
    for entry in CATALOG.values():
        assert not any(ch in entry.binary for ch in ";|&$`"), entry.binary


# ---------------------------------------------------------------------------
# Roster and skills
# ---------------------------------------------------------------------------
def test_the_roster_grew_and_every_role_can_be_refuted():
    assert len(AGENT_ROLES) == 70
    for role in AGENT_ROLES:
        assert role.refutation.strip(), f"{role.role_id} has no refutation"
        assert role.objective.strip()
        assert role.capabilities, f"{role.role_id} declares no capability"


def test_the_hunting_roles_are_present_and_advisory():
    for role_id in (
        "xss-hunter",
        "sqli-hunter",
        "idor-hunter",
        "ssrf-hunter",
        "ssti-hunter",
        "xxe-hunter",
        "auth-bypass-analyst",
        "graphql-auditor",
        "mobile-app-analyst",
        "wireless-survey-analyst",
        "forensics-examiner",
        "coverage-auditor",
        "intel-ranker",
    ):
        role = get_role(role_id)
        assert role.to_dict()["can_execute"] is False
        assert role.to_dict()["can_approve"] is False
        assert role.to_dict()["can_widen_scope"] is False


def test_a_role_is_withheld_when_the_mode_lacks_its_capability():
    available = {r.role_id for r in roles_for_capabilities({"validation"})}
    assert "coverage-auditor" in available
    assert "intel-ranker" not in available


def test_every_skill_file_validates_against_the_playbook_schema():
    files = sorted((ROOT / "skills").glob("*.yaml"))
    assert len(files) == 24
    for path in files:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        spec = validate_skill_spec(raw)
        assert 1 <= len(spec["steps"]) <= 6
        for step in spec["steps"]:
            assert step["tool"] in {
                "dns_lookup", "tcp_port_probe", "http_headers", "tls_inspect",
                "sandbox_script", "nmap",
            }
        assert spec["report_focus"], f"{path.name} states no report focus"


def test_a_hunting_skill_cannot_smuggle_an_approval_gated_tool():
    raw = yaml.safe_load((ROOT / "skills" / "xss_hunt.yaml").read_text(encoding="utf-8"))
    raw["steps"].append({"stage": "run_dalfox", "tool": "sqlmap", "params": {}})
    with pytest.raises(Exception, match="prohibited"):
        validate_skill_spec(raw)


# ---------------------------------------------------------------------------
# Intel engine: ranking
# ---------------------------------------------------------------------------
def test_ranking_states_every_term_and_is_deterministic():
    kwargs = dict(
        tech_stack=["nginx", "spa"],
        observations=["forms", "api_listing"],
        hacktivity={"xss": 0.9},
        outcomes=[{"vuln_class": "xss", "result": "confirmed"}],
    )
    first = rank_classes(**kwargs)
    assert first == rank_classes(**kwargs)
    assert first["advisory_only"] is True
    assert "no model call" in first["basis"]
    for row in first["classes"]:
        assert set(row["terms"]) >= {"prior", "tech_signal", "hacktivity_roi"}
        assert row["reasons"]
        assert row["evidence_required"]


def test_a_refuting_brain_entry_lowers_a_class_that_signals_raised():
    ranks = rank_classes(observations=["forms", "reflected_param"])["classes"]
    raised = next(c for c in ranks if c["vuln_class"] == "xss")
    assert raised["score"] > 0
    lowered = rank_classes(
        observations=["forms", "reflected_param"],
        brain_signals=[{"vuln_class": "xss", "stance": "refute"}] * 2,
        # A refuted class legitimately falls out of a shortlist; ask for the full
        # ranking so the score itself is what is compared.
        limit=32,
    )
    xss = next(c for c in lowered["classes"] if c["vuln_class"] == "xss")
    assert xss["score"] < raised["score"]
    assert any("refuting" in reason for reason in xss["reasons"])


def test_an_unknown_class_or_signal_is_refused_not_ignored():
    with pytest.raises(IntelError, match="Unknown vulnerability class"):
        rank_classes(hacktivity={"not_a_class": 0.5})


def test_every_declared_class_is_rankable():
    for cls in VULN_CLASSES:
        assert cls["id"] in CLASS_INDEX
        assert cls["evidence"]


# ---------------------------------------------------------------------------
# Intel engine: surface, budget, exhaustion, chain, evidence, CVSS
# ---------------------------------------------------------------------------
def test_surface_buckets_put_authenticated_object_endpoints_first():
    result = rank_surface(
        [
            {"endpoint": "/api/v1/orders/{id}", "traits": ["auth", "object_reference"]},
            {"endpoint": "/search", "traits": ["search"]},
            {"endpoint": "/static/app.js", "traits": ["static"]},
        ]
    )
    assert result["surface"][0]["endpoint"] == "/api/v1/orders/{id}"
    assert result["surface"][0]["bucket"] == "P1"
    assert result["buckets"].get("Kill") == 1
    with pytest.raises(IntelError, match="Unknown surface trait"):
        rank_surface([{"endpoint": "/x", "traits": ["made_up"]}])


def test_budget_allocation_sums_to_at_most_the_allowance():
    classes = rank_classes(observations=["forms", "api_listing"])["classes"]
    result = allocate_budget(classes, minutes=60, tokens=50000)
    assert sum(a["budget_minutes"] for a in result["allocation"]) <= 60
    assert sum(a["budget_tokens"] for a in result["allocation"]) <= 50000
    assert all(a["budget_minutes"] >= 1 for a in result["allocation"])


def test_exhaustion_requires_recorded_work():
    assert exhaustion_gate({"attempts": 0})["ok"] is False
    ok = exhaustion_gate({"attempts": 3, "evidence_items": 2, "variants_tried": 2})
    assert ok["ok"] is True
    blocked = exhaustion_gate(
        {"attempts": 5, "evidence_items": 3, "variants_tried": 3, "unexplained_anomaly": True}
    )
    assert blocked["ok"] is False
    assert "anomaly" in blocked["reason"]


def test_chain_plan_escalates_from_what_is_already_proven():
    result = chain_plan(["db_read"])
    assert result["chain"][0]["gained_capability"] == "account_takeover"
    assert result["chain"][0]["terminal_impact"] == "critical"
    assert chain_plan(["not_a_capability"])["chain"] == []


def test_evidence_score_names_the_gaps_instead_of_averaging_them():
    thin = evidence_score({"steps": ["open the page"]})
    assert thin["decision"] == "do_not_submit"
    assert "request_response_captured" in thin["failed"]
    strong = evidence_score(
        {
            "steps": ["login as A", "request B's object"],
            "request": "GET /orders/2",
            "response": "200 {...}",
            "impact": "read another tenant's order",
            "remediation": "enforce object-level authorisation",
            "in_scope": True,
            "redacted": True,
            "reproduced_by": "op-bob",
        }
    )
    assert strong["decision"] == "submit"
    assert strong["failed"] == []


@pytest.mark.parametrize(
    "vector,score",
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N", 7.2),
        ("CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N", 2.6),
        ("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", 0.0),
    ],
)
def test_cvss_31_matches_the_reference_calculator(vector, score):
    result = cvss_base(vector)
    assert result["base_score"] == score
    assert result["version"] == "3.1"


def test_other_cvss_versions_are_refused_rather_than_approximated():
    for vector in (
        "CVSS:4.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P",
    ):
        with pytest.raises(IntelError, match="not scored here"):
            cvss_base(vector)
    with pytest.raises(IntelError, match="Invalid value"):
        cvss_base("CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")


# ---------------------------------------------------------------------------
# Outcomes (the only learning input)
# ---------------------------------------------------------------------------
def test_outcomes_are_append_only_and_feed_the_ranking(db):
    store = OutcomeStore(db)
    row = store.record(
        engagement_id=ENG, vuln_class="idor", result="confirmed", operator_id="op-alice"
    )
    assert row["outcome_id"].startswith("int-")
    second = store.record(engagement_id=ENG, vuln_class="idor", result="rejected")
    assert second["outcome_id"] != row["outcome_id"]
    assert len(store.list(ENG)) == 2
    summary = store.summary(ENG)
    assert summary["by_class"]["idor"] == {"confirmed": 1, "rejected": 1}
    ranked = rank_classes(outcomes=store.list(ENG))
    idor = next(c for c in ranked["classes"] if c["vuln_class"] == "idor")
    assert any("outcome" in reason for reason in idor["reasons"])


def test_an_unknown_outcome_is_refused(db):
    with pytest.raises(IntelError, match="Unknown vulnerability class"):
        OutcomeStore(db).record(engagement_id=ENG, vuln_class="x", result="confirmed")
    with pytest.raises(IntelError, match="result must be"):
        OutcomeStore(db).record(engagement_id=ENG, vuln_class="xss", result="probably")


def test_brain_entries_only_count_when_they_name_a_class_and_stance():
    """Brain rows are (kind, content, verdict); a signal needs both halves."""
    signals = brain_signals_from_entries(
        [
            {"kind": "verdict", "content": json.dumps({"vuln_class": "xss"}), "verdict": "refuted"},
            {"kind": "hypothesis", "content": "idor is likely here", "verdict": "supported"},
            {"kind": "verdict", "content": "xss again", "verdict": ""},
            {"kind": "note", "content": "no class mentioned", "verdict": "supported"},
            {"kind": "verdict", "content": "not json at all", "verdict": "supported"},
        ]
    )
    assert signals == [
        {"vuln_class": "xss", "stance": "refute"},
        {"vuln_class": "idor", "stance": "support"},
    ]


def test_a_refuted_brain_verdict_reaches_the_ranking_through_the_db(db):
    """The brain is read with its real columns, so the join cannot rot silently."""
    from gateway.auth import OperatorPrincipal
    from gateway.hunt_loop import HuntLoopService

    principal = OperatorPrincipal(
        operator_id="op-alice",
        display_name="Alice",
        role="operator",
        rate_limit_rpm=60,
        quota_period="daily",
        quota_max_calls=100,
        quota_max_tokens=100000,
        allowed_engagements=(ENG,),
    )
    loops = HuntLoopService(db=db)
    loop = loops.open_loop(
        principal=principal,
        engagement_id=ENG,
        role_id="xss-hunter",
        hypothesis="reflected parameter is rendered unencoded",
    )
    loops.append_brain(
        principal=principal,
        engagement_id=ENG,
        loop_id=loop["loop_id"],
        kind="verdict",
        content=json.dumps({"vuln_class": "xss"}),
        verdict="refuted",
    )
    with db.connection() as conn:
        rows = [
            dict(r)
            for r in conn.execute(
                "SELECT kind, content, verdict FROM brain_entries WHERE engagement_id=?",
                (ENG,),
            ).fetchall()
        ]
    assert brain_signals_from_entries(rows) == [{"vuln_class": "xss", "stance": "refute"}]


# ---------------------------------------------------------------------------
# Coverage ledger
# ---------------------------------------------------------------------------
def test_a_covered_surface_must_name_a_check(db):
    ledger = CoverageLedger(db)
    with pytest.raises(CoverageError, match="must name at least one check"):
        ledger.record(engagement_id=ENG, surface="https://a.example", checks=[])
    row = ledger.record(
        engagement_id=ENG,
        surface="https://a.example",
        checks=["hsts", "csp"],
        depth="deep",
        operator_id="op-alice",
    )
    assert row["checks"] == ["hsts", "csp"]


def test_a_skipped_surface_must_state_why(db):
    ledger = CoverageLedger(db)
    with pytest.raises(CoverageError, match="state why"):
        ledger.record(engagement_id=ENG, surface="x", status="skipped")
    row = ledger.record(
        engagement_id=ENG, surface="x", status="skipped", skip_reason="host decommissioned"
    )
    assert row["skip_reason"] == "host decommissioned"


def test_coverage_upserts_and_merges_checks(db):
    ledger = CoverageLedger(db)
    ledger.record(engagement_id=ENG, surface="https://a.example", checks=["hsts"])
    ledger.record(engagement_id=ENG, surface="https://a.example", checks=["csp", "hsts"])
    row = ledger.get(ENG, "https://a.example")
    assert row["checks"] == ["hsts", "csp"]
    assert ledger.list(ENG)[0]["surface"] == "https://a.example"


def test_unrecorded_surfaces_are_reported_as_uncovered(db):
    ledger = CoverageLedger(db)
    ledger.record(engagement_id=ENG, surface="https://a.example", checks=["hsts"])
    summary = ledger.summary(ENG, expected=["https://a.example", "https://b.example"])
    assert summary["uncovered"] == ["https://b.example"]
    assert summary["coverage_ratio"] == 0.5
    assert summary["counts"]["covered"] == 1


def test_a_shallow_sweep_is_visible_in_the_summary(db):
    ledger = CoverageLedger(db)
    ledger.record(engagement_id=ENG, surface="https://a.example", checks=["title"], depth="shallow")
    assert ledger.summary(ENG)["shallow_only"] == ["https://a.example"]


def test_dropping_a_record_removes_it(db):
    ledger = CoverageLedger(db)
    ledger.record(engagement_id=ENG, surface="https://a.example", checks=["hsts"])
    assert ledger.drop(ENG, "https://a.example") is True
    assert ledger.get(ENG, "https://a.example") is None
    assert ledger.drop(ENG, "https://a.example") is False


# ---------------------------------------------------------------------------
# Response fingerprints
# ---------------------------------------------------------------------------
def test_shape_ignores_counters_and_whitespace_but_not_wording():
    a = shape_of("<html><title>Orders 12</title>  <p>Hello</p></html>")
    b = shape_of("<html><title>Orders 13</title>\n\n<p>Hello</p></html>")
    c = shape_of("<html><title>Orders 12</title><p>Goodbye</p></html>")
    assert a["body_sha256"] == b["body_sha256"]
    assert a["body_sha256"] != c["body_sha256"]
    # The title is hashed verbatim: it is the most frequently read signal, so a
    # changed title must surface even when the body shape is identical.
    assert a["title_sha256"] != b["title_sha256"]
    assert a["title"] == "Orders 12"


def test_two_observations_are_diffed_by_field_and_header(db):
    tracker = ResponseTracker(db)
    tracker.observe(
        engagement_id=ENG,
        asset="https://a.example",
        status_code=200,
        body="<title>Home</title>alpha",
        headers={"Strict-Transport-Security": "max-age=100", "Date": "Mon"},
    )
    tracker.observe(
        engagement_id=ENG,
        asset="https://a.example",
        status_code=200,
        body="<title>Home</title>beta",
        headers={"Date": "Tue"},
    )
    diff = tracker.diff(ENG, "https://a.example")
    assert diff["changed"] is True
    assert "body_sha256" in diff["field_changes"]
    assert "strict-transport-security" in diff["header_changes"]
    # A volatile header must never make a diff noisy.
    assert "date" not in diff["header_changes"]
    assert "re-verify" in diff["interpretation"]


def test_one_observation_is_not_a_comparison(db):
    tracker = ResponseTracker(db)
    tracker.observe(engagement_id=ENG, asset="https://a.example", body="x")
    diff = tracker.diff(ENG, "https://a.example")
    assert diff["changed"] is False
    assert diff["observations"] == 1


def test_an_invalid_observation_is_refused(db):
    tracker = ResponseTracker(db)
    with pytest.raises(CoverageError, match="status_code"):
        tracker.observe(engagement_id=ENG, asset="https://a.example", status_code=999)


# ---------------------------------------------------------------------------
# API wiring
# ---------------------------------------------------------------------------
def test_the_intel_routes_are_registered():
    import os

    os.environ.setdefault("REDGATE_DB_PATH", str(Path(tempfile.mkdtemp()) / "api.db"))
    from gateway.main import create_app

    paths = set(create_app().openapi()["paths"])
    for path in (
        "/api/v1/intel/classes",
        "/api/v1/intel/surface",
        "/api/v1/intel/budget",
        "/api/v1/intel/exhaustion",
        "/api/v1/intel/chain",
        "/api/v1/intel/evidence-score",
        "/api/v1/intel/cvss",
        "/api/v1/intel/outcomes",
        "/api/v1/coverage",
        "/api/v1/responses/observe",
        "/api/v1/responses/diff",
        "/api/v1/responses/history",
    ):
        assert path in paths, path
