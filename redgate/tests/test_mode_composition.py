"""2.3 mode composition and the deterministic decision engine.

These tests never execute a tool and never contact a target. They pin the two
properties the prompt cares about:

* composing modes *widens the permitted capability set only* — the narrowest
  ceiling wins, mandatory obligations cannot be composed away, and expansion
  clauses are intersected rather than unioned;
* the decision engine is a rule engine with a stated basis. It proposes, it never
  executes, and it says so (``advisory_only``).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from gateway.capabilities import (
    SSL_TLS_MODE_ID,
    CapabilityError,
    CapabilityRegistry,
)
from gateway.capability_models import ApproachRequest, ComposeRequest
from gateway.workspace_models import MissionCreateRequest

CAPABILITIES = Path(__file__).resolve().parents[1] / "config" / "capabilities.yaml"


class _NullDB:
    """No admin toggle row: the manifest is authoritative."""

    def get_tool_policy(self, _name: str):  # noqa: ANN001 - mirrors Database
        return None


class _RestrictiveDB(_NullDB):
    def get_tool_policy(self, _name: str):  # noqa: ANN001 - mirrors Database
        return {"enabled": True, "allowed_params": {"modes": ["pentest"]}}


@pytest.fixture()
def registry() -> CapabilityRegistry:
    return CapabilityRegistry.from_file(CAPABILITIES)


# ---------------------------------------------------------------------------
# The sixth mode
# ---------------------------------------------------------------------------
def test_the_manifest_declares_six_modes_including_ssl_tls_analysis(registry):
    assert registry.mode_ids() == [
        "assessment",
        "bug_bounty",
        "ctf",
        "pentest",
        "ssl_tls_analysis",
        "vulnerability_discovery",
    ]
    assert SSL_TLS_MODE_ID in registry.mode_ids()
    assert registry.get_mode(SSL_TLS_MODE_ID).allows("tls_deep_analysis")


def test_ssl_tls_mode_treats_deep_analysis_as_mandatory(registry):
    mode = registry.get_mode(SSL_TLS_MODE_ID)
    assert "tls_deep_analysis" in mode.mandatory_capabilities
    assert mode.ceiling.max_hosts <= 8


# ---------------------------------------------------------------------------
# Composition: ceilings, obligations, clauses
# ---------------------------------------------------------------------------
def test_composition_is_declared_with_six_named_combinations(registry):
    spec = registry.composition_spec()
    assert spec["enabled"] is True
    assert spec["max_modes"] == 3
    ids = {row["id"] for row in registry.composition_allowed()}
    assert ids == {
        "vuln_plus_tls",
        "bug_bounty_plus_tls",
        "pentest_plus_tls",
        "assessment_plus_tls",
        "pentest_plus_bounty_reporting",
        "discovery_plus_assessment",
    }


def test_composition_takes_the_narrowest_ceiling_never_the_widest(registry):
    composed, audit = registry.compose(["pentest", "ssl_tls_analysis"])
    parts = [registry.get_mode("pentest"), registry.get_mode(SSL_TLS_MODE_ID)]
    assert composed.ceiling.max_hosts == min(p.ceiling.max_hosts for p in parts)
    assert composed.ceiling.max_actions == min(p.ceiling.max_actions for p in parts)
    assert composed.ceiling.max_seconds == min(p.ceiling.max_seconds for p in parts)
    assert audit["rule"].startswith("narrowest ceiling wins")


def test_composition_unions_capabilities_and_keeps_every_obligation(registry):
    composed, audit = registry.compose(["bug_bounty", "ssl_tls_analysis"])
    for part in ("bug_bounty", "ssl_tls_analysis"):
        mode = registry.get_mode(part)
        assert mode.capabilities <= composed.capabilities
        assert mode.mandatory_capabilities <= composed.mandatory_capabilities
    assert "tls_deep_analysis" in composed.mandatory_capabilities
    assert composed.allows("tls_deep_analysis")
    assert audit["capabilities_removed"] == []


def test_composition_intersects_expansion_clauses(registry):
    composed, audit = registry.compose(["pentest", "ssl_tls_analysis"])
    expected = set(registry.get_mode("pentest").expansion_clauses) & set(
        registry.get_mode(SSL_TLS_MODE_ID).expansion_clauses
    )
    assert set(composed.expansion_clauses) == expected
    assert set(audit["expansion_clauses"]) == expected


def test_composition_requires_at_least_two_modes(registry):
    with pytest.raises(CapabilityError, match="at least two"):
        registry.compose(["pentest"])


def test_composition_is_capped_by_max_modes(registry):
    with pytest.raises(CapabilityError, match="At most 3"):
        registry.compose(["pentest", "bug_bounty", SSL_TLS_MODE_ID, "assessment"])


def test_composition_rejects_an_unknown_mode(registry):
    with pytest.raises(CapabilityError):
        registry.compose(["pentest", "not_a_mode"])


def test_a_named_alias_resolves_through_get_mode_to_the_canonical_id(registry):
    assert registry.is_composition_alias("pentest_plus_tls") is True
    assert registry.is_composition_alias("pentest") is False
    mode = registry.get_mode("pentest_plus_tls")
    assert mode.mode_id == "pentest+ssl_tls_analysis"
    assert mode.allows("tls_deep_analysis")
    assert registry.capabilities_for("pentest_plus_tls") == registry.capabilities_for(
        "pentest+ssl_tls_analysis"
    )


def test_a_named_alias_expands_to_its_parts(registry):
    composed, audit = registry.compose(["pentest_plus_tls"])
    assert audit["mode_ids"] == ["pentest", SSL_TLS_MODE_ID]
    assert composed.mode_id == f"pentest+{SSL_TLS_MODE_ID}"


# ---------------------------------------------------------------------------
# parse_mode / enforce_ceiling / resolve / capabilities_for
# ---------------------------------------------------------------------------
def test_parse_mode_accepts_a_plain_id_a_plus_string_and_a_list(registry):
    assert registry.parse_mode("ctf").mode_id == "ctf"
    assert registry.parse_mode("ctf+ssl_tls_analysis").mode_id == (
        f"ctf+{SSL_TLS_MODE_ID}"
    )
    assert registry.parse_mode(["ctf", SSL_TLS_MODE_ID]).mode_id == (
        f"ctf+{SSL_TLS_MODE_ID}"
    )
    with pytest.raises(CapabilityError):
        registry.parse_mode("")


def test_a_composed_ceiling_is_enforced_against_the_request(registry):
    db = _NullDB()
    registry.enforce_ceiling(
        db, "ctf+ssl_tls_analysis", target_count=2, max_actions=8, max_seconds=600
    )
    with pytest.raises(CapabilityError, match="allows at most"):
        registry.enforce_ceiling(
            db, "ctf+ssl_tls_analysis", target_count=99, max_actions=8, max_seconds=600
        )


def test_an_admin_allow_list_blocks_a_composed_mode_if_any_part_is_missing(registry):
    ok, _ = registry.mode_enabled(_RestrictiveDB(), "pentest")
    assert ok is True
    allowed, reason = registry.mode_enabled(_RestrictiveDB(), "pentest+ssl_tls_analysis")
    assert allowed is False
    assert "ssl_tls_analysis" in reason and "composed" in reason


def test_capabilities_for_accepts_a_composed_spec(registry):
    caps = registry.capabilities_for("pentest+ssl_tls_analysis")
    assert "tls_deep_analysis" in caps
    assert "script_validation_sandbox" in caps


def test_resolve_returns_a_decision_for_a_composed_mode(registry):
    allowed = registry.resolve(_NullDB(), "pentest+ssl_tls_analysis", "tls_deep_analysis")
    assert allowed.allowed is True
    denied = registry.resolve(_NullDB(), "ssl_tls_analysis", "password_attack")
    assert denied.allowed is False
    assert "does not include" in denied.reason


# ---------------------------------------------------------------------------
# API contracts accept composed ids
# ---------------------------------------------------------------------------
def test_request_models_accept_a_composed_mode_id():
    mission = MissionCreateRequest.model_validate(
        {
            "engagement_id": "eng-abc123",
            "name": "composed mission",
            "targets": ["198.51.100.10"],
            "mode_id": "pentest+ssl_tls_analysis",
        }
    )
    assert mission.mode_id == "pentest+ssl_tls_analysis"
    assert ComposeRequest(modes=["pentest", "ssl_tls_analysis"]).modes
    assert ApproachRequest(
        engagement_id="eng-abc123",
        target="198.51.100.10",
        mode_id="pentest+ssl_tls_analysis",
    ).mode_id == "pentest+ssl_tls_analysis"


def test_the_mode_id_pattern_still_rejects_smuggled_input():
    """A composed id must not become a way to smuggle free text past the schema."""
    for bad in ("Pentest", "pentest+", "+pentest", "pentest++tls", "a", "pentest tls"):
        with pytest.raises(ValueError):
            ComposeRequest(modes=[bad])


# ---------------------------------------------------------------------------
# Decision engine
# ---------------------------------------------------------------------------
def test_the_decision_engine_prioritises_tls_for_a_tls_target(registry):
    plan = registry.decide_approach(
        target="198.51.100.10",
        observations={"https": True, "server_header": "nginx"},
        mode_id="pentest+ssl_tls_analysis",
    )
    assert plan["advisory_only"] is True
    assert "tls_or_https" in plan["signals"]
    tools = [step["tool"] for step in plan["recommended"]]
    assert tools[0] in {"testssl.sh", "tls_inspect"}
    # The TLS step is present, so the "mandatory step missing" note must not fire.
    assert plan["mode"]["mandatory_capabilities"] == ["tls_deep_analysis"]
    assert plan["notes"] == []
    assert plan["next_call"].startswith("POST /api/v1/offensive/tools/run")


def test_the_decision_engine_falls_back_to_recon_without_signals(registry):
    plan = registry.decide_approach(target="198.51.100.10")
    assert plan["signals"] == ["no_signal"]
    assert plan["recommended"][0]["tool"] == "nmap"
    assert plan["mode"] is None


def test_the_decision_engine_skips_work_that_already_ran(registry):
    plan = registry.decide_approach(
        target="198.51.100.10",
        observations={"https": True},
        history=[{"tool": "testssl.sh"}],
    )
    assert "testssl.sh" not in [step["tool"] for step in plan["recommended"]]
    assert [step["tool"] for step in plan["skipped_as_already_run"]] == ["testssl.sh"]


def test_every_recommendation_names_the_policy_row_that_governs_it(registry):
    plan = registry.decide_approach(
        target="198.51.100.10",
        observations={"https": True, "forms": True, "db_error": True},
    )
    assert plan["recommended"]
    for step in plan["recommended"]:
        assert step["policy"].startswith("tool:")
        assert step["evidence"] in plan["signals"]
        assert isinstance(step["priority"], int)


def test_the_decision_engine_is_deterministic(registry):
    kwargs = dict(
        target="198.51.100.10",
        observations={"https": True, "forms": True},
        mode_id="pentest",
    )
    assert registry.decide_approach(**kwargs) == registry.decide_approach(**kwargs)
