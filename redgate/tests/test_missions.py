"""Durable, finite, owner-attributed missions and their projection/API contracts."""

from __future__ import annotations

import asyncio
import concurrent.futures
import datetime as dt
import json

import pytest
from pydantic import ValidationError

from gateway.auth import AuthManager
from gateway.workspace_models import MissionCreateRequest
from gateway.workspace_store import MissionBudgetExceeded, WorkspaceConflict, WorkspaceStore


async def test_planning_deduplicates_without_dns_or_target_contact(ws, monkeypatch):
    evaluate = ws.rt.scope.evaluate_target
    resolutions = []

    def guarded(engagement, target, resolve_dns=True):
        resolutions.append(resolve_dns)
        return evaluate(engagement, target, resolve_dns=resolve_dns)

    monkeypatch.setattr(ws.rt.scope, "evaluate_target", guarded)
    mission = ws.plan(targets=["unit.lab.example", "unit.lab.example"], name="  Lab baseline  ")
    assert mission["status"] == "draft"
    assert mission["name"] == "Lab baseline"
    assert len(mission["intents"]) == 1
    assert mission["used_actions"] == 0 and mission["deadline_at"] is None
    assert resolutions and not any(resolutions)
    assert ws.mcp.calls == ws.sandbox.calls == []
    assert ws.service.store.coverage("ENG-A") == {"total": 1, "tested": 0, "untested": 1}
    assert ws.service.asset_graph("ENG-A")["nodes"][0]["status"] == "untested"
    with pytest.raises(PermissionError):
        ws.plan(targets=["out-of-scope.invalid"])
    assert len(ws.service.store.list_missions("ENG-A")) == 1


@pytest.mark.parametrize(
    "change",
    [
        {"targets": []},
        {"targets": ["127.0.0.1"] * 9},
        {"targets": ["http://127.0.0.1/"]},
        {"targets": ["127.0.0.1;id"]},
        {"max_actions": 65},
        {"max_actions": 0},
        {"max_seconds": 1801},
        {"name": "   "},
        {"goal": "       "},
        {"unknown": "field"},
    ],
)
def test_mission_models_reject_unbounded_or_ambiguous_plans(change):
    with pytest.raises(ValidationError):
        MissionCreateRequest(
            **{"engagement_id": "ENG-A", "name": "Fixture", "targets": ["127.0.0.1"], **change}
        )


async def test_mission_runs_are_durable_pinned_owned_and_exportable(ws):
    mission = ws.plan(targets=["127.0.0.1", "127.0.0.2"], name="<baseline> review")
    started = await ws.service.start(mission["mission_id"], ws.admin)
    done = await ws.settled(mission["mission_id"])
    assert done["status"] == "completed", done
    assert done["used_actions"] == 6  # HTTP + synthesis + evidence for each target.
    assert all(
        i["status"] == "completed" and i["attempts"] == 1 and i["run_id"] for i in done["intents"]
    )
    assert all(c["params"]["method"] == "HEAD" for c in ws.mcp.calls)
    assert started["deadline_at"] == done["deadline_at"]
    quota = ws.db.get_or_init_quota("owner", "daily", 1000, 1000000)
    assert quota["used_calls"] == 6
    assert ws.db.get_or_init_quota("admin", "daily", 1000, 1000000)["used_calls"] == 0
    evidence = ws.service.store.list_evidence("ENG-A", mission_id=mission["mission_id"])
    assert len(evidence) == 2 and all(e["integrity_valid"] for e in evidence)
    assert ws.service.store.coverage("ENG-A") == {"total": 4, "tested": 4, "untested": 0}
    graph = ws.service.exploration_graph(done)
    ids = {node["id"] for node in graph["nodes"]}
    assert all(e["source"] in ids and e["target"] in ids for e in graph["edges"])
    assert any(n.get("retest_supported") for n in graph["nodes"])
    assert any(n["kind"] == "evidence" for n in graph["nodes"])
    base = f"/api/v1/missions/{mission['mission_id']}"
    report = await ws.client.get(base + "/report.md", headers=ws.headers["owner"])
    assert report.status_code == 200 and "&lt;baseline&gt;" in report.text
    assert report.headers["cache-control"] == "no-store"
    exported = await ws.client.get(base + "/export.json", headers=ws.headers["owner"])
    assert exported.status_code == 200
    assert exported.json()["format"] == "redgate-workspace/2.1"
    assert len(exported.json()["runs"]) == 2
    assert len(exported.json()["retests"]) == 4
    assert ws.db.verify_audit_chain()["valid"] is True


async def test_budget_is_reserved_before_io_and_never_refunded(ws):
    mission = ws.plan(max_actions=1)
    await ws.service.start(mission["mission_id"], ws.owner)
    done = await ws.settled(mission["mission_id"])
    assert done["status"] == "budget_exhausted" and done["used_actions"] == 1
    assert done["intents"][0]["status"] == "failed"
    assert len(ws.mcp.calls) == 1 and ws.sandbox.calls == []
    with pytest.raises(WorkspaceConflict):
        await ws.service.start(mission["mission_id"], ws.owner)


async def test_quota_failure_stops_contact_but_keeps_action_reservation(ws):
    ws.db.get_or_init_quota("owner", "daily", 0, 1000000)
    mission = ws.plan()
    await ws.service.start(mission["mission_id"], ws.owner)
    done = await ws.settled(mission["mission_id"])
    assert done["status"] == "failed" and done["used_actions"] == 1
    assert ws.mcp.calls == ws.sandbox.calls == []


async def test_pause_drains_intent_resume_never_replays_completed_work(ws):
    ws.mcp.block = asyncio.Event()
    mission = ws.plan(targets=["127.0.0.1", "127.0.0.2"], capture_evidence=False)
    await ws.service.start(mission["mission_id"], ws.owner)
    await asyncio.wait_for(ws.mcp.entered.wait(), 2)
    assert ws.service.store.control(mission["mission_id"], "pause")["status"] == "pausing"
    ws.mcp.block.set()
    paused = await ws.settled(mission["mission_id"])
    assert paused["status"] == "paused"
    assert [i["status"] for i in paused["intents"]] == ["completed", "pending"]
    first_run = paused["intents"][0]["run_id"]
    await ws.service.start(mission["mission_id"], ws.admin)
    done = await ws.settled(mission["mission_id"])
    assert done["status"] == "completed" and len(ws.mcp.calls) == 2
    assert done["intents"][0]["run_id"] == first_run
    assert [i["attempts"] for i in done["intents"]] == [1, 1]
    assert done["deadline_at"] == paused["deadline_at"]
    assert done["used_actions"] == 4


async def test_cancel_stops_at_next_action_and_never_starts_next_target(ws):
    ws.mcp.block = asyncio.Event()
    mission = ws.plan(targets=["127.0.0.1", "127.0.0.2"])
    await ws.service.start(mission["mission_id"], ws.owner)
    await asyncio.wait_for(ws.mcp.entered.wait(), 2)
    ws.service.store.control(mission["mission_id"], "cancel")
    ws.mcp.block.set()
    done = await ws.settled(mission["mission_id"])
    assert done["status"] == "cancelled" and done["used_actions"] == 1
    assert all(i["status"] == "cancelled" for i in done["intents"])
    assert len(ws.mcp.calls) == 1 and ws.sandbox.calls == []


async def test_clean_shutdown_before_first_worker_tick_pauses_without_contact(ws):
    mission = ws.plan()
    await ws.service.start(mission["mission_id"], ws.owner)
    await ws.service.close()  # The task has not entered _drive yet.
    paused = ws.service.store.get_mission(mission["mission_id"])
    assert paused["status"] == "paused" and paused["used_actions"] == 0
    assert paused["intents"][0]["status"] == "pending"
    assert not ws.service._tasks and ws.mcp.calls == ws.sandbox.calls == []


async def test_shutdown_keeps_run_checkpoint_and_does_not_recapture_it_on_resume(ws):
    ws.sandbox.block = asyncio.Event()
    mission = ws.plan()
    await ws.service.start(mission["mission_id"], ws.owner)
    await asyncio.wait_for(ws.sandbox.entered.wait(), 2)
    await ws.service.close()
    paused = ws.service.store.get_mission(mission["mission_id"])
    assert paused["status"] == "paused" and paused["used_actions"] == 3
    assert paused["intents"][0]["status"] == "completed" and paused["intents"][0]["run_id"]
    await ws.service.start(mission["mission_id"], ws.owner)
    done = await ws.settled(mission["mission_id"])
    assert done["status"] == "completed" and done["used_actions"] == 3
    assert len(ws.mcp.calls) == len(ws.sandbox.calls) == 1
    assert ws.service.store.list_evidence("ENG-A") == []


async def test_live_scope_and_tool_policy_are_rechecked_between_actions(ws):
    def revoke_scope():
        for entry in ws.db.list_allowlist("ENG-A"):
            ws.db.set_allowlist_active(entry["id"], False)

    ws.mcp.after_call = revoke_scope
    mission = ws.plan()
    await ws.service.start(mission["mission_id"], ws.owner)
    done = await ws.settled(mission["mission_id"])
    assert done["status"] == "failed" and done["used_actions"] == 1
    assert len(ws.mcp.calls) == 1 and ws.sandbox.calls == []
    assert ws.service.asset_graph("ENG-A")["nodes"][0]["in_scope"] is False


async def test_policy_revocation_during_dns_check_is_not_a_stale_snapshot(ws, monkeypatch):
    evaluate, count = ws.rt.scope.evaluate_target, 0
    mission = ws.plan()

    def revoke_during_checkpoint(*args, **kwargs):
        nonlocal count
        count += 1
        if count == 2:
            ws.db.update_tool_policy("http_headers", enabled=False)
        return evaluate(*args, **kwargs)

    monkeypatch.setattr(ws.rt.scope, "evaluate_target", revoke_during_checkpoint)
    await ws.service.start(mission["mission_id"], ws.owner)
    done = await ws.settled(mission["mission_id"])
    assert done["status"] == "failed" and ws.mcp.calls == ws.sandbox.calls == []


async def test_restart_recovery_keeps_checkpoint_budget_and_requires_explicit_resume(ws):
    store = ws.service.store
    saved_run = ws.run()
    first = ws.plan()
    store.start_mission(first["mission_id"])
    store.start_intent(first["intents"][0]["intent_id"])
    store.reserve_action(first["mission_id"])
    store.checkpoint_run(first["intents"][0]["intent_id"], saved_run["run_id"])
    second = ws.plan(name="Second operator")
    with ws.db.transaction() as conn:
        conn.execute(
            "UPDATE missions SET requested_by='peer' WHERE mission_id=?", (second["mission_id"],)
        )
    store.start_mission(second["mission_id"])
    store.start_intent(second["intents"][0]["intent_id"])
    ws.service.recover()
    one, two = store.get_mission(first["mission_id"]), store.get_mission(second["mission_id"])
    assert one["status"] == two["status"] == "paused"
    assert one["used_actions"] == 1 and one["intents"][0]["status"] == "completed"
    assert two["intents"][0]["status"] == "pending" and two["intents"][0]["attempts"] == 1
    assert ws.mcp.calls == ws.sandbox.calls == [] and not ws.service._tasks
    assert ws.db.verify_audit_chain()["valid"]


async def test_deadline_and_concurrency_limits_cannot_be_reset_by_resume(ws):
    store = ws.service.store
    first, other = ws.plan(), ws.plan(name="Another mission")
    store.start_mission(first["mission_id"])
    with pytest.raises(WorkspaceConflict):
        store.start_mission(other["mission_id"])
    with ws.db.transaction() as conn:
        conn.execute(
            "UPDATE missions SET requested_by='peer' WHERE mission_id=?", (other["mission_id"],)
        )
    store.start_mission(other["mission_id"])
    third = ws.plan(name="Third mission")
    with ws.db.transaction() as conn:
        conn.execute(
            "UPDATE missions SET requested_by='admin' WHERE mission_id=?", (third["mission_id"],)
        )
    with pytest.raises(WorkspaceConflict):
        store.start_mission(third["mission_id"])
    store.finish(first["mission_id"], "paused")
    with ws.db.transaction() as conn:
        conn.execute(
            "UPDATE missions SET deadline_at=? WHERE mission_id=?",
            (
                (dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=1)).isoformat(),
                first["mission_id"],
            ),
        )
    with pytest.raises(MissionBudgetExceeded):
        store.start_mission(first["mission_id"])


async def test_action_reservations_are_atomic_even_across_database_instances(ws):
    mission = ws.plan(max_actions=7)
    ws.service.store.start_mission(mission["mission_id"])
    from gateway.db import Database

    second = WorkspaceStore(Database(ws.db.db_path))

    def reserve(index):
        try:
            (second if index % 2 else ws.service.store).reserve_action(mission["mission_id"])
            return True
        except MissionBudgetExceeded:
            return False

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        accepted = list(pool.map(reserve, range(40)))
    assert sum(accepted) == 7
    assert ws.service.store.get_mission(mission["mission_id"])["used_actions"] == 7


async def test_disabled_original_identity_cannot_resume_under_admin_credentials(ws):
    mission = ws.plan()
    ws.rt.auth._principals = [
        (digest, principal)
        for digest, principal in ws.rt.auth._principals
        if principal.operator_id != "owner"
    ]
    assert ws.rt.auth.get_operator("owner") is None
    with pytest.raises(PermissionError, match="original operator"):
        await ws.service.start(mission["mission_id"], ws.admin)
    assert not ws.mcp.calls
    assert (
        AuthManager(
            {"operators": [{"operator_id": "disabled", "token_hash_env": "UNCONFIGURED_TOKEN"}]}
        ).get_operator("disabled")
        is None
    )


async def test_workspace_reads_are_engagement_bound_and_controls_are_owner_bound(ws):
    mission = ws.plan()
    base = f"/api/v1/missions/{mission['mission_id']}"
    assert (await ws.client.get(base)).status_code == 401
    for suffix in ("", "/graph", "/report.md", "/export.json"):
        assert (
            await ws.client.get(base + suffix, headers=ws.headers["outsider"])
        ).status_code == 403
    for action in ("start", "pause", "cancel"):
        assert (
            await ws.client.post(
                base + "/control", headers=ws.headers["peer"], json={"action": action}
            )
        ).status_code == 403
    for route in ("workspace", "assets", "assets/graph", "evidence", "missions"):
        response = await ws.client.get(
            f"/api/v1/{route}?engagement_id=ENG-B", headers=ws.headers["admin"]
        )
        assert response.status_code == 403  # An admin still needs engagement assignment.
    snapshot = await ws.client.get(
        "/api/v1/workspace?engagement_id=ENG-A", headers=ws.headers["owner"]
    )
    assert (
        snapshot.status_code == 200
        and snapshot.json()["selected_mission"]["mission_id"] == mission["mission_id"]
    )
    assert snapshot.headers["cache-control"] == "no-store"
    assert ws.mcp.calls == ws.sandbox.calls == []
    start = await ws.client.post(
        base + "/control", headers=ws.headers["owner"], json={"action": "resume"}
    )
    assert start.status_code == 409  # Resume never silently starts a draft.
    assert (
        await ws.client.post(
            base + "/control", headers=ws.headers["owner"], json={"action": "cancel"}
        )
    ).status_code == 200
    assert (
        await ws.client.post(
            base + "/control", headers=ws.headers["owner"], json={"action": "start"}
        )
    ).status_code == 409
    assert ws.db.verify_audit_chain()["valid"]


async def test_health_versions_and_private_static_assets(ws):
    from gateway import __version__
    from mcp_server import __version__ as mcp_version
    from pathlib import Path

    version = (Path(__file__).parents[1] / "VERSION").read_text().strip()
    assert version == __version__ == mcp_version == "2.3.1"
    assert (await ws.client.get("/healthz")).json()["version"] == version
    assert (await ws.client.get("/readyz")).status_code == 200
    assert (await ws.client.get("/api/v1/demo/bootstrap")).status_code == 404
    assert (await ws.client.get("/openapi.json")).status_code == 200
    for asset in ("graph.js", "workspace.js", "workspace.css"):
        assert (await ws.client.get("/static/" + asset)).status_code == 200
    report = await ws.client.get("/api/v1/health")
    assert report.json()["features"]["missions"]
    assert json.loads(report.content)["version"] == version
