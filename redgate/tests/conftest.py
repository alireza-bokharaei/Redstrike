"""Local-only fixtures for the 2.1 workspace; no external target is contacted."""

from __future__ import annotations

import asyncio
import datetime as dt
import hashlib
import json
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import pytest

from gateway.auth import AuthManager, OperatorPrincipal
from gateway.config_loader import load_platform_config
from gateway.db import Database, utc_now_iso
from gateway.policy import ScopePolicyEngine
from gateway.skills import seed_builtin_skills, validate_skill_spec
from gateway.workspace_models import MissionCreateRequest

APP_ROOT = Path(__file__).resolve().parent.parent


class FakeMCP:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.block: asyncio.Event | None = None
        self.entered = asyncio.Event()
        self.after_call = None

    async def health(self) -> dict[str, Any]:
        return {"status": "ok", "version": "2.3.1"}

    async def call_tool(self, **kwargs) -> dict[str, Any]:
        self.calls.append(kwargs)
        self.entered.set()
        if self.block:
            await self.block.wait()
        if self.after_call:
            self.after_call()
        params = kwargs["params"]
        assert kwargs["pinned_ips"], "A mission must not make an unpinned request"
        return {
            "exit_code": 0,
            "duration_ms": 1,
            "stderr": "",
            "stdout": json.dumps(
                {
                    "url": f"{params['scheme']}://{kwargs['target']}:{params['port']}{params['path']}",
                    "status_code": 200,
                    "present_security_headers": {"x-content-type-options": "nosniff"},
                    "missing_recommended_headers": [
                        "content-security-policy",
                        "strict-transport-security",
                    ],
                }
            ),
        }


class FakeSandbox:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.override: dict[str, Any] = {}
        self.block: asyncio.Event | None = None
        self.entered = asyncio.Event()

    async def health(self) -> dict[str, Any]:
        return {"status": "ok", "version": "2.3.1", "http_evidence": True}

    async def capture_http(self, **kwargs) -> dict[str, Any]:
        self.calls.append(kwargs)
        self.entered.set()
        if self.block:
            await self.block.wait()
        return {
            "url": f"{kwargs['scheme']}://{kwargs['target']}:{kwargs['port']}{kwargs['path']}",
            "method": kwargs["method"],
            "connected_ip": kwargs["pinned_ips"][0],
            "status_code": 200,
            "request_headers": {"user-agent": "Redstrike"},
            "response_headers": {
                "content-type": "application/json",
                "x-content-type-options": "nosniff",
            },
            "body_preview": "",
            "body_truncated": False,
            "body_omitted": "not requested",
            "captured_at": utc_now_iso(),
            "duration_ms": 2,
            **self.override,
        }


@dataclass
class WorkspaceHarness:
    app: Any
    rt: Any
    service: Any
    db: Database
    owner: OperatorPrincipal
    peer: OperatorPrincipal
    outsider: OperatorPrincipal
    admin: OperatorPrincipal
    headers: dict[str, dict[str, str]]
    mcp: FakeMCP
    sandbox: FakeSandbox
    client: httpx.AsyncClient

    def plan(self, **changes) -> dict[str, Any]:
        payload = {
            "engagement_id": "ENG-A",
            "name": "Local baseline",
            "goal": "Read-only fixture assessment.",
            "targets": ["127.0.0.1"],
            "skill_id": "fixture-headers",
            "http": {"scheme": "http", "port": 8080, "path": "/headers", "method": "HEAD"},
            "capture_evidence": True,
            "max_actions": 24,
            "max_seconds": 300,
            **changes,
        }
        return self.service.create(MissionCreateRequest(**payload), self.owner)

    async def settled(self, mission_id: str) -> dict[str, Any]:
        task = self.service._tasks.get(mission_id)
        if task:
            await asyncio.wait_for(asyncio.shield(task), timeout=5)
        return self.service.store.get_mission(mission_id)

    def run(
        self,
        *,
        engagement="ENG-A",
        target="127.0.0.1",
        key="missing:content-security-policy",
        scheme="https",
        steps=True,
        port=None,
        path="/original",
        method="HEAD",
    ):
        params = {
            "scheme": scheme,
            "port": port or (443 if scheme == "https" else 8080),
            "path": path,
            "method": method,
        }
        return self.db.save_recon_run(
            run_id="rcn-" + secrets.token_hex(6),
            engagement_id=engagement,
            operator_id="owner",
            root_target=target,
            skill_id="fixture-headers",
            llm_provider="mock",
            llm_model="fixture",
            status="completed",
            discovered_assets=[{"asset": target, "in_scope": True}],
            steps=[{"tool": "http_headers", "status": "completed", "params": params}]
            if steps
            else [],
            memories_applied=[],
            queued_approvals=[],
            summary_stats={},
            ai_synthesis="Fixture only.",
            report_markdown="# Fixture",
            started_at=utc_now_iso(),
            finished_at=utc_now_iso(),
            duration_ms=1,
            findings=[
                {
                    "asset": target,
                    "category": "http_hardening",
                    "finding_key": key,
                    "title": "Missing header",
                    "severity": "low",
                    "priority_score": 30,
                    "ai_confidence": 0.7,
                    "requires_human_judgment": True,
                }
            ],
        )


@pytest.fixture
async def ws(tmp_path, monkeypatch):
    # Importing gateway.main constructs its default app, so isolate that too.
    monkeypatch.setenv("REDGATE_DB_PATH", str(tmp_path / "workspace.sqlite"))
    monkeypatch.setenv("REDGATE_CONFIG_DIR", str(APP_ROOT / "config"))
    monkeypatch.setenv("REDGATE_SKILLS_DIR", str(APP_ROOT / "skills"))
    monkeypatch.setenv("REDGATE_INTERNAL_TOKEN", secrets.token_hex(32))
    monkeypatch.setenv("REDGATE_LLM_MODE", "mock")
    monkeypatch.setenv("REDGATE_DEMO_MODE", "false")
    monkeypatch.setenv("REDGATE_STRICT_DNS_RESOLVE", "true")
    from gateway.main import build_runtime, create_app

    rt = build_runtime()
    now = dt.datetime.now(dt.timezone.utc)
    for engagement in ("ENG-A", "ENG-B"):
        rt.db.upsert_engagement(
            engagement,
            engagement,
            "Local fixture",
            (now - dt.timedelta(days=1)).isoformat(),
            (now + dt.timedelta(days=1)).isoformat(),
        )
        for host in ("127.0.0.1", "127.0.0.2", "unit.lab.example"):
            rt.db.seed_allowlist_target(engagement, host, "Fixture", "fixture", True)
    operators, headers = [], {}
    for name, role, engagements in [
        ("owner", "operator", ["ENG-A"]),
        ("peer", "operator", ["ENG-A"]),
        ("outsider", "operator", ["ENG-B"]),
        ("admin", "admin", ["ENG-A"]),
    ]:
        token = secrets.token_hex(24)
        env = f"REDGATE_TEST_{name.upper()}_SHA"
        monkeypatch.setenv(env, hashlib.sha256(token.encode()).hexdigest())
        operators.append(
            {
                "operator_id": name,
                "role": role,
                "token_hash_env": env,
                "rate_limit_rpm": 10000,
                "allowed_engagements": engagements,
                "quota": {"max_calls": 1000, "max_tokens": 1000000},
            }
        )
        headers[name] = {"Authorization": f"Bearer {token}"}
    rt.auth = AuthManager({"operators": operators})
    rt.db.upsert_skill(
        skill_id="fixture-headers",
        name="Fixture headers",
        version="1",
        category="test",
        description="Local-only fixture",
        created_by="fixture",
        enabled=True,
        is_builtin=False,
        spec=validate_skill_spec(
            {"steps": [{"stage": "headers", "tool": "http_headers", "params": {"method": "GET"}}]}
        ),
    )
    mcp, sandbox = FakeMCP(), FakeSandbox()
    rt.mcp = rt.agent.mcp = mcp
    rt.sandbox = rt.agent.sandbox = sandbox
    app = create_app(rt)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            yield WorkspaceHarness(
                app=app,
                rt=rt,
                service=app.state.workspace,
                db=rt.db,
                owner=rt.auth.get_operator("owner"),
                peer=rt.auth.get_operator("peer"),
                outsider=rt.auth.get_operator("outsider"),
                admin=rt.auth.get_operator("admin"),
                headers=headers,
                mcp=mcp,
                sandbox=sandbox,
                client=client,
            )


@pytest.fixture
def isolated_store(tmp_path):
    db = Database(tmp_path / "store.sqlite")
    cfg = load_platform_config(APP_ROOT / "config")
    from gateway.config_loader import seed_database_from_config

    seed_database_from_config(db, cfg)
    seed_builtin_skills(db, APP_ROOT / "skills")
    return db, ScopePolicyEngine(db)
