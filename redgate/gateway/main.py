"""Redstrike Layer 1 — FastAPI Security Testing Gateway.

Orchestrates:
  - Bearer SHA-256 auth, RBAC (operator / approver / admin), and RPM rate limiting
  - Per-engagement target allowlist + RoE time window + DNS rebinding guard
  - Tool policy enforcement + Two-Person approval queue -> Layer 2 MCP Server
  - Secret-scrubbing LLM proxy + multi-language static validation (Py/Bash/Go/JS)
  - Hash-verified isolated script execution -> Layer 3 Go Sandbox Runner
  - Append-only, SHA-256 hash-chained SQLite audit logging
"""

from __future__ import annotations

import asyncio
import json
import os
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Response, status
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from gateway import __version__
from gateway.agent import PersonalizedReconAgent
from gateway.auth import AuthManager, OperatorPrincipal
from gateway.capabilities import CapabilityRegistry
from gateway.bugbounty import BugBountyService
from gateway.capability_api import capability_router
from gateway.coverage import CoverageLedger, ResponseTracker
from gateway.intel_api import intel_router
from gateway.intel_engine import OutcomeStore
from gateway.evidence_gate import EvidenceGate
from gateway.exploitation import ExploitationService
from gateway.exploration import ExplorationService
from gateway.hunt_loop import HuntLoopService
from gateway.config_loader import PlatformConfig, load_platform_config, seed_database_from_config
from gateway.db import Database, utc_now_iso
from gateway.llm_proxy import LLMProxyError, LLMProxyGateway
from gateway.mcp_client import MCPBridgeClient, MCPClientError
from gateway.memory import AgentMemoryEngine
from gateway.missions import MissionService
from gateway.offensive_api import offensive_router
from gateway.offensive_policy import OffensivePolicyEngine
from gateway.pwntools_layer import PwntoolsLayer
from gateway.scan_runner import ScanRunner
from gateway.model_hub import (
    LocalModelHub,
    validate_llm_endpoint_url,
    validate_model_identifier,
)
from gateway.models import (
    AllowlistCreateRequest,
    AllowlistPatchRequest,
    ApprovalDecisionRequest,
    FindingReviewRequest,
    LLMRuntimeUpdateRequest,
    MemoryCreateRequest,
    MemoryPatchRequest,
    QuantizationRecommendRequest,
    ReconRunRequest,
    ScanRequest,
    ScriptGenerateRequest,
    ScriptRunRequest,
    ScriptValidateRequest,
    SkillCreateRequest,
    ToolPolicyPatchRequest,
)
from gateway.policy import ScopePolicyEngine, validate_allowlist_entry_syntax
from gateway.sandbox_client import GoSandboxClient, SandboxClientError
from gateway.expansion import ExpansionService
from gateway.skills import SkillValidationError, validate_skill_spec
from gateway.tls_audit import TLSProbeProfile, TLSAuditService
from gateway.workspace_store import WorkspaceStore
from gateway.validators import ScriptValidationOrchestrator
from gateway.workspace_api import workspace_router
from mcp_server.tools import ToolParamValidationError, validate_tool_params

STATIC_DIR = Path(__file__).resolve().parent / "static"


@dataclass
class GatewayRuntime:
    """Dependency container holding initialized gateway & personalized agent subsystems."""

    config: PlatformConfig
    db: Database
    auth: AuthManager
    scope: ScopePolicyEngine
    llm: LLMProxyGateway
    model_hub: LocalModelHub
    memory: AgentMemoryEngine
    agent: PersonalizedReconAgent
    validator: ScriptValidationOrchestrator
    mcp: MCPBridgeClient
    sandbox: GoSandboxClient
    sandbox_mem_mb: int
    sandbox_max_output: int
    # ---- 2.2 capability layers (widened but governed policy surface) ----
    registry: CapabilityRegistry
    evidence_gate: EvidenceGate
    tls_audit: TLSAuditService
    artifact_root: Path
    # ---- 2.3 offensive surface -------------------------------------------
    policies: OffensivePolicyEngine
    exploitation: ExploitationService
    exploration: ExplorationService
    bounty: BugBountyService
    pwntools: PwntoolsLayer
    loops: HuntLoopService
    runner: ScanRunner
    store: WorkspaceStore
    # ---- 2.3.1 intel / coverage ------------------------------------------
    intel_outcomes: OutcomeStore
    coverage: CoverageLedger
    responses: ResponseTracker


def build_runtime() -> GatewayRuntime:
    """Initialize config, DB, policy, Local Model Hub, Skills, Memory, and Recon Agent."""
    repo_root = Path(__file__).resolve().parent.parent
    config_dir = Path(os.environ.get("REDGATE_CONFIG_DIR", str(repo_root / "config")))
    skills_dir = Path(os.environ.get("REDGATE_SKILLS_DIR", str(repo_root / "skills")))
    db_path = Path(os.environ.get("REDGATE_DB_PATH", str(repo_root / "data" / "redgate.db")))
    internal_token = os.environ.get("REDGATE_INTERNAL_TOKEN", "")
    mcp_url = os.environ.get("REDGATE_MCP_URL", "http://127.0.0.1:8001")
    sandbox_url = os.environ.get("REDGATE_SANDBOX_URL", "http://127.0.0.1:8002")

    cfg = load_platform_config(config_dir)
    db = Database(db_path)
    seed_database_from_config(db, cfg, skills_dir=skills_dir)

    default_rpm = int(cfg.llm_proxy.get("rate_limit", {}).get("requests_per_minute", 10))
    sb_defaults = cfg.script_policy.get("sandbox_defaults", {})
    sandbox_mem_mb = int(sb_defaults.get("max_memory_mb", 128))
    sandbox_max_output = int(sb_defaults.get("max_output_bytes", 65536))

    artifact_root = Path(
        os.environ.get("REDGATE_ARTIFACT_DIR", str(repo_root / "data" / "artifacts"))
    ).resolve()
    artifact_root.mkdir(parents=True, exist_ok=True)

    scope = ScopePolicyEngine(db, cfg.allowlist.get("dns_security"))
    registry = CapabilityRegistry.from_file(config_dir / "capabilities.yaml")
    evidence_gate = EvidenceGate(registry.evidence_gate())

    llm = LLMProxyGateway(cfg.llm_proxy, runtime_getter=db.get_or_init_llm_runtime)
    model_hub = LocalModelHub(cfg.local_models)
    memory = AgentMemoryEngine(db=db, llm_proxy=llm)
    validator = ScriptValidationOrchestrator(
        max_script_bytes=int(sb_defaults.get("max_script_bytes", 32768))
    )
    mcp = MCPBridgeClient(base_url=mcp_url, internal_token=internal_token)
    sandbox = GoSandboxClient(base_url=sandbox_url, internal_token=internal_token)
    agent = PersonalizedReconAgent(
        db=db,
        scope=scope,
        mcp=mcp,
        sandbox=sandbox,
        validator=validator,
        llm=llm,
        memory=memory,
        sandbox_mem_mb=sandbox_mem_mb,
        sandbox_max_output=sandbox_max_output,
    )

    tls_audit = TLSAuditService(
        db=db,
        scope=scope,
        store=WorkspaceStore(db),
        profile=TLSProbeProfile.from_manifest(registry.tls_profile()),
        evidence_gate=evidence_gate,
    )

    # ---- 2.3: the offensive surface -------------------------------------
    # The policy engine seeds itself from config/policies.yaml on first use, so a
    # fresh database is immediately consistent with the declarative manifest.
    workspace_store = WorkspaceStore(db)
    policies = OffensivePolicyEngine(
        db, OffensivePolicyEngine.load_manifest(config_dir / "policies.yaml")
    )
    policies.seed()

    return GatewayRuntime(
        config=cfg,
        db=db,
        auth=AuthManager(cfg.operators, default_rpm=default_rpm),
        scope=scope,
        llm=llm,
        model_hub=model_hub,
        memory=memory,
        agent=agent,
        validator=validator,
        mcp=mcp,
        sandbox=sandbox,
        sandbox_mem_mb=sandbox_mem_mb,
        sandbox_max_output=sandbox_max_output,
        registry=registry,
        evidence_gate=evidence_gate,
        tls_audit=tls_audit,
        artifact_root=artifact_root,
        policies=policies,
        exploitation=ExploitationService(
            db=db, scope=scope, store=workspace_store, policies=policies
        ),
        exploration=ExplorationService(
            db=db, scope=scope, store=workspace_store, policies=policies
        ),
        bounty=BugBountyService(db=db, scope=scope),
        pwntools=PwntoolsLayer(
            db=db, scope=scope, policies=policies, artifact_root=str(artifact_root)
        ),
        loops=HuntLoopService(db=db),
        runner=ScanRunner(db=db, scope=scope, policies=policies, mcp=mcp),
        store=workspace_store,
        intel_outcomes=OutcomeStore(db),
        coverage=CoverageLedger(db),
        responses=ResponseTracker(db),
    )


def create_app(runtime: GatewayRuntime | None = None) -> FastAPI:
    """Create and wire the FastAPI Gateway application."""
    rt = runtime or build_runtime()
    workspace = MissionService(
        db=rt.db,
        auth=rt.auth,
        scope=rt.scope,
        agent=rt.agent,
        sandbox=rt.sandbox,
        registry=rt.registry,
    )
    # Deep TLS analysis reaches the HSTS header through the same governed MCP
    # bridge as every other tool; it never opens a header probe of its own.
    rt.tls_audit.mcp = rt.mcp
    expansion_service = ExpansionService(
        db=rt.db,
        scope=rt.scope,
        store=WorkspaceStore(rt.db),
        policy=rt.registry.expansion_policy(),
        registry=rt.registry,
    )
    application_tls = rt.tls_audit

    @asynccontextmanager
    async def lifespan(_application: FastAPI):
        workspace.recover()
        try:
            yield
        finally:
            await workspace.close()

    application = FastAPI(
        title="Redstrike 2.1 — Auditable Mission & Evidence Workspace",
        description=(
            "Policy-controlled security verification & automated recon platform with Local LLM Hub "
            "(Ollama / LM Studio / Hugging Face GGUF Quantization), Operator Skills & Memory, "
            "MCP tools, 4-language static validation, Go sandbox, and SHA-256 hash-chained audit logs."
        ),
        version=__version__,
        lifespan=lifespan,
    )
    application.state.rt = rt
    application.state.workspace = workspace

    @application.middleware("http")
    async def private_api_responses(request, call_next):
        response = await call_next(request)
        if request.url.path.startswith("/api/"):
            # Evidence, engagement data and demo credentials must not survive in
            # a shared browser/proxy cache when the operator changes identities.
            response.headers["Cache-Control"] = "no-store"
            response.headers.append("Vary", "Authorization")
        return response

    def get_principal(authorization: str | None = Header(default=None)) -> OperatorPrincipal:
        principal = rt.auth.authenticate(authorization)
        try:
            rt.auth.enforce_rate_limit(principal)
        except HTTPException as exc:
            rt.db.write_audit_log(
                engagement_id="SYSTEM",
                operator_id=principal.operator_id,
                target="-",
                tool_or_script="gateway:rate_limiter",
                status="rejected",
                rejection_reason=str(exc.detail),
            )
            raise
        return principal

    def ensure_engagement_access(principal: OperatorPrincipal, engagement_id: str) -> None:
        if not principal.can_access_engagement(engagement_id):
            rt.db.write_audit_log(
                engagement_id=engagement_id,
                operator_id=principal.operator_id,
                target="-",
                tool_or_script="gateway:rbac",
                status="rejected",
                rejection_reason=f"Operator '{principal.operator_id}' not assigned to '{engagement_id}'.",
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Operator '{principal.operator_id}' is not authorized for engagement '{engagement_id}'.",
            )

    async def _dispatch_mcp_scan(
        *,
        operator_id: str,
        engagement_id: str,
        target: str,
        tool_name: str,
        sanitized_params: dict[str, Any],
        timeout_sec: int,
        allowed_params: dict[str, Any],
        pinned_ips: list[str],
        approval_id: str | None = None,
    ) -> dict[str, Any]:
        started = utc_now_iso()
        try:
            exec_res = await rt.mcp.call_tool(
                tool_name=tool_name,
                target=target,
                params=sanitized_params,
                max_timeout=timeout_sec,
                allowed_params=allowed_params,
                pinned_ips=pinned_ips,
            )
        except MCPClientError as exc:
            audit = rt.db.write_audit_log(
                engagement_id=engagement_id,
                operator_id=operator_id,
                target=target,
                resolved_ips=pinned_ips,
                tool_or_script=f"tool:{tool_name}",
                params={**sanitized_params, **({"approval_id": approval_id} if approval_id else {})},
                started_at=started,
                status="rejected" if exc.is_param_error else "error",
                rejection_reason=str(exc),
            )
            code = 422 if exc.is_param_error else status.HTTP_502_BAD_GATEWAY
            raise HTTPException(status_code=code, detail={"message": str(exc), "audit_id": audit["id"]}) from exc

        exit_code = int(exec_res.get("exit_code", 1))
        summary = (exec_res.get("stdout") or exec_res.get("stderr") or "").strip()
        run_status = "completed" if exit_code == 0 else ("timeout" if exec_res.get("timed_out") else "failed")
        audit = rt.db.write_audit_log(
            engagement_id=engagement_id,
            operator_id=operator_id,
            target=target,
            resolved_ips=pinned_ips,
            tool_or_script=f"tool:{tool_name}",
            params={**sanitized_params, **({"approval_id": approval_id} if approval_id else {})},
            started_at=str(exec_res.get("started_at", started)),
            finished_at=str(exec_res.get("finished_at", utc_now_iso())),
            duration_ms=int(exec_res.get("duration_ms", 0)),
            exit_code=exit_code,
            stdout_summary=summary,
            status=run_status,
            rejection_reason=exec_res.get("stderr") if exit_code != 0 else None,
        )
        return {
            "status": run_status,
            "audit_id": audit["id"],
            "audit_hash": audit["entry_hash"],
            "engagement_id": engagement_id,
            "target": target,
            "pinned_ips": pinned_ips,
            "execution": exec_res,
        }

    async def _dispatch_sandbox_script(
        *,
        operator_id: str,
        script_record: dict[str, Any],
        timeout_override: int | None = None,
        approval_id: str | None = None,
    ) -> dict[str, Any]:
        engagement_id = str(script_record["engagement_id"])
        target = str(script_record["target"])
        language = str(script_record["language"])

        # Re-verify allowlist & DNS pinning immediately before execution (anti-TOCTOU).
        scope_res = rt.scope.evaluate_target(engagement_id, target, resolve_dns=True)
        if not scope_res.allowed:
            audit = rt.db.write_audit_log(
                engagement_id=engagement_id,
                operator_id=operator_id,
                target=target,
                tool_or_script=f"script:{script_record['script_id']}",
                language=language,
                status="rejected",
                rejection_reason=f"Pre-execution scope recheck failed: {scope_res.reason}",
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"message": scope_res.reason, "audit_id": audit["id"]},
            )

        lang_policy = rt.db.get_script_policy(language)
        if not lang_policy or not lang_policy["enabled"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Language '{language}' is disabled by script policy.",
            )

        max_rt = int(lang_policy["max_runtime_sec"])
        effective_timeout = min(
            timeout_override or int(script_record["expected_runtime_sec"]) or max_rt,
            max_rt,
        )

        started = utc_now_iso()
        try:
            sb_res = await rt.sandbox.execute_script(
                language=language,
                script=str(script_record["script_body"]),
                expected_sha256=str(script_record["sha256"]),
                target=scope_res.normalized_target,
                pinned_ips=scope_res.resolved_ips,
                egress_allowlist=scope_res.egress_allowlist,
                timeout_sec=effective_timeout,
                memory_limit_mb=rt.sandbox_mem_mb,
                max_output_bytes=rt.sandbox_max_output,
            )
        except SandboxClientError as exc:
            audit = rt.db.write_audit_log(
                engagement_id=engagement_id,
                operator_id=operator_id,
                target=scope_res.normalized_target,
                resolved_ips=scope_res.resolved_ips,
                tool_or_script=f"script:{script_record['script_id']}",
                language=language,
                started_at=started,
                status="error",
                rejection_reason=str(exc),
            )
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail={"message": str(exc), "audit_id": audit["id"]},
            ) from exc

        exit_code = int(sb_res.get("exit_code", -1))
        timed_out = bool(sb_res.get("timed_out", False))
        run_status = "completed" if exit_code == 0 else ("timeout" if timed_out else "failed")
        stdout_text = str(sb_res.get("stdout", ""))
        stderr_text = str(sb_res.get("stderr", ""))
        err_text = str(sb_res.get("error", ""))
        combined_summary = stdout_text if stdout_text.strip() else (stderr_text or err_text)

        audit = rt.db.write_audit_log(
            engagement_id=engagement_id,
            operator_id=operator_id,
            target=scope_res.normalized_target,
            resolved_ips=scope_res.resolved_ips,
            tool_or_script=f"script:{script_record['script_id']}",
            language=language,
            params={
                "sha256": script_record["sha256"],
                "timeout_sec": effective_timeout,
                "memory_limit_mb": rt.sandbox_mem_mb,
                "source": script_record["source"],
                **({"approval_id": approval_id} if approval_id else {}),
            },
            started_at=started,
            finished_at=utc_now_iso(),
            duration_ms=int(sb_res.get("duration_ms", 0)),
            exit_code=exit_code,
            stdout_summary=combined_summary,
            status=run_status,
            rejection_reason=(err_text or stderr_text[:400]) if exit_code != 0 else None,
        )

        return {
            "status": run_status,
            "audit_id": audit["id"],
            "audit_hash": audit["entry_hash"],
            "script_id": script_record["script_id"],
            "sha256": script_record["sha256"],
            "language": language,
            "target": scope_res.normalized_target,
            "pinned_ips": scope_res.resolved_ips,
            "sandbox": sb_res,
        }

    # ------------------------------------------------------------------
    # System Health, Benign Self-Test Probe, and Local Lab Helper
    # ------------------------------------------------------------------

    @application.get("/healthz", include_in_schema=False)
    async def liveness() -> dict[str, str]:
        # Cheap liveness; do not walk the entire audit ledger every 30 seconds.
        return {"status": "ok", "version": __version__}

    @application.get("/readyz", include_in_schema=False)
    async def readiness() -> JSONResponse:
        mcp, sandbox = await asyncio.gather(rt.mcp.health(), rt.sandbox.health())
        ready = mcp.get("status") == "ok" and sandbox.get("status") == "ok"
        return JSONResponse({"status": "ready" if ready else "degraded", "version": __version__},
                            status_code=200 if ready else 503)

    @application.get("/api/v1/health")
    async def health() -> dict[str, Any]:
        mcp_health = await rt.mcp.health()
        sb_health = await rt.sandbox.health()
        chain = rt.db.verify_audit_chain()
        return {
            "status": "ok",
            "gateway": "online",
            "version": __version__,
            "features": {
                "missions": True,
                "asset_graph": True,
                "http_evidence": True,
                "header_retests": True,
                "capability_modes": rt.registry.enabled,
                "tls_deep_analysis": True,
                "expansion_requests": True,
                "evidence_gate": True,
                "agent_roles": True,
                "binary_triage": True,
                # ---- 2.3 offensive surface ----
                "offensive_policies": True,
                "offensive_tools": True,
                "tool_catalog_size": len(rt.runner.installed_tools()),
                "exploitation_lifecycle": True,
                "attack_chains": True,
                "bug_bounty": True,
                "pwntools_layer": rt.pwntools.availability()["available"],
                "recursive_discovery": True,
                "mass_scan_budgets": True,
                "hunt_loops": True,
                "agent_brain": True,
                "agent_roles_count": len(rt.loops.roster()["roles"]),
            },
            "gateway_port": int(os.environ.get("REDGATE_GATEWAY_PORT", "8000")),
            "mcp_server": mcp_health,
            "sandbox_runner": sb_health,
            "llm_proxy": {
                "mode": rt.llm.current_mode,
                "model": rt.llm.current_model,
                "secret_scrubbing": True,
            },
            "validators": rt.validator.toolchain_status(),
            "audit_chain": chain,
            "demo_mode": os.environ.get("REDGATE_DEMO_MODE", "false").lower() == "true",
        }

    @application.get("/probe/headers")
    @application.head("/probe/headers", include_in_schema=False)
    async def local_probe_endpoint(response: Response) -> dict[str, str]:
        """Benign local endpoint used strictly for ENG-LOCAL-LAB verification tests.

        Intentionally sets a subset of defensive headers while omitting HSTS and CSP
        so header-inspection tools and sandboxed scripts produce realistic findings.
        """
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Cache-Control"] = "no-store"
        return {
            "service": "redgate-local-lab-target",
            "note": "Authorized loopback verification target for ENG-LOCAL-LAB.",
        }

    @application.get("/api/v1/demo/bootstrap")
    async def demo_bootstrap() -> dict[str, Any]:
        """Return ephemeral local lab session tokens ONLY when REDGATE_DEMO_MODE=true.

        Disabled (HTTP 404) in all production and Docker deployments.
        """
        if os.environ.get("REDGATE_DEMO_MODE", "false").lower() != "true":
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Demo mode is disabled.")
        token_file = os.environ.get("REDGATE_DEMO_TOKENS_FILE", "")
        if not token_file or not Path(token_file).is_file():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No demo token manifest.")
        return json.loads(Path(token_file).read_text(encoding="utf-8"))

    # ------------------------------------------------------------------
    # Identity, Engagements, Allowlist, Policies, and Quotas
    # ------------------------------------------------------------------

    @application.get("/api/v1/me")
    async def get_me(principal: OperatorPrincipal = Depends(get_principal)) -> dict[str, Any]:
        quota = rt.db.get_or_init_quota(
            principal.operator_id,
            principal.quota_period,
            principal.quota_max_calls,
            principal.quota_max_tokens,
        )
        return {
            "operator_id": principal.operator_id,
            "display_name": principal.display_name,
            "role": principal.role,
            "rate_limit_rpm": principal.rate_limit_rpm,
            "allowed_engagements": list(principal.allowed_engagements),
            "quota": quota,
        }

    @application.get("/api/v1/engagements")
    async def list_engagements(
        principal: OperatorPrincipal = Depends(get_principal),
    ) -> dict[str, Any]:
        all_engs = rt.db.list_engagements()
        visible = [e for e in all_engs if principal.can_access_engagement(str(e["id"]))]
        return {"engagements": visible}

    @application.get("/api/v1/allowlist")
    async def get_allowlist(
        engagement_id: str | None = Query(default=None),
        principal: OperatorPrincipal = Depends(get_principal),
    ) -> dict[str, Any]:
        if engagement_id:
            ensure_engagement_access(principal, engagement_id)
        entries = rt.db.list_allowlist(engagement_id=engagement_id, active_only=False)
        visible = [e for e in entries if principal.can_access_engagement(str(e["engagement_id"]))]
        return {"allowlist": visible}

    @application.post("/api/v1/allowlist", status_code=status.HTTP_201_CREATED)
    async def add_allowlist(
        req: AllowlistCreateRequest,
        principal: OperatorPrincipal = Depends(get_principal),
    ) -> dict[str, Any]:
        if not principal.can_approve():
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only 'approver' or 'admin' roles may modify engagement allowlists.",
            )
        ensure_engagement_access(principal, req.engagement_id)
        if not rt.db.get_engagement(req.engagement_id):
            raise HTTPException(status_code=404, detail=f"Engagement '{req.engagement_id}' not found.")

        try:
            normalized = validate_allowlist_entry_syntax(req.target)
        except ValueError as exc:
            rt.db.write_audit_log(
                engagement_id=req.engagement_id,
                operator_id=principal.operator_id,
                target=req.target,
                tool_or_script="policy:allowlist_add",
                status="rejected",
                rejection_reason=str(exc),
            )
            raise HTTPException(status_code=422, detail=str(exc)) from exc

        entry = rt.db.add_allowlist_target(
            engagement_id=req.engagement_id,
            target=normalized,
            description=req.description,
            created_by=principal.operator_id,
        )
        rt.db.write_audit_log(
            engagement_id=req.engagement_id,
            operator_id=principal.operator_id,
            target=normalized,
            tool_or_script="policy:allowlist_add",
            params={"description": req.description},
            exit_code=0,
            stdout_summary=f"Allowlist entry #{entry['id']} enabled for {normalized}",
            status="completed",
        )
        return {"entry": entry}

    @application.patch("/api/v1/allowlist/{entry_id}")
    async def patch_allowlist(
        entry_id: int,
        req: AllowlistPatchRequest,
        principal: OperatorPrincipal = Depends(get_principal),
    ) -> dict[str, Any]:
        if not principal.can_approve():
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only 'approver' or 'admin' roles may toggle allowlist entries.",
            )
        updated = rt.db.set_allowlist_active(entry_id, req.active)
        if not updated:
            raise HTTPException(status_code=404, detail=f"Allowlist entry #{entry_id} not found.")
        rt.db.write_audit_log(
            engagement_id=str(updated["engagement_id"]),
            operator_id=principal.operator_id,
            target=str(updated["target"]),
            tool_or_script="policy:allowlist_toggle",
            params={"entry_id": entry_id, "active": req.active},
            exit_code=0,
            stdout_summary=f"Set allowlist #{entry_id} active={req.active}",
            status="completed",
        )
        return {"entry": updated}

    @application.get("/api/v1/policies")
    async def get_policies(principal: OperatorPrincipal = Depends(get_principal)) -> dict[str, Any]:
        del principal
        return {
            "tool_policies": rt.db.list_tool_policies(),
            "script_policies": rt.db.list_script_policies(),
        }

    @application.patch("/api/v1/policies/tools/{tool_name}")
    async def patch_tool_policy(
        tool_name: str,
        req: ToolPolicyPatchRequest,
        principal: OperatorPrincipal = Depends(get_principal),
    ) -> dict[str, Any]:
        if not principal.is_admin():
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only 'admin' role may modify tool enablement policies.",
            )
        updated = rt.db.update_tool_policy(
            tool_name=tool_name,
            enabled=req.enabled,
            requires_approval=req.requires_approval,
            max_timeout=req.max_timeout,
        )
        if not updated:
            raise HTTPException(status_code=404, detail=f"Tool policy '{tool_name}' not found.")
        rt.db.write_audit_log(
            engagement_id="SYSTEM",
            operator_id=principal.operator_id,
            target=tool_name,
            tool_or_script="policy:tool_update",
            params=req.model_dump(exclude_none=True),
            exit_code=0,
            stdout_summary=(
                f"Updated {tool_name}: enabled={updated['enabled']}, "
                f"requires_approval={updated['requires_approval']}, max_timeout={updated['max_timeout']}s"
            ),
            status="completed",
        )
        return {"tool_policy": updated}

    @application.get("/api/v1/quota")
    async def get_quota(principal: OperatorPrincipal = Depends(get_principal)) -> dict[str, Any]:
        own = rt.db.get_or_init_quota(
            principal.operator_id,
            principal.quota_period,
            principal.quota_max_calls,
            principal.quota_max_tokens,
        )
        result: dict[str, Any] = {"quota": own}
        if principal.can_approve():
            result["all_operators"] = rt.db.list_all_quotas()
        return result

    # ------------------------------------------------------------------
    # Layer 2 Tool Scan Orchestration (POST /api/v1/scan & POST /scan)
    # ------------------------------------------------------------------

    @application.post("/api/v1/scan")
    @application.post("/scan", include_in_schema=False)
    async def submit_scan(
        req: ScanRequest,
        principal: OperatorPrincipal = Depends(get_principal),
    ) -> JSONResponse:
        ensure_engagement_access(principal, req.engagement_id)

        # 1. Scope allowlist + DNS rebinding guard.
        scope_res = rt.scope.evaluate_target(req.engagement_id, req.target, resolve_dns=True)
        if not scope_res.allowed:
            audit = rt.db.write_audit_log(
                engagement_id=req.engagement_id,
                operator_id=principal.operator_id,
                target=req.target,
                tool_or_script=f"tool:{req.tool_name}",
                params=req.params,
                status="rejected",
                rejection_reason=scope_res.reason,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"message": scope_res.reason, "audit_id": audit["id"]},
            )

        # 2. Tool policy verification.
        pol = rt.db.get_tool_policy(req.tool_name)
        if not pol:
            audit = rt.db.write_audit_log(
                engagement_id=req.engagement_id,
                operator_id=principal.operator_id,
                target=scope_res.normalized_target,
                resolved_ips=scope_res.resolved_ips,
                tool_or_script=f"tool:{req.tool_name}",
                params=req.params,
                status="rejected",
                rejection_reason=f"Tool '{req.tool_name}' is not registered in tool_policy.",
            )
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"message": f"Unknown tool '{req.tool_name}'.", "audit_id": audit["id"]},
            )

        if not pol["enabled"]:
            reason = (
                f"Tool '{req.tool_name}' (risk={pol['risk_level']}) is DISABLED by default policy."
            )
            audit = rt.db.write_audit_log(
                engagement_id=req.engagement_id,
                operator_id=principal.operator_id,
                target=scope_res.normalized_target,
                resolved_ips=scope_res.resolved_ips,
                tool_or_script=f"tool:{req.tool_name}",
                params=req.params,
                status="rejected",
                rejection_reason=reason,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"message": reason, "audit_id": audit["id"]},
            )

        # 3. Upfront parameter whitelist verification (defense-in-depth before MCP).
        try:
            clean_params = validate_tool_params(req.tool_name, req.params, pol["allowed_params"])
        except ToolParamValidationError as exc:
            audit = rt.db.write_audit_log(
                engagement_id=req.engagement_id,
                operator_id=principal.operator_id,
                target=scope_res.normalized_target,
                resolved_ips=scope_res.resolved_ips,
                tool_or_script=f"tool:{req.tool_name}",
                params=req.params,
                status="rejected",
                rejection_reason=str(exc),
            )
            raise HTTPException(
                status_code=422,
                detail={"message": str(exc), "audit_id": audit["id"]},
            ) from exc

        # 4. Operator call quota enforcement.
        ok, q_reason, _ = rt.db.check_and_consume_quota(
            operator_id=principal.operator_id,
            period=principal.quota_period,
            max_calls=principal.quota_max_calls,
            max_tokens=principal.quota_max_tokens,
            calls_delta=1,
        )
        if not ok:
            audit = rt.db.write_audit_log(
                engagement_id=req.engagement_id,
                operator_id=principal.operator_id,
                target=scope_res.normalized_target,
                tool_or_script=f"tool:{req.tool_name}",
                params=clean_params,
                status="rejected",
                rejection_reason=q_reason,
            )
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail={"message": q_reason, "audit_id": audit["id"]},
            )

        effective_timeout = min(req.timeout_sec or int(pol["max_timeout"]), int(pol["max_timeout"]))

        # 5. Route gated tools to Two-Person Approval Queue.
        if pol["requires_approval"]:
            queued = rt.db.enqueue_approval(
                engagement_id=req.engagement_id,
                request_type="tool_scan",
                target=scope_res.normalized_target,
                tool_or_script=req.tool_name,
                payload={
                    "tool_name": req.tool_name,
                    "params": clean_params,
                    "timeout_sec": effective_timeout,
                    "risk_level": pol["risk_level"],
                },
                requested_by=principal.operator_id,
            )
            audit = rt.db.write_audit_log(
                engagement_id=req.engagement_id,
                operator_id=principal.operator_id,
                target=scope_res.normalized_target,
                resolved_ips=scope_res.resolved_ips,
                tool_or_script=f"tool:{req.tool_name}",
                params={"sanitized_params": clean_params, "approval_id": queued["request_id"]},
                stdout_summary=f"Queued for two-person approval as {queued['request_id']}.",
                status="pending_approval",
            )
            return JSONResponse(
                status_code=status.HTTP_202_ACCEPTED,
                content={
                    "status": "pending_approval",
                    "message": (
                        f"Tool '{req.tool_name}' (risk={pol['risk_level']}) requires explicit "
                        "approval by a separate approver/admin."
                    ),
                    "approval": queued,
                    "audit_id": audit["id"],
                    "audit_hash": audit["entry_hash"],
                },
            )

        # 6. Execute immediately via Layer 2 MCP Server.
        result = await _dispatch_mcp_scan(
            operator_id=principal.operator_id,
            engagement_id=req.engagement_id,
            target=scope_res.normalized_target,
            tool_name=req.tool_name,
            sanitized_params=clean_params,
            timeout_sec=effective_timeout,
            allowed_params=pol["allowed_params"],
            pinned_ips=scope_res.resolved_ips,
        )
        return JSONResponse(status_code=status.HTTP_200_OK, content=result)

    # ------------------------------------------------------------------
    # AI Script Generation + Multi-Language Validation + Go Sandbox Run
    # ------------------------------------------------------------------

    @application.post("/api/v1/script/generate")
    @application.post("/script/generate", include_in_schema=False)
    async def generate_script(
        req: ScriptGenerateRequest,
        principal: OperatorPrincipal = Depends(get_principal),
    ) -> JSONResponse:
        ensure_engagement_access(principal, req.engagement_id)

        # 1. Verify target is in engagement allowlist BEFORE invoking LLM.
        scope_res = rt.scope.evaluate_target(req.engagement_id, req.target, resolve_dns=True)
        if not scope_res.allowed:
            audit = rt.db.write_audit_log(
                engagement_id=req.engagement_id,
                operator_id=principal.operator_id,
                target=req.target,
                tool_or_script="llm:script_generate",
                language=req.language,
                status="rejected",
                rejection_reason=scope_res.reason,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"message": scope_res.reason, "audit_id": audit["id"]},
            )

        # 2. Load language script_policy.
        s_pol = rt.db.get_script_policy(req.language)
        if not s_pol or not s_pol["enabled"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Script generation for '{req.language}' is disabled by script_policy.",
            )

        # 3. Check call + minimum token reserve BEFORE hitting LLM gateway.
        min_token_reserve = 250
        ok, q_reason, _ = rt.db.check_and_consume_quota(
            operator_id=principal.operator_id,
            period=principal.quota_period,
            max_calls=principal.quota_max_calls,
            max_tokens=principal.quota_max_tokens,
            calls_delta=1,
            estimated_tokens=0,
        )
        cur_q = rt.db.get_or_init_quota(
            principal.operator_id,
            principal.quota_period,
            principal.quota_max_calls,
            principal.quota_max_tokens,
        )
        if not ok or (cur_q["used_tokens"] + min_token_reserve > cur_q["max_tokens"]):
            reason = q_reason if not ok else (
                f"LLM token quota exhausted ({cur_q['used_tokens']}/{cur_q['max_tokens']})."
            )
            audit = rt.db.write_audit_log(
                engagement_id=req.engagement_id,
                operator_id=principal.operator_id,
                target=scope_res.normalized_target,
                tool_or_script="llm:script_generate",
                language=req.language,
                status="rejected",
                rejection_reason=reason,
            )
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail={"message": reason, "audit_id": audit["id"]},
            )

        # 4. Call secret-scrubbing LLM proxy with restricted prompt template.
        started = utc_now_iso()
        try:
            artifact = await rt.llm.generate_script(
                engagement_id=req.engagement_id,
                target=scope_res.normalized_target,
                language=req.language,
                objective=req.objective,
                script_policy=s_pol,
            )
        except LLMProxyError as exc:
            audit = rt.db.write_audit_log(
                engagement_id=req.engagement_id,
                operator_id=principal.operator_id,
                target=scope_res.normalized_target,
                resolved_ips=scope_res.resolved_ips,
                tool_or_script="llm:script_generate",
                language=req.language,
                started_at=started,
                status="rejected",
                rejection_reason=str(exc),
            )
            raise HTTPException(
                status_code=422,
                detail={"message": str(exc), "audit_id": audit["id"]},
            ) from exc

        # Record exact LLM token usage against operator's quota.
        rt.db.record_llm_tokens(principal.operator_id, principal.quota_period, artifact.tokens_used)

        # 5. Mandatory static validation pipeline (AST / ShellCheck / go vet+build / ESLint).
        val_result = rt.validator.validate(
            language=req.language,
            script=artifact.script,
            script_policy=s_pol,
            is_host_allowed=lambda h: rt.scope.is_literal_host_in_scope(req.engagement_id, h),
        )

        if not val_result.passed:
            audit = rt.db.write_audit_log(
                engagement_id=req.engagement_id,
                operator_id=principal.operator_id,
                target=scope_res.normalized_target,
                resolved_ips=scope_res.resolved_ips,
                tool_or_script="llm:script_generate",
                language=req.language,
                params={
                    "sha256": val_result.sha256,
                    "tokens_used": artifact.tokens_used,
                    "scrubbed_secrets": artifact.scrubbed_secrets,
                },
                started_at=started,
                status="validation_failed",
                rejection_reason=val_result.rejection_summary(),
            )
            return JSONResponse(
                status_code=422,
                content={
                    "status": "validation_failed",
                    "audit_id": audit["id"],
                    "language": req.language,
                    "script": artifact.script,
                    "validation": val_result.to_dict(),
                    "tokens_used": artifact.tokens_used,
                    "scrubbed_secrets": artifact.scrubbed_secrets,
                },
            )

        # 6. Register immutable, SHA-256-pinned validated script.
        saved = rt.db.save_validated_script(
            engagement_id=req.engagement_id,
            operator_id=principal.operator_id,
            target=scope_res.normalized_target,
            language=req.language,
            script_body=artifact.script,
            sha256=val_result.sha256,
            dependencies=artifact.dependencies,
            expected_runtime_sec=artifact.expected_runtime_sec,
            risk_level=artifact.risk_level,
            risk_notes=artifact.risk_notes,
            validation_dict=val_result.to_dict(),
            source="ai_generated",
        )

        gen_audit = rt.db.write_audit_log(
            engagement_id=req.engagement_id,
            operator_id=principal.operator_id,
            target=scope_res.normalized_target,
            resolved_ips=scope_res.resolved_ips,
            tool_or_script=f"llm:generate:{saved['script_id']}",
            language=req.language,
            params={
                "sha256": val_result.sha256,
                "provider_mode": artifact.provider_mode,
                "model": artifact.model,
                "tokens_used": artifact.tokens_used,
                "scrubbed_secrets": artifact.scrubbed_secrets,
                "sanitized_objective": artifact.sanitized_objective,
            },
            started_at=started,
            exit_code=0,
            stdout_summary=(
                f"Generated & validated {req.language} script {saved['script_id']} "
                f"(sha256={val_result.sha256[:12]}..., tokens={artifact.tokens_used})."
            ),
            status="validated",
        )

        response_payload: dict[str, Any] = {
            "status": "validated",
            "audit_id": gen_audit["id"],
            "audit_hash": gen_audit["entry_hash"],
            "script_id": saved["script_id"],
            "engagement_id": req.engagement_id,
            "target": scope_res.normalized_target,
            "pinned_ips": scope_res.resolved_ips,
            "language": req.language,
            "script": artifact.script,
            "sha256": val_result.sha256,
            "metadata": {
                "dependencies": artifact.dependencies,
                "expected_runtime_sec": artifact.expected_runtime_sec,
                "risk_level": artifact.risk_level,
                "risk_notes": artifact.risk_notes,
                "provider_mode": artifact.provider_mode,
                "model": artifact.model,
                "tokens_used": artifact.tokens_used,
                "scrubbed_secrets": artifact.scrubbed_secrets,
            },
            "validation": val_result.to_dict(),
        }

        if req.auto_run and artifact.risk_level != "high":
            run_out = await _dispatch_sandbox_script(
                operator_id=principal.operator_id, script_record=saved
            )
            response_payload["status"] = run_out["status"]
            response_payload["execution"] = run_out

        return JSONResponse(status_code=status.HTTP_200_OK, content=response_payload)

    @application.post("/api/v1/script/validate")
    async def validate_custom_script(
        req: ScriptValidateRequest,
        principal: OperatorPrincipal = Depends(get_principal),
    ) -> JSONResponse:
        """Validate an operator-supplied script in Py/Bash/Go/JS and register if safe."""
        ensure_engagement_access(principal, req.engagement_id)

        scope_res = rt.scope.evaluate_target(req.engagement_id, req.target, resolve_dns=True)
        if not scope_res.allowed:
            audit = rt.db.write_audit_log(
                engagement_id=req.engagement_id,
                operator_id=principal.operator_id,
                target=req.target,
                tool_or_script="validator:custom_script",
                language=req.language,
                status="rejected",
                rejection_reason=scope_res.reason,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"message": scope_res.reason, "audit_id": audit["id"]},
            )

        s_pol = rt.db.get_script_policy(req.language)
        if not s_pol or not s_pol["enabled"]:
            raise HTTPException(status_code=403, detail=f"Language '{req.language}' is disabled.")

        started = utc_now_iso()
        val_result = rt.validator.validate(
            language=req.language,
            script=req.script,
            script_policy=s_pol,
            is_host_allowed=lambda h: rt.scope.is_literal_host_in_scope(req.engagement_id, h),
        )

        if not val_result.passed:
            audit = rt.db.write_audit_log(
                engagement_id=req.engagement_id,
                operator_id=principal.operator_id,
                target=scope_res.normalized_target,
                resolved_ips=scope_res.resolved_ips,
                tool_or_script="validator:custom_script",
                language=req.language,
                params={"sha256": val_result.sha256},
                started_at=started,
                status="validation_failed",
                rejection_reason=val_result.rejection_summary(),
            )
            return JSONResponse(
                status_code=422,
                content={
                    "status": "validation_failed",
                    "audit_id": audit["id"],
                    "audit_hash": audit["entry_hash"],
                    "validation": val_result.to_dict(),
                },
            )

        saved = rt.db.save_validated_script(
            engagement_id=req.engagement_id,
            operator_id=principal.operator_id,
            target=scope_res.normalized_target,
            language=req.language,
            script_body=req.script,
            sha256=val_result.sha256,
            dependencies=[],
            expected_runtime_sec=int(s_pol["max_runtime_sec"]),
            risk_level="low",
            risk_notes=req.risk_notes,
            validation_dict=val_result.to_dict(),
            source="operator_submitted",
        )
        audit = rt.db.write_audit_log(
            engagement_id=req.engagement_id,
            operator_id=principal.operator_id,
            target=scope_res.normalized_target,
            resolved_ips=scope_res.resolved_ips,
            tool_or_script=f"validator:register:{saved['script_id']}",
            language=req.language,
            params={"sha256": val_result.sha256},
            started_at=started,
            exit_code=0,
            stdout_summary=f"Validated operator {req.language} script as {saved['script_id']}.",
            status="validated",
        )
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "status": "validated",
                "script_id": saved["script_id"],
                "sha256": val_result.sha256,
                "audit_id": audit["id"],
                "audit_hash": audit["entry_hash"],
                "validation": val_result.to_dict(),
            },
        )

    @application.post("/api/v1/script/run")
    @application.post("/script/run", include_in_schema=False)
    async def run_script(
        req: ScriptRunRequest,
        principal: OperatorPrincipal = Depends(get_principal),
    ) -> JSONResponse:
        """Execute a registered, validated script inside the Go Sandbox Runner."""
        record = rt.db.get_validated_script(req.script_id)
        if not record:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Validated script '{req.script_id}' not found. Validate or generate first.",
            )
        ensure_engagement_access(principal, str(record["engagement_id"]))

        ok, q_reason, _ = rt.db.check_and_consume_quota(
            operator_id=principal.operator_id,
            period=principal.quota_period,
            max_calls=principal.quota_max_calls,
            max_tokens=principal.quota_max_tokens,
            calls_delta=1,
        )
        if not ok:
            raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=q_reason)

        # High-risk scripts are gated by Two-Person Approval before sandbox execution.
        if record["risk_level"] == "high":
            queued = rt.db.enqueue_approval(
                engagement_id=str(record["engagement_id"]),
                request_type="script_run",
                target=str(record["target"]),
                tool_or_script=str(record["script_id"]),
                payload={"script_id": record["script_id"], "timeout_sec": req.timeout_sec},
                requested_by=principal.operator_id,
            )
            audit = rt.db.write_audit_log(
                engagement_id=str(record["engagement_id"]),
                operator_id=principal.operator_id,
                target=str(record["target"]),
                tool_or_script=f"script:{record['script_id']}",
                language=str(record["language"]),
                params={"approval_id": queued["request_id"], "sha256": record["sha256"]},
                status="pending_approval",
            )
            return JSONResponse(
                status_code=status.HTTP_202_ACCEPTED,
                content={
                    "status": "pending_approval",
                    "approval": queued,
                    "audit_id": audit["id"],
                },
            )

        out = await _dispatch_sandbox_script(
            operator_id=principal.operator_id,
            script_record=record,
            timeout_override=req.timeout_sec,
        )
        return JSONResponse(status_code=status.HTTP_200_OK, content=out)

    @application.get("/api/v1/scripts")
    async def list_scripts(principal: OperatorPrincipal = Depends(get_principal)) -> dict[str, Any]:
        scripts = [
            s
            for s in rt.db.list_validated_scripts(limit=30)
            if principal.can_access_engagement(str(s["engagement_id"]))
        ]
        return {"scripts": scripts}

    # ------------------------------------------------------------------
    # Two-Person Approval Queue Endpoints
    # ------------------------------------------------------------------

    @application.get("/api/v1/approvals")
    async def list_approvals(
        approval_status: str | None = Query(default=None, alias="status"),
        principal: OperatorPrincipal = Depends(get_principal),
    ) -> dict[str, Any]:
        items = [
            a
            for a in rt.db.list_approvals(status=approval_status, limit=50)
            if principal.can_access_engagement(str(a["engagement_id"]))
        ]
        return {"approvals": items}

    @application.post("/api/v1/approvals/{request_id}/decide")
    async def decide_approval(
        request_id: str,
        req: ApprovalDecisionRequest,
        principal: OperatorPrincipal = Depends(get_principal),
    ) -> dict[str, Any]:
        if not principal.can_approve():
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only 'approver' or 'admin' roles may decide queued approval requests.",
            )

        try:
            updated = rt.db.decide_approval(
                request_id=request_id,
                approved_by=principal.operator_id,
                decision=req.decision,
                note=req.note,
            )
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except PermissionError as exc:
            rt.db.write_audit_log(
                engagement_id="SYSTEM",
                operator_id=principal.operator_id,
                target=request_id,
                tool_or_script="approval:self_approve_blocked",
                status="rejected",
                rejection_reason=str(exc),
            )
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

        rt.db.write_audit_log(
            engagement_id=str(updated["engagement_id"]),
            operator_id=principal.operator_id,
            target=str(updated["target"]),
            tool_or_script=f"approval:{req.decision}:{updated['tool_or_script']}",
            params={
                "request_id": request_id,
                "requested_by": updated["requested_by"],
                "note": req.note,
            },
            exit_code=0,
            stdout_summary=f"Request {request_id} {req.decision} by {principal.operator_id}.",
            status="approved" if req.decision == "approved" else "rejected",
            rejection_reason=req.note if req.decision == "rejected" else None,
        )

        execution_out: dict[str, Any] | None = None
        if req.decision == "approved" and req.execute_immediately:
            payload = updated["payload"]
            try:
                if updated["request_type"] == "tool_scan":
                    pol = rt.db.get_tool_policy(str(payload["tool_name"]))
                    if not pol or not pol["enabled"]:
                        raise HTTPException(
                            status_code=403,
                            detail=f"Tool '{payload['tool_name']}' is no longer enabled.",
                        )
                    scope_res = rt.scope.evaluate_target(
                        str(updated["engagement_id"]), str(updated["target"]), resolve_dns=True
                    )
                    if not scope_res.allowed:
                        raise HTTPException(status_code=403, detail=scope_res.reason)
                    execution_out = await _dispatch_mcp_scan(
                        operator_id=str(updated["requested_by"]),
                        engagement_id=str(updated["engagement_id"]),
                        target=scope_res.normalized_target,
                        tool_name=str(payload["tool_name"]),
                        sanitized_params=dict(payload["params"]),
                        timeout_sec=int(payload["timeout_sec"]),
                        allowed_params=pol["allowed_params"],
                        pinned_ips=scope_res.resolved_ips,
                        approval_id=request_id,
                    )
                elif updated["request_type"] == "script_run":
                    rec = rt.db.get_validated_script(str(payload["script_id"]))
                    if not rec:
                        raise HTTPException(status_code=404, detail="Script record missing.")
                    execution_out = await _dispatch_sandbox_script(
                        operator_id=str(updated["requested_by"]),
                        script_record=rec,
                        timeout_override=payload.get("timeout_sec"),
                        approval_id=request_id,
                    )
                succeeded = bool(execution_out and execution_out.get("status") == "completed")
                rt.db.mark_approval_executed(request_id, succeeded=succeeded)
                updated = rt.db.get_approval(request_id) or updated
            except HTTPException as exc:
                rt.db.mark_approval_executed(request_id, succeeded=False)
                execution_out = {"status": "failed", "error": exc.detail}

        return {"approval": updated, "execution": execution_out}

    # ------------------------------------------------------------------
    # Append-Only, Tamper-Evident Audit Log Query & Verification
    # ------------------------------------------------------------------

    @application.get("/api/v1/audit")
    @application.get("/audit", include_in_schema=False)
    async def get_audit_log(
        engagement_id: str | None = Query(default=None),
        operator_id: str | None = Query(default=None),
        audit_status: str | None = Query(default=None, alias="status"),
        limit: int = Query(default=50, ge=1, le=500),
        offset: int = Query(default=0, ge=0),
        principal: OperatorPrincipal = Depends(get_principal),
    ) -> dict[str, Any]:
        # Standard operators see their own records; approvers and admins see full ledger.
        effective_operator = operator_id if principal.can_approve() else principal.operator_id
        records = rt.db.query_audit_log(
            engagement_id=engagement_id,
            operator_id=effective_operator,
            status=audit_status,
            limit=limit,
            offset=offset,
        )
        return {"count": len(records), "entries": records}

    @application.get("/api/v1/audit/verify")
    async def verify_audit_integrity(
        principal: OperatorPrincipal = Depends(get_principal),
    ) -> dict[str, Any]:
        del principal
        return rt.db.verify_audit_chain()

    # ------------------------------------------------------------------
    # Iteration 2: Local AI Model Hub (Ollama / LM Studio / HF GGUF / Quant)
    # ------------------------------------------------------------------

    @application.get("/api/v1/models/hub")
    async def get_model_hub(
        principal: OperatorPrincipal = Depends(get_principal),
    ) -> dict[str, Any]:
        del principal
        active = rt.db.get_or_init_llm_runtime()
        probes = await rt.model_hub.probe_local_runtimes(active)
        return {
            "active_runtime": active,
            "local_probes": probes,
            "providers": rt.model_hub.providers,
            "quantization_profiles": rt.model_hub.quant_profiles,
            "huggingface_catalog": rt.model_hub.catalog,
            "governance": rt.model_hub.governance,
        }

    @application.put("/api/v1/models/runtime")
    async def update_model_runtime(
        req: LLMRuntimeUpdateRequest,
        principal: OperatorPrincipal = Depends(get_principal),
    ) -> dict[str, Any]:
        try:
            default_openai, _ = rt.model_hub.default_urls_for_provider(req.provider)
            raw_url = req.base_url.strip() if req.base_url else default_openai
            openai_url, native_url = validate_llm_endpoint_url(raw_url, req.provider)
            clean_model = validate_model_identifier(req.model)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

        updated = rt.db.update_llm_runtime(
            active_provider=req.provider,
            base_url=openai_url,
            native_url=native_url,
            active_model=clean_model,
            quantization=req.quantization.strip().upper(),
            context_length=req.context_length,
            updated_by=principal.operator_id,
        )
        rt.db.write_audit_log(
            engagement_id="SYSTEM",
            operator_id=principal.operator_id,
            target=openai_url,
            tool_or_script="models:switch_runtime",
            params={
                "provider": req.provider,
                "model": clean_model,
                "quantization": updated["quantization"],
                "context_length": req.context_length,
            },
            exit_code=0,
            stdout_summary=f"Switched Local AI runtime to {req.provider} ({clean_model}, {updated['quantization']}).",
            status="completed",
        )
        return {
            "active_runtime": updated,
            "modelfile": rt.model_hub.render_modelfile(clean_model, req.context_length),
        }

    @application.post("/api/v1/models/recommend")
    async def recommend_quantized_models(
        req: QuantizationRecommendRequest,
        principal: OperatorPrincipal = Depends(get_principal),
    ) -> dict[str, Any]:
        del principal
        try:
            return rt.model_hub.recommend_quantized_models(
                vram_gb=req.vram_gb,
                system_ram_gb=req.system_ram_gb,
                context_length=req.context_length,
                task=req.task,
                custom_hf_repo=req.custom_hf_repo,
                custom_params_b=req.custom_params_b,
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    # ------------------------------------------------------------------
    # Iteration 2: Personalized Agent Skills & Persistent Memory (Brain)
    # ------------------------------------------------------------------

    @application.get("/api/v1/skills")
    async def list_skills(principal: OperatorPrincipal = Depends(get_principal)) -> dict[str, Any]:
        del principal
        return {"skills": rt.db.list_skills(enabled_only=False)}

    @application.post("/api/v1/skills", status_code=status.HTTP_201_CREATED)
    async def create_skill(
        req: SkillCreateRequest,
        principal: OperatorPrincipal = Depends(get_principal),
    ) -> dict[str, Any]:
        existing = rt.db.get_skill(req.skill_id)
        if existing and existing["is_builtin"] and not principal.is_admin():
            raise HTTPException(
                status_code=403, detail="Only 'admin' may overwrite built-in skill definitions."
            )
        try:
            clean_spec = validate_skill_spec(
                {
                    "max_steps": len(req.steps),
                    "expand_wildcard_subdomains": req.expand_wildcard_subdomains,
                    "subdomain_prefixes": req.subdomain_prefixes,
                    "steps": [s.model_dump() for s in req.steps],
                    "prioritization_rules": req.prioritization_rules,
                    "report_focus": req.report_focus,
                }
            )
        except SkillValidationError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

        saved = rt.db.upsert_skill(
            skill_id=req.skill_id,
            name=req.name,
            version="1.0",
            category=req.category,
            description=req.description,
            spec=clean_spec,
            created_by=principal.operator_id,
            enabled=True,
            is_builtin=False,
        )
        rt.db.write_audit_log(
            engagement_id="SYSTEM",
            operator_id=principal.operator_id,
            target=req.skill_id,
            tool_or_script="agent:skill_save",
            params={"steps": len(clean_spec["steps"]), "category": req.category},
            exit_code=0,
            stdout_summary=f"Saved personalized skill '{req.name}' ({req.skill_id}).",
            status="completed",
        )
        return {"skill": saved}

    @application.get("/api/v1/memory")
    async def list_memories(
        engagement_id: str | None = Query(default=None),
        memory_type: str | None = Query(default=None),
        active_only: bool = Query(default=False),
        principal: OperatorPrincipal = Depends(get_principal),
    ) -> dict[str, Any]:
        if engagement_id:
            ensure_engagement_access(principal, engagement_id)
        items = rt.db.list_memories(
            operator_id=principal.operator_id,
            engagement_id=engagement_id,
            memory_type=memory_type,
            active_only=active_only,
        )
        return {"memories": items}

    @application.post("/api/v1/memory", status_code=status.HTTP_201_CREATED)
    async def create_memory(
        req: MemoryCreateRequest,
        principal: OperatorPrincipal = Depends(get_principal),
    ) -> dict[str, Any]:
        if req.engagement_id:
            ensure_engagement_access(principal, req.engagement_id)
            if not rt.db.get_engagement(req.engagement_id):
                raise HTTPException(status_code=404, detail=f"Engagement '{req.engagement_id}' not found.")
        try:
            entry, scrubbed = rt.memory.remember(
                operator_id=principal.operator_id,
                engagement_id=req.engagement_id,
                memory_type=req.memory_type,
                title=req.title,
                content=req.content,
                tags=req.tags,
                pattern_key=req.pattern_key,
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

        rt.db.write_audit_log(
            engagement_id=req.engagement_id or "GLOBAL_OPERATOR",
            operator_id=principal.operator_id,
            target=req.pattern_key or "-",
            tool_or_script=f"agent:memory_add:{req.memory_type}",
            params={"memory_id": entry["id"], "scrubbed_secrets": scrubbed},
            exit_code=0,
            stdout_summary=f"Saved {req.memory_type} memory #{entry['id']}: {entry['title']}",
            status="completed",
        )
        return {"memory": entry, "scrubbed_secrets": scrubbed}

    @application.patch("/api/v1/memory/{memory_id}")
    async def patch_memory(
        memory_id: int,
        req: MemoryPatchRequest,
        principal: OperatorPrincipal = Depends(get_principal),
    ) -> dict[str, Any]:
        try:
            updated = rt.db.set_memory_active(
                memory_id,
                operator_id=principal.operator_id,
                active=req.active,
                allow_override=principal.is_admin(),
            )
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        if not updated:
            raise HTTPException(status_code=404, detail=f"Memory #{memory_id} not found.")
        return {"memory": updated}

    # ------------------------------------------------------------------
    # Iteration 2: Automated Recon Pipeline & Human Judgment Review
    # ------------------------------------------------------------------

    @application.post("/api/v1/recon/run")
    async def run_automated_recon(
        req: ReconRunRequest,
        principal: OperatorPrincipal = Depends(get_principal),
    ) -> dict[str, Any]:
        ensure_engagement_access(principal, req.engagement_id)

        skill = rt.db.get_skill(req.skill_id)
        if not skill or not skill["enabled"]:
            raise HTTPException(status_code=404, detail=f"Active skill '{req.skill_id}' not found.")

        ok, q_reason, _ = rt.db.check_and_consume_quota(
            operator_id=principal.operator_id,
            period=principal.quota_period,
            max_calls=principal.quota_max_calls,
            max_tokens=principal.quota_max_tokens,
            calls_delta=1,
        )
        if not ok:
            raise HTTPException(status_code=429, detail=q_reason)

        try:
            run_record = await rt.agent.execute_run(
                operator_id=principal.operator_id,
                quota_period=principal.quota_period,
                engagement_id=req.engagement_id,
                raw_target=req.target,
                skill_record=skill,
                candidate_subdomains=req.candidate_subdomains,
                http_port_override=req.http_port_override,
                http_scheme_override=req.http_scheme_override,
                http_path_override=req.http_path_override,
                queue_gated_followups=req.queue_gated_followups,
                operator_focus=req.operator_focus,
            )
        except PermissionError as exc:
            audit = rt.db.write_audit_log(
                engagement_id=req.engagement_id,
                operator_id=principal.operator_id,
                target=req.target,
                tool_or_script=f"agent:recon:{req.skill_id}",
                status="rejected",
                rejection_reason=str(exc),
            )
            raise HTTPException(
                status_code=403, detail={"message": str(exc), "audit_id": audit["id"]}
            ) from exc

        return {"run": run_record}

    @application.get("/api/v1/recon/runs")
    async def list_recon_runs(
        engagement_id: str | None = Query(default=None),
        principal: OperatorPrincipal = Depends(get_principal),
    ) -> dict[str, Any]:
        runs = [
            r
            for r in rt.db.list_recon_runs(engagement_id=engagement_id, limit=30)
            if principal.can_access_engagement(str(r["engagement_id"]))
        ]
        return {"runs": runs}

    @application.get("/api/v1/recon/runs/{run_id}")
    async def get_recon_run(
        run_id: str,
        principal: OperatorPrincipal = Depends(get_principal),
    ) -> dict[str, Any]:
        rec = rt.db.get_recon_run(run_id)
        if not rec:
            raise HTTPException(status_code=404, detail=f"Recon run '{run_id}' not found.")
        ensure_engagement_access(principal, str(rec["engagement_id"]))
        return {"run": rec}

    @application.get("/api/v1/recon/runs/{run_id}/report.md")
    async def download_recon_report_markdown(
        run_id: str,
        principal: OperatorPrincipal = Depends(get_principal),
    ) -> PlainTextResponse:
        rec = rt.db.get_recon_run(run_id)
        if not rec:
            raise HTTPException(status_code=404, detail=f"Recon run '{run_id}' not found.")
        ensure_engagement_access(principal, str(rec["engagement_id"]))
        return PlainTextResponse(
            content=str(rec["report_markdown"]),
            media_type="text/markdown; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{run_id}-report.md"'},
        )

    @application.patch("/api/v1/recon/findings/{finding_id}")
    async def review_recon_finding(
        finding_id: int,
        req: FindingReviewRequest,
        principal: OperatorPrincipal = Depends(get_principal),
    ) -> dict[str, Any]:
        existing = rt.db.get_finding(finding_id)
        if not existing:
            raise HTTPException(status_code=404, detail=f"Finding #{finding_id} not found.")
        # Authorize BEFORE modifying the verdict or teaching operator memory.
        ensure_engagement_access(principal, str(existing["engagement_id"]))
        updated = rt.db.review_finding(
            finding_id=finding_id,
            verdict=req.verdict,
            note=req.note,
            reviewed_by=principal.operator_id,
        )
        if not updated:
            raise HTTPException(status_code=404, detail=f"Finding #{finding_id} not found.")

        learned_memory: dict[str, Any] | None = None
        if req.verdict == "false_positive" and req.learn_false_positive_rule:
            learned_memory, _ = rt.memory.remember(
                operator_id=principal.operator_id,
                engagement_id=None,
                memory_type="false_positive_rule",
                title=f"Suppress FP: {updated['title']}",
                content=req.note or f"Analyst verified '{updated['finding_key']}' as false positive.",
                tags=["human-verified", "false-positive", str(updated["category"])],
                pattern_key=str(updated["finding_key"]),
            )

        rt.db.write_audit_log(
            engagement_id=str(updated["engagement_id"]),
            operator_id=principal.operator_id,
            target=str(updated["asset"]),
            tool_or_script=f"analyst:verdict:{req.verdict}",
            params={
                "finding_id": finding_id,
                "finding_key": updated["finding_key"],
                "learned_memory_id": learned_memory["id"] if learned_memory else None,
            },
            exit_code=0,
            stdout_summary=f"Finding #{finding_id} marked '{req.verdict}' by {principal.operator_id}.",
            status="completed",
        )
        return {"finding": updated, "learned_memory": learned_memory}

    application.include_router(workspace_router(workspace, get_principal, ensure_engagement_access))
    application.include_router(
        capability_router(
            registry=rt.registry,
            gate=rt.evidence_gate,
            tls=application_tls,
            expansion=expansion_service,
            db=rt.db,
            store=expansion_service.store,
            get_principal=get_principal,
            ensure_access=ensure_engagement_access,
            artifact_root=str(rt.artifact_root),
        )
    )
    application.include_router(
        offensive_router(
            db=rt.db,
            policies=rt.policies,
            exploitation=rt.exploitation,
            exploration=rt.exploration,
            bounty=rt.bounty,
            pwntools=rt.pwntools,
            loops=rt.loops,
            runner=rt.runner,
            registry=rt.registry,
            store=rt.store,
            get_principal=get_principal,
            ensure_access=ensure_engagement_access,
        )
    )
    application.include_router(
        intel_router(
            db=rt.db,
            outcomes=rt.intel_outcomes,
            coverage=rt.coverage,
            tracker=rt.responses,
            get_principal=get_principal,
            ensure_access=ensure_engagement_access,
        )
    )
    application.state.expansion = expansion_service

    # ------------------------------------------------------------------
    # Optional Web Management Console (Static Assets)
    # ------------------------------------------------------------------

    if STATIC_DIR.is_dir():
        application.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

        @application.api_route("/", methods=["GET", "HEAD"], include_in_schema=False)
        async def serve_console() -> FileResponse:
            return FileResponse(str(STATIC_DIR / "index.html"))

    return application


app = create_app()
