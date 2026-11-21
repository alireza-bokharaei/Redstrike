"""Bounded, restart-safe mission coordination, without another queue/database.

The planner expands explicitly approved hosts into existing read-only Skill
intents. This is intentionally NOT an unconstrained autonomous exploitation
agent. Pause drains the current intent; cancellation stops at the next action.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import html
from typing import Any

from gateway.agent import PersonalizedReconAgent
from gateway.auth import AuthManager, OperatorPrincipal
from gateway.db import Database
from gateway.evidence import EvidenceService, redact_text, retest_settings
from gateway.policy import ScopePolicyEngine
from gateway.sandbox_client import GoSandboxClient, SandboxClientError
from gateway.skills import validate_skill_spec
from gateway.workspace_models import HTTPSettings, MissionCreateRequest
from gateway.workspace_store import MissionBudgetExceeded, WorkspaceConflict, WorkspaceStore


class MissionCancelled(RuntimeError):
    pass


class MissionService:
    def __init__(
        self,
        *,
        db: Database,
        auth: AuthManager,
        scope: ScopePolicyEngine,
        agent: PersonalizedReconAgent,
        sandbox: GoSandboxClient,
        registry: Any | None = None,
    ) -> None:
        self.db, self.auth, self.scope, self.agent = db, auth, scope, agent
        self.registry = registry
        self.store = WorkspaceStore(db)
        self.evidence = EvidenceService(db=db, store=self.store, scope=scope, sandbox=sandbox)
        self._tasks: dict[str, asyncio.Task[None]] = {}

    def audit(
        self,
        mission: dict[str, Any],
        action: str,
        operator: str,
        *,
        status: str = "completed",
        detail: str = "",
    ) -> None:
        self.db.write_audit_log(
            engagement_id=mission["engagement_id"],
            operator_id=operator,
            target=mission["mission_id"],
            tool_or_script=f"mission:{action}",
            params={"mission_id": mission["mission_id"]},
            status=status,
            stdout_summary=redact_text(detail)[:1000],
        )

    def recover(self) -> None:
        for row in self.store.recover_interrupted():
            self.audit(
                row,
                "restart_recovery",
                "system",
                detail="Interrupted mission paused; no automatic target contact.",
            )

    async def close(self) -> None:
        tasks = dict(self._tasks)
        for task in tasks.values():
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks.values(), return_exceptions=True)
        # Cancellation before a task's first event-loop tick never enters its
        # try/finally. Do not leave that mission running after a clean shutdown.
        for mission_id in tasks:
            mission = self.store.get_mission(mission_id)
            if mission and mission["status"] in {"running", "pausing", "cancelling"}:
                status = "cancelled" if mission["status"] == "cancelling" else "paused"
                self.store.finish(mission_id, status, "Gateway stopped; no automatic resume.")
                self.audit(
                    mission, f"shutdown_{status}", "system", detail="Stopped before worker startup."
                )
        self._tasks.clear()

    def create(self, request: MissionCreateRequest, principal: OperatorPrincipal) -> dict[str, Any]:
        skill = self.db.get_skill(request.skill_id)
        if not skill or not skill["enabled"]:
            raise ValueError("An enabled Skill is required.")
        # Validate even persisted custom skills; a DB row cannot enlarge the
        # autonomous tool surface. Snapshot the plan; recheck live policies later.
        skill["spec"] = validate_skill_spec(skill["spec"])
        targets: list[str] = []
        for raw in request.targets:
            if any(c in raw for c in "/\\@?#% \t\r\n"):
                raise ValueError(
                    "Mission targets must be plain hostnames or IP literals, not URLs or commands."
                )
            result = self.scope.evaluate_target(request.engagement_id, raw, resolve_dns=False)
            if not result.allowed:
                raise PermissionError(result.reason)
            if result.normalized_target not in targets:
                targets.append(result.normalized_target)
        if not principal.can_access_engagement(request.engagement_id):
            raise PermissionError("The operator is not assigned to this engagement.")

        # 2.2: a declared mode freezes a ceiling onto the mission. Omitted modes
        # keep the legacy 2.1 bounds, so older clients behave exactly as before.
        mode_id = getattr(request, "mode_id", None)
        mode_ceiling: dict[str, Any] = {}
        if mode_id:
            if self.registry is None:
                raise ValueError("Operational modes are not configured on this Gateway.")
            # A composed spec ("pentest+ssl_tls_analysis") is a first-class mode: the
            # narrowest ceiling of its parts applies and the mandatory obligations are
            # the union, so composing never loosens a limit.
            composition = None
            if "+" in str(mode_id):
                composed, composition = self.registry.compose(
                    [p.strip() for p in str(mode_id).split("+") if p.strip()]
                )
                if composed.mode_id != mode_id:
                    raise ValueError(
                        f"Composed mode '{mode_id}' does not match the computed order "
                        f"'{composed.mode_id}'."
                    )
            elif self.registry.is_composition_alias(mode_id):
                # A declared shorthand ("pentest_plus_tls") resolves to the same
                # composed definition, and the audit says which parts it named.
                composed, composition = self.registry.compose([mode_id])
                composition["requested_as"] = mode_id
                mode_id = composed.mode_id
            mode = self.registry.enforce_ceiling(
                self.db,
                mode_id,
                target_count=len(targets),
                max_actions=request.max_actions,
                max_seconds=request.max_seconds,
            )
            mode_ceiling = {
                "max_hosts": mode.ceiling.max_hosts,
                "max_actions": mode.ceiling.max_actions,
                "max_seconds": mode.ceiling.max_seconds,
                "mandatory_capabilities": sorted(mode.mandatory_capabilities),
                "expansion_clauses": list(mode.expansion_clauses),
                "captured_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            }
            if composition is not None:
                mode_ceiling["composition"] = composition

        mission = self.store.create_mission(
            engagement_id=request.engagement_id,
            requested_by=principal.operator_id,
            name=redact_text(request.name.strip()),
            goal=redact_text(request.goal.strip()),
            targets=targets,
            skill=skill,
            http=request.http.model_dump(),
            capture_evidence=request.capture_evidence,
            max_actions=request.max_actions,
            max_seconds=request.max_seconds,
        )
        if mode_id:
            self.store.bind_mode(mission["mission_id"], mode_id, mode_ceiling)
            mission = self.store.get_mission(mission["mission_id"]) or mission
        self.audit(
            mission,
            "create",
            principal.operator_id,
            detail=(
                f"Planned {len(targets)} scope-checked read-only intents."
                + (
                    f" Mode={mode_id} ceiling={mode_ceiling.get('max_actions')} actions/"
                    f"{mode_ceiling.get('max_seconds')}s."
                    if mode_id
                    else " Legacy 2.1 bounds (no mode declared)."
                )
            ),
        )
        return mission

    async def start(self, mission_id: str, actor: OperatorPrincipal) -> dict[str, Any]:
        current = self.store.get_mission(mission_id)
        if not current:
            raise WorkspaceConflict("Mission not found.")
        if not actor.can_access_engagement(current["engagement_id"]) or (
            actor.operator_id != current["requested_by"] and not actor.is_admin()
        ):
            raise PermissionError("Only the owner or an assigned admin can control this mission.")
        owner = self.auth.get_operator(str(current["requested_by"]))
        if not owner or not owner.can_access_engagement(current["engagement_id"]):
            raise PermissionError(
                "The original operator is no longer assigned; create a new mission under an authorized identity."
            )
        # Execution always charges the original owner, even if an admin resumes.
        if mission_id in self._tasks:
            raise WorkspaceConflict("The mission already has a worker.")
        mission = self.store.start_mission(mission_id)
        self.audit(
            mission,
            "start",
            actor.operator_id,
            detail="Explicit execution authorized; finite budgets are active.",
        )
        self._tasks[mission_id] = asyncio.create_task(
            self._drive(mission, owner), name=f"redgate:{mission_id}"
        )
        return mission

    async def _drive(self, mission: dict[str, Any], owner: OperatorPrincipal) -> None:
        mission_id = mission["mission_id"]
        current_intent: dict[str, Any] | None = None

        async def before_action(stage: str, tool: str) -> None:
            state = self.store.get_mission(mission_id)
            if not state or state["status"] == "cancelling":
                raise MissionCancelled("Operator requested cancellation.")
            self.store.reserve_action(mission_id)
            self.evidence.consume_quota(owner)
            self.db.write_audit_log(
                engagement_id=mission["engagement_id"],
                operator_id=owner.operator_id,
                target=current_intent["target"] if current_intent else mission_id,
                tool_or_script="mission:action_reserved",
                status="completed",
                params={"mission_id": mission_id, "stage": stage, "tool": tool},
            )

        try:
            deadline = dt.datetime.fromisoformat(mission["deadline_at"])
            remaining = max(0.001, (deadline - dt.datetime.now(dt.timezone.utc)).total_seconds())
            async with asyncio.timeout(remaining):
                for intent in mission["intents"]:
                    if intent["status"] != "pending":
                        continue  # completed intents are never silently replayed
                    current = self.store.get_mission(mission_id) or mission
                    if current["status"] == "pausing":
                        self.store.finish(mission_id, "paused")
                        self.audit(
                            mission,
                            "paused",
                            owner.operator_id,
                            detail="Current intent drained; remaining intents are untouched.",
                        )
                        return
                    if current["status"] == "cancelling":
                        raise MissionCancelled("Operator requested cancellation.")
                    current_intent = intent
                    self.store.start_intent(intent["intent_id"])
                    try:
                        settings = HTTPSettings(**mission["http"])
                        params = settings.tool_params()
                        run = await self.agent.execute_run(
                            operator_id=owner.operator_id,
                            quota_period=owner.quota_period,
                            engagement_id=mission["engagement_id"],
                            raw_target=intent["target"],
                            skill_record=mission["skill_snapshot"],
                            candidate_subdomains=[],
                            http_scheme_override=settings.scheme,
                            http_port_override=int(params["port"]),
                            http_path_override=settings.path,
                            http_method_override=settings.method,
                            queue_gated_followups=True,
                            operator_focus=mission["goal"],
                            before_action=before_action,
                        )
                        self.store.checkpoint_run(intent["intent_id"], run["run_id"])
                        warning = ""
                        if mission["capture_evidence"]:
                            try:
                                await self.evidence.capture(
                                    principal=owner,
                                    engagement_id=mission["engagement_id"],
                                    target=intent["target"],
                                    settings=settings,
                                    mission_id=mission_id,
                                    run_id=run["run_id"],
                                    before_io=before_action,
                                )
                            except (SandboxClientError, PermissionError) as exc:
                                warning = redact_text(str(exc))[:500]
                                self.audit(
                                    mission,
                                    "evidence_unavailable",
                                    owner.operator_id,
                                    status="error",
                                    detail=warning,
                                )
                        self.store.finish_intent(
                            intent["intent_id"], "completed", run_id=run["run_id"], error=warning
                        )
                        self.audit(
                            mission,
                            "intent_completed",
                            owner.operator_id,
                            detail=f"Intent {intent['intent_id']} bound to {run['run_id']}.",
                        )
                    except PermissionError as exc:
                        reason = redact_text(str(exc))[:500]
                        self.store.finish_intent(intent["intent_id"], "failed", error=reason)
                        self.audit(
                            mission,
                            "intent_rejected",
                            owner.operator_id,
                            status="rejected",
                            detail=reason,
                        )
                    current_intent = None
                final = self.store.get_mission(mission_id) or mission
                if final["status"] == "cancelling":
                    raise MissionCancelled("Operator requested cancellation.")
                status = (
                    "failed"
                    if any(i["status"] == "failed" for i in final["intents"])
                    else "completed"
                )
                self.store.finish(mission_id, status)
                self.audit(
                    mission,
                    status,
                    owner.operator_id,
                    detail="All planned intents reached a terminal state; findings still require human review.",
                )
        except MissionCancelled as exc:
            self.store.finish(mission_id, "cancelled", str(exc))
            self.audit(mission, "cancelled", owner.operator_id, detail=str(exc))
        except (MissionBudgetExceeded, TimeoutError) as exc:
            if current_intent:
                self.store.finish_intent(
                    current_intent["intent_id"],
                    "failed",
                    error="Execution stopped by the mission budget.",
                )
            self.store.finish(
                mission_id, "budget_exhausted", str(exc) or "Absolute mission deadline exceeded."
            )
            self.audit(
                mission,
                "budget_exhausted",
                owner.operator_id,
                status="rejected",
                detail=str(exc) or "Deadline exceeded.",
            )
        except asyncio.CancelledError:
            # Gateway shutdown is not permission to resume on restart. The
            # already-reserved action budget and any completed run remain durable.
            if current_intent:
                state = self.store.get_mission(mission_id) or mission
                intent = next(
                    i for i in state["intents"] if i["intent_id"] == current_intent["intent_id"]
                )
                self.store.finish_intent(
                    intent["intent_id"],
                    "completed" if intent["run_id"] else "pending",
                    error="Gateway stopped; explicit resume required.",
                )
            state = self.store.get_mission(mission_id) or mission
            stopped_status = "cancelled" if state["status"] == "cancelling" else "paused"
            self.store.finish(mission_id, stopped_status, "Gateway stopped; no automatic resume.")
            self.audit(
                mission,
                f"shutdown_{stopped_status}",
                "system",
                detail="No automatic target contact on the next startup.",
            )
            raise
        except Exception as exc:
            reason = f"Execution failed safely ({type(exc).__name__}); inspect the audit ledger."
            if current_intent:
                self.store.finish_intent(current_intent["intent_id"], "failed", error=reason)
            self.store.finish(mission_id, "failed", reason)
            self.audit(mission, "failed", owner.operator_id, status="error", detail=reason)
        finally:
            self._tasks.pop(mission_id, None)

    def asset_graph(self, engagement_id: str) -> dict[str, Any]:
        assets = self.store.list_assets(engagement_id, limit=200)
        nodes = []
        for asset in assets:
            active = self.scope.evaluate_target(
                engagement_id, asset["host"], resolve_dns=False
            ).allowed
            nodes.append(
                {
                    "id": asset["asset_id"],
                    "label": asset["locator"],
                    "kind": asset["kind"],
                    "status": "tested"
                    if asset["run_count"] or asset["evidence_count"]
                    else "untested",
                    "in_scope": active,
                    "run_count": asset["run_count"],
                    "evidence_count": asset["evidence_count"],
                }
            )
        visible = {n["id"] for n in nodes}
        return {
            "nodes": nodes,
            "edges": [
                {"source": a["parent_id"], "target": a["asset_id"], "relation": "contains"}
                for a in assets
                if a["parent_id"] in visible
            ],
            "coverage": self.store.coverage(engagement_id),
            "truncated": self.store.coverage(engagement_id)["total"] > len(nodes),
        }

    def exploration_graph(self, mission: dict[str, Any]) -> dict[str, Any]:
        root_id = f"goal:{mission['mission_id']}"
        nodes: dict[str, dict[str, Any]] = {
            root_id: {
                "id": root_id,
                "kind": "goal",
                "label": mission["goal"],
                "status": mission["status"],
            }
        }
        edges: list[dict[str, str]] = []
        for intent in mission["intents"]:
            intent_id = intent["intent_id"]
            nodes[intent_id] = {
                "id": intent_id,
                "kind": "intent",
                "label": intent["target"],
                "status": intent["status"],
                "asset_id": intent["asset_id"],
                "run_id": intent["run_id"],
            }
            edges.append({"source": root_id, "target": intent_id, "relation": "spawns"})
            run = self.db.get_recon_run(intent["run_id"]) if intent["run_id"] else None
            if not run:
                continue
            for position, step in enumerate(run["steps"][:6]):
                node_id = f"fact:{run['run_id']}:{position}"
                nodes[node_id] = {
                    "id": node_id,
                    "kind": "fact",
                    "label": step["tool"],
                    "status": step["status"],
                    "asset_id": intent["asset_id"],
                }
                edges.append({"source": intent_id, "target": node_id, "relation": "yields"})
            for finding in run["findings"]:
                try:
                    retest_settings(finding, run)
                    supported = True
                except ValueError:
                    supported = False
                node_id = f"finding:{finding['id']}"
                nodes[node_id] = {
                    "id": node_id,
                    "kind": "finding",
                    "label": finding["title"],
                    "status": finding["analyst_verdict"],
                    "severity": finding["severity"],
                    "asset_id": intent["asset_id"],
                    "finding_id": finding["id"],
                    "retest_supported": supported,
                    "latest_retest": next(iter(self.store.list_retests(finding["id"])), None),
                    "requires_human_judgment": bool(finding["requires_human_judgment"]),
                }
                edges.append({"source": intent_id, "target": node_id, "relation": "yields"})
            for evidence in self.store.list_evidence(
                mission["engagement_id"], run_id=run["run_id"], limit=100
            ):
                node_id = evidence["evidence_id"]
                nodes[node_id] = {
                    "id": node_id,
                    "kind": "evidence",
                    "label": evidence["evidence_id"],
                    "status": "intact" if evidence["integrity_valid"] else "integrity_error",
                    "asset_id": evidence["asset_id"],
                    "sha256": evidence["sha256"],
                }
                edges.append({"source": intent_id, "target": node_id, "relation": "observes"})
        # Bound browser/export work, and never return dangling graph edges.
        visible_nodes = list(nodes.values())[:500]
        visible = {n["id"] for n in visible_nodes}
        return {
            "nodes": visible_nodes,
            "edges": [e for e in edges if e["source"] in visible and e["target"] in visible],
            "truncated": len(nodes) > len(visible_nodes),
        }

    def report(self, mission: dict[str, Any]) -> str:
        def safe(value: Any) -> str:
            return html.escape(str(value)).replace("|", "\\|").replace("\n", " ").replace("`", "'")

        lines = [
            f"# Redstrike 2.3.1 — {safe(mission['name'])}",
            "",
            f"- Mission: `{mission['mission_id']}`",
            f"- Engagement: `{safe(mission['engagement_id'])}`",
            f"- State: **{mission['status']}**",
            f"- Goal: {safe(mission['goal'])}",
            f"- Actions: {mission['used_actions']} / {mission['max_actions']}",
            f"- Absolute deadline: {safe(mission['deadline_at'] or 'not started')}",
            "",
            "> Read-only observations, not proof of exploitability. Human review is required.",
            "",
            "## Execution and findings",
            "",
        ]
        for intent in mission["intents"]:
            lines += [f"### {safe(intent['target'])} — {intent['status']}", ""]
            if intent["error"]:
                lines += [f"Note: {safe(intent['error'])}", ""]
            run = self.db.get_recon_run(intent["run_id"]) if intent["run_id"] else None
            if not run:
                lines += ["No completed recon run is bound to this intent.", ""]
                continue
            lines += [
                f"Run: `{run['run_id']}`",
                "",
                "| Finding | Severity | Analyst verdict | Latest retest |",
                "|---|---|---|---|",
            ]
            for finding in run["findings"]:
                retests = self.store.list_retests(finding["id"])
                lines.append(
                    f"| {safe(finding['title'])} | {safe(finding['severity'])} | {safe(finding['analyst_verdict'])} | {retests[0]['outcome'] if retests else 'not run'} |"
                )
            lines += [""]
        lines += [
            "## Redacted HTTP evidence",
            "",
            "Hashes cover stored, redacted snapshots, not unredacted wire traffic.",
            "",
        ]
        for evidence in self.store.list_evidence(
            mission["engagement_id"], mission_id=mission["mission_id"], limit=100
        ):
            payload = evidence["payload"]
            lines += [
                f"- `{evidence['evidence_id']}` — {safe(payload['method'])} {safe(payload['url'])}; HTTP {payload['status_code']}",
                f"  - SHA-256: `{evidence['sha256']}`; integrity: {'valid' if evidence['integrity_valid'] else 'FAILED'}",
            ]
        return "\n".join(lines) + "\n"
