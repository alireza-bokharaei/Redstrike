"""Governed execution of catalogued tools (HexStrike-style layer, 2.3).

The HexStrike fork exposes ~151 tools behind a decision engine; that project has
no licence we can inherit, so nothing is copied. What this module does is
implement the same *shape* natively: one governed entry point, a catalog of 144
tools, and a decision step that runs before any binary does.

Order of checks, and why:

1. **Catalog membership** — an unknown tool is a typo or an attempt to reach a
   binary the deployment did not choose to expose.
2. **Scope** — the target must satisfy the allowlist, the signed RoE window and
   DNS pinning. This runs before policy so an out-of-scope target is reported as
   out of scope, not as "needs consent".
3. **Posture/consent** — the policy row for the tool plus the engagement posture
   decides whether the operator may run it. High-impact tools additionally need a
   second human, which is handled by returning ``pending_approval`` rather than
   executing.
4. **argv construction** — done by :func:`mcp_server.catalog.build_argv`, so the
   flag surface is deny-by-default and the target is pinned by IP.
5. **Execution** — through the MCP bridge into the executor, which resolves the
   binary, re-pins the target and byte-caps the output.

A missing binary is reported as ``unavailable`` with the validated argv, never
faked. On this image only a handful of the 144 catalogued tools are installed,
and the honest answer is part of the product.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from gateway.auth import OperatorPrincipal
from gateway.db import Database
from gateway.evidence import redact_text
from gateway.offensive_policy import OffensivePolicyEngine
from gateway.policy import ScopePolicyEngine
from mcp_server.catalog import CATALOG, ArgvBuildError, build_argv, get_entry, takes_artifact


class ScanError(ValueError):
    """The scan request is not permitted or cannot be executed."""


@dataclass
class ToolRunResult:
    tool: str
    target: str
    status: str
    argv: list[str]
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int
    pinned_ip: str | None
    decision: dict[str, Any]
    policy_id: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "target": self.target,
            "status": self.status,
            "argv": self.argv,
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "duration_ms": self.duration_ms,
            "pinned_ip": self.pinned_ip,
            "decision": self.decision,
            "policy_id": self.policy_id,
        }


class ScanRunner:
    """Resolve, authorise and execute one catalogued tool call."""

    def __init__(
        self,
        *,
        db: Database,
        scope: ScopePolicyEngine,
        policies: OffensivePolicyEngine,
        mcp: Any,
    ) -> None:
        self.db = db
        self.scope = scope
        self.policies = policies
        self.mcp = mcp

    # ------------------------------------------------------------------
    def installed_tools(self) -> dict[str, str]:
        import shutil

        from mcp_server.catalog import is_path_binary

        found: dict[str, str] = {}
        for name, entry in CATALOG.items():
            if not is_path_binary(entry):
                continue
            path = shutil.which(entry.binary)
            if path:
                found[name] = path
        return found

    def policy_for(self, tool: str, decision_policy_id: str | None = None) -> dict[str, Any]:
        """Which policy row governs this tool's flags (read-only vs. active)."""
        candidates = [decision_policy_id, f"tool:{tool}", "tool:nmap" if tool == "nmap_aggressive" else None]
        for policy_id in candidates:
            if not policy_id:
                continue
            record = self.policies.get(policy_id)
            if record is not None:
                return {
                    "policy_id": record.policy_id,
                    "allowed_flags": list(record.bounds.get("allowed_flags", [])),
                    "refused_flags": list(record.bounds.get("refused_flags", [])),
                    "target_flag": record.bounds.get("target_flag"),
                }
        return {"policy_id": None, "allowed_flags": [], "refused_flags": [], "target_flag": None}

    # ------------------------------------------------------------------
    async def run(
        self,
        *,
        principal: OperatorPrincipal,
        engagement_id: str,
        tool: str,
        target: str,
        flags: list[str] | None = None,
        mission_id: str | None = None,
        timeout_sec: int = 60,
    ) -> ToolRunResult:
        entry = get_entry(tool)
        if entry is None:
            raise ScanError(f"'{tool}' is not in the catalog; nothing was executed.")

        # Two kinds of target, and conflating them is a real bug: a network tool
        # takes a scoped host (checked against the allowlist and pinned), while a
        # binary tool takes an artifact inside the configured root (checked for
        # traversal). "Read the hardening flags of 127.0.0.1" is a category error
        # and is refused as one.
        artifact_tool = takes_artifact(entry)
        if artifact_tool:
            normalized_target = target.strip()
            pinned_ip = None
        else:
            decision_scope = self.scope.evaluate_target(engagement_id, target)
            if not decision_scope.allowed:
                self._audit(
                    principal, engagement_id, tool, target, "rejected",
                    decision_scope.reason or "Target is out of scope.", mission_id=mission_id,
                )
                raise ScanError(decision_scope.reason or "Target is out of scope.")
            normalized_target = decision_scope.normalized_target
            pinned_ip = (decision_scope.resolved_ips or [None])[0]

        policy_id = f"tool:{tool}"
        semantics = self.policy_for(tool, policy_id)

        # Build the argv *before* asking for consent: a refused flag is a
        # capability question, not a permission question. Reporting "needs
        # consent" for `sqlmap --os-shell` would imply that consent would unlock
        # it, which is false in every posture.
        try:
            argv = build_argv(
                tool,
                normalized_target,
                flags=list(flags or []),
                allowed_flags=semantics["allowed_flags"],
                refused_flags=semantics["refused_flags"],
                target_flag=semantics["target_flag"],
            )
        except ArgvBuildError as exc:
            self._audit(
                principal, engagement_id, tool, target, "rejected", str(exc), mission_id=mission_id
            )
            raise ScanError(str(exc)) from exc

        decision = self.policies.evaluate_action(
            principal=principal,
            engagement_id=engagement_id,
            action=f"tool:{tool}",
            tool_name=tool,
            policy_id=policy_id if self.policies.get(policy_id) else None,
        )

        if decision.two_person_required:
            approval = self.db.enqueue_approval(
                engagement_id=engagement_id,
                request_type="tool_execution",
                target=target,
                tool_or_script=tool,
                payload={
                    "tool": tool,
                    "flags": list(flags or []),
                    "mission_id": mission_id,
                    "policy_id": decision.policy_id,
                },
                requested_by=principal.operator_id,
            )
            self._audit(
                principal, engagement_id, tool, target, "pending",
                f"{tool} needs a second approval ({decision.reason}).", mission_id=mission_id,
            )
            return ToolRunResult(
                tool=tool,
                target=target,
                status="pending_approval",
                argv=[],
                exit_code=0,
                stdout=json.dumps(
                    {"approval_id": approval["request_id"], "policy_id": decision.policy_id},
                    indent=2,
                ),
                stderr=(
                    "This is a high-impact action: a different approver must grant it before "
                    "the tool is executed."
                ),
                duration_ms=0,
                pinned_ip=pinned_ip,
                decision=decision.to_dict(),
                policy_id=decision.policy_id,
            )

        if not decision.allowed:
            self._audit(
                principal, engagement_id, tool, target, "rejected",
                decision.reason, mission_id=mission_id,
            )
            raise ScanError(decision.reason)

        if not self.installed_tools().get(tool):
            self._audit(
                principal, engagement_id, tool, target, "unavailable",
                f"Binary '{entry.binary}' is not installed on this image.", mission_id=mission_id,
            )
            return ToolRunResult(
                tool=tool,
                target=target,
                status="unavailable",
                argv=argv,
                exit_code=127,
                stdout=json.dumps({"validated_argv": argv, "target": target}, indent=2),
                stderr=(
                    f"Binary '{entry.binary}' is not installed on this runner image. "
                    "argv was validated; nothing was executed."
                ),
                duration_ms=0,
                pinned_ip=pinned_ip,
                decision=decision.to_dict(),
                policy_id=decision.policy_id,
            )

        try:
            result = await self.mcp.call_tool(
                tool_name=tool,
                target=normalized_target,
                params={"flags": list(flags or [])},
                max_timeout=max(1, min(int(timeout_sec), 300)),
                allowed_params={
                    "allowed_flags": semantics["allowed_flags"],
                    "refused_flags": semantics["refused_flags"],
                    "target_flag": semantics["target_flag"],
                },
                pinned_ips=list((pinned_ip,) if pinned_ip else []),
            )
        except Exception as exc:  # noqa: BLE001 - the bridge is a separate process
            # A tool service that is down or refused the call is a *deployment*
            # condition, not an operator error and not a finding. Report it as such
            # instead of letting it surface as a 500 with a stack trace.
            from gateway.mcp_client import MCPClientError

            reason = str(exc) if isinstance(exc, MCPClientError) else f"{type(exc).__name__}: {exc}"
            self._audit(
                principal, engagement_id, tool, target, "unavailable", reason,
                mission_id=mission_id,
                params={"argv": argv, "policy_id": decision.policy_id},
            )
            return ToolRunResult(
                tool=tool,
                target=target,
                status="unavailable",
                argv=argv,
                exit_code=127,
                stdout=json.dumps({"validated_argv": argv, "target": target}, indent=2),
                stderr=(
                    "The tool-execution service did not answer, so nothing was executed: "
                    f"{reason[:300]}"
                ),
                duration_ms=0,
                pinned_ip=pinned_ip,
                decision=decision.to_dict(),
                policy_id=decision.policy_id,
            )
        status = "completed" if result.get("exit_code", 0) == 0 else "failed"
        if result.get("timed_out"):
            status = "timed_out"
        self._audit(
            principal, engagement_id, tool, target, status,
            redact_text(str(result.get("stderr", "")))[:400] or f"{tool} exited {result.get('exit_code')}",
            mission_id=mission_id,
            params={"argv": argv, "policy_id": decision.policy_id, "pinned_ip": pinned_ip},
        )
        return ToolRunResult(
            tool=tool,
            target=target,
            status=status,
            argv=argv,
            exit_code=int(result.get("exit_code", 0)),
            stdout=result.get("stdout", ""),
            stderr=result.get("stderr", ""),
            duration_ms=int(result.get("duration_ms", 0)),
            pinned_ip=pinned_ip,
            decision=decision.to_dict(),
            policy_id=decision.policy_id,
        )

    # ------------------------------------------------------------------
    def _audit(
        self,
        principal: OperatorPrincipal,
        engagement_id: str,
        tool: str,
        target: str,
        status: str,
        summary: str,
        *,
        mission_id: str | None = None,
        params: dict[str, Any] | None = None,
    ) -> None:
        self.db.write_audit_log(
            engagement_id=engagement_id,
            operator_id=principal.operator_id,
            target=target or tool,
            tool_or_script=f"tool:{tool}",
            params={"mission_id": mission_id, **(params or {})},
            status="completed" if status == "completed" else status,
            stdout_summary=summary[:500],
            rejection_reason=summary[:500] if status == "rejected" else None,
        )
