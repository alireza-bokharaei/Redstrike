"""Standard MCP JSON-RPC 2.0 stdio server entrypoint (compatible with Claude Code).

Exposes policy-enabled Redstrike recon tools and `list_recon_skills` over newline-delimited
JSON-RPC 2.0 stdio while strictly enforcing `config/allowlist.yaml`, parameter whitelists,
and `config/tool_policy.yaml` (medium/high-risk tools still require Two-Person Gateway approval).
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import sys
from pathlib import Path
from typing import Any

import yaml

from mcp_server import __version__
from mcp_server.executor import MCPToolExecutor
from mcp_server.catalog import catalog_size
from mcp_server.tools import (
    CATALOG_TOOL_INPUT_SCHEMA,
    MCP_TOOL_CATALOG,
    ToolParamValidationError,
)

MCP_PROTOCOL_VERSION = "2024-11-05"
executor = MCPToolExecutor()


def _config_dir() -> Path:
    return Path(os.environ.get("REDGATE_CONFIG_DIR", "config"))


def _load_tool_policies() -> dict[str, dict[str, Any]]:
    raw = yaml.safe_load((_config_dir() / "tool_policy.yaml").read_text(encoding="utf-8")) or {}
    return {item["tool_name"]: item for item in raw.get("tools", [])}


def _target_matches_rule(target: str, rule: str) -> bool:
    t = target.strip().lower().rstrip(".")
    r = rule.strip().lower().rstrip(".")
    if not t or not r:
        return False
    try:
        t_ip = ipaddress.ip_address(t)
        if "/" in r:
            return t_ip in ipaddress.ip_network(r, strict=False)
        return t_ip == ipaddress.ip_address(r)
    except ValueError:
        pass
    if r.startswith("*."):
        suffix = r[2:]
        return t.endswith("." + suffix) and t != suffix
    return t == r


def _check_target_in_any_active_allowlist(target: str) -> tuple[bool, list[str], str]:
    """Ensure even direct stdio MCP calls from Claude Code stay inside allowlist.yaml."""
    raw = yaml.safe_load((_config_dir() / "allowlist.yaml").read_text(encoding="utf-8")) or {}
    for eng in raw.get("engagements", []):
        if not eng.get("active", True):
            continue
        for entry in eng.get("targets", []):
            rule = str(entry.get("target", "")).strip()
            if rule and _target_matches_rule(target, rule):
                return True, [], ""
    return False, [], f"Target '{target}' is not in any active engagement allowlist."


def list_exposed_tools() -> list[dict[str, Any]]:
    policies = _load_tool_policies()
    tools: list[dict[str, Any]] = []
    for name, tool in MCP_TOOL_CATALOG.items():
        pol = policies.get(name, {})
        if pol.get("enabled", False):
            tools.append(
                {
                    "name": tool.name,
                    "description": tool.description,
                    "inputSchema": tool.input_schema,
                }
            )
    tools.append(
        {
            "name": "redstrike_tool",
            "description": (
                f"Run any of the {catalog_size()} catalogued offensive tools. Flags must appear "
                "in the engagement's policy row; argv is built as an argument vector."
            ),
            "inputSchema": CATALOG_TOOL_INPUT_SCHEMA,
        }
    )
    tools.append(
        {
            "name": "list_recon_skills",
            "description": "List declarative Redstrike recon & triage Skills available in skills/*.yaml.",
            "inputSchema": {"type": "object", "additionalProperties": False, "properties": {}},
        }
    )
    return tools


async def dispatch_tool_call(name: str, arguments: dict[str, Any] | None) -> dict[str, Any]:
    if name == "list_recon_skills":
        skills_dir = Path(os.environ.get("REDGATE_SKILLS_DIR", "skills"))
        items: list[dict[str, Any]] = []
        if skills_dir.is_dir():
            for p in sorted(skills_dir.glob("*.yaml")):
                doc = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
                items.append(
                    {
                        "id": doc.get("id"),
                        "name": doc.get("name"),
                        "category": doc.get("category"),
                        "description": str(doc.get("description", "")).strip(),
                        "steps": [s.get("tool") for s in doc.get("steps", [])],
                    }
                )
        return {
            "content": [{"type": "text", "text": json.dumps({"skills": items}, indent=2)}],
            "isError": False,
        }

    policies = _load_tool_policies()
    pol = policies.get(name)
    if not pol or not pol.get("enabled", False):
        return {
            "content": [{"type": "text", "text": f"POLICY_DENIED: tool '{name}' is disabled."}],
            "isError": True,
        }
    if pol.get("requires_approval", True):
        return {
            "content": [
                {
                    "type": "text",
                    "text": (
                        f"APPROVAL_REQUIRED: '{name}' requires Two-Person approval via "
                        "Redstrike Gateway POST /api/v1/scan."
                    ),
                }
            ],
            "isError": True,
        }

    args = dict(arguments or {})
    target = str(args.pop("target", "")).strip()
    allowed, pinned_ips, reason = _check_target_in_any_active_allowlist(target)
    if not allowed:
        return {
            "content": [{"type": "text", "text": f"SCOPE_DENIED: {reason}"}],
            "isError": True,
        }

    try:
        res = await executor.execute(
            tool_name=name,
            target=target,
            params=args,
            timeout_sec=int(pol.get("max_timeout", 20)),
            allowed_params_policy=pol.get("allowed_params"),
            pinned_ips=pinned_ips,
        )
    except ToolParamValidationError as exc:
        return {
            "content": [{"type": "text", "text": f"PARAM_REJECTED: {exc}"}],
            "isError": True,
        }
    return {
        "content": [{"type": "text", "text": json.dumps(res.to_dict(), indent=2)}],
        "isError": res.exit_code != 0,
    }


async def handle_rpc(msg: dict[str, Any]) -> dict[str, Any] | None:
    method = msg.get("method", "")
    req_id = msg.get("id")

    # Notifications have no id and require no response.
    if req_id is None:
        return None

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "redgate-mcp-server", "version": __version__},
            },
        }
    if method == "ping":
        return {"jsonrpc": "2.0", "id": req_id, "result": {}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": list_exposed_tools()}}
    if method == "tools/call":
        params = msg.get("params") or {}
        result = await dispatch_tool_call(str(params.get("name", "")), params.get("arguments"))
        return {"jsonrpc": "2.0", "id": req_id, "result": result}

    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": -32601, "message": f"Method not found: {method}"},
    }


async def main() -> None:
    for raw_line in sys.stdin:
        line = raw_line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            resp: dict[str, Any] | None = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": "Parse error"},
            }
        else:
            resp = await handle_rpc(msg)
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    asyncio.run(main())
