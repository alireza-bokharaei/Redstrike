"""Authenticated MCP JSON-RPC 2.0 HTTP bridge for Layer 2.

Implements the Model Context Protocol methods (`initialize`, `tools/list`,
`tools/call`) over HTTP so the FastAPI Gateway can invoke isolated tools across
Docker network boundaries while enforcing `X-Internal-Service-Token`.
"""

from __future__ import annotations

import hmac
import logging
import os
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse

from mcp_server import __version__
from mcp_server.executor import MCPToolExecutor
from mcp_server.catalog import catalog_size, category_counts
from mcp_server.tools import (
    CATALOG_TOOL_INPUT_SCHEMA,
    MCP_TOOL_CATALOG,
    ToolParamValidationError,
)

logger = logging.getLogger("redgate.mcp")

INTERNAL_TOKEN = os.environ.get("REDGATE_INTERNAL_TOKEN", "")
MAX_CONCURRENT = int(os.environ.get("REDGATE_MCP_MAX_CONCURRENT", "4"))
MAX_OUTPUT_BYTES = int(os.environ.get("REDGATE_MCP_MAX_OUTPUT_BYTES", "65536"))

executor = MCPToolExecutor(
    max_concurrent=MAX_CONCURRENT,
    max_output_bytes=MAX_OUTPUT_BYTES,
    artifact_root=os.environ.get("REDGATE_ARTIFACT_DIR", ""),
)

app = FastAPI(
    title="Redstrike Layer 2 — MCP Tool Server",
    version=__version__,
    docs_url=None,
    redoc_url=None,
)


def _require_internal_auth(token: str | None) -> None:
    if len(INTERNAL_TOKEN) < 16:
        raise HTTPException(status_code=503, detail="MCP server misconfigured: missing internal token.")
    if not token or not hmac.compare_digest(token.encode("utf-8"), INTERNAL_TOKEN.encode("utf-8")):
        raise HTTPException(status_code=401, detail="Unauthorized internal service caller.")


@app.get("/health")
async def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "service": "redgate-mcp-server",
        "version": __version__,
        "protocol": "MCP/2024-11-05",
        "registered_tools": list(MCP_TOOL_CATALOG.keys()),
        "catalog_size": catalog_size(),
        "catalog_categories": category_counts(),
        "max_concurrent": MAX_CONCURRENT,
    }


@app.post("/mcp")
async def mcp_rpc(
    request: Request,
    x_internal_service_token: str | None = Header(default=None),
) -> JSONResponse:
    """Handle JSON-RPC 2.0 Model Context Protocol calls from the Gateway."""
    _require_internal_auth(x_internal_service_token)
    body = await request.json()
    rpc_id = body.get("id")
    method = body.get("method")
    params = body.get("params") or {}

    if method == "initialize":
        return JSONResponse(
            {
                "jsonrpc": "2.0",
                "id": rpc_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "serverInfo": {"name": "redgate-mcp-server", "version": __version__},
                    "capabilities": {"tools": {"listChanged": False}},
                },
            }
        )

    if method == "tools/list":
        tools_payload = [
            {
                "name": t.name,
                "description": t.description,
                "inputSchema": t.input_schema,
            }
            for t in MCP_TOOL_CATALOG.values()
        ]
        # The extended surface is published as one grouped tool so the protocol
        # stays readable: clients see ``redstrike_tool`` plus the catalog listing
        # it can call through (see /api/v1/offensive/tools on the Gateway).
        tools_payload.append(
            {
                "name": "redstrike_tool",
                "description": (
                    f"Run any of the {catalog_size()} catalogued offensive tools. The flag "
                    "surface of each tool is governed by the engagement's policy row; argv is "
                    "built as an argument vector and the target must already be scope-validated."
                ),
                "inputSchema": CATALOG_TOOL_INPUT_SCHEMA,
            }
        )
        return JSONResponse({"jsonrpc": "2.0", "id": rpc_id, "result": {"tools": tools_payload}})

    if method == "tools/call":
        tool_name = str(params.get("name", ""))
        arguments = dict(params.get("arguments") or {})
        meta = dict(params.get("_policy") or {})
        target = str(arguments.pop("target", ""))
        timeout_sec = int(meta.get("max_timeout", 20))
        allowed_params_policy = meta.get("allowed_params")
        pinned_ips = list(meta.get("pinned_ips") or [])

        try:
            res = await executor.execute(
                tool_name=tool_name,
                target=target,
                params=arguments,
                timeout_sec=timeout_sec,
                allowed_params_policy=allowed_params_policy,
                pinned_ips=pinned_ips,
            )
        except ToolParamValidationError as exc:
            return JSONResponse(
                {
                    "jsonrpc": "2.0",
                    "id": rpc_id,
                    "error": {"code": -32602, "message": str(exc)},
                },
                status_code=422,
            )

        return JSONResponse(
            {
                "jsonrpc": "2.0",
                "id": rpc_id,
                "result": {
                    "content": [{"type": "text", "text": res.stdout or res.stderr}],
                    "isError": res.exit_code != 0,
                    "execution": res.to_dict(),
                },
            }
        )

    return JSONResponse(
        {
            "jsonrpc": "2.0",
            "id": rpc_id,
            "error": {"code": -32601, "message": f"Unknown MCP method '{method}'."},
        },
        status_code=400,
    )
