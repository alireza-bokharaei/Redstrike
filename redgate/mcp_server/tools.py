"""MCP tool schemas and parameter governance for Layer 2.

Every tool exposed by Layer 2 enforces:

1. Target syntax normalisation (no whitespace, shell metacharacters, or option
   injection).
2. An explicit parameter whitelist. As of 2.3 the flag surface of a tool is a
   *policy* question answered by ``config/policies.yaml`` plus the engagement
   posture, not a hardcoded ban list: an engagement may allow ``nmap -T4`` (via
   ``tool:nmap_aggressive`` and operator consent) or keep it refused.
3. A code-level refusal floor that no configuration edit can lift: flags that
   turn a check into a compromise (``sqlmap --os-shell`` and friends) stay
   refused through :data:`mcp_server.catalog.BASELINE_REFUSED_FLAGS`. The floor
   is intentionally narrow — it is about capability, not about noise or speed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

# ---------------------------------------------------------------------------
# Refusal floor.
#
# The authoritative refusal sets now live beside the catalog so that the argv
# builder, the validators and the executor all consult one source. These aliases
# stay for callers that imported them before 2.3; they are derived, never
# hand-maintained, so they cannot drift from the builder's behaviour.
# ---------------------------------------------------------------------------
from mcp_server.catalog import (  # noqa: E402 - keeps the alias block readable
    BASELINE_REFUSED_FLAGS,
    ArgvBuildError,
    build_argv,
)

PERMANENTLY_BANNED_SQLMAP_FLAGS: frozenset[str] = frozenset(
    BASELINE_REFUSED_FLAGS["sqlmap"]
)

#: Nmap flags that remain refused in every posture. Timing (``-T4``) is NOT here:
#: it is governed by the ``tool:nmap_aggressive`` policy row and operator
#: consent, because speed is a noise question, not a capability question.
PERMANENTLY_BANNED_NMAP_FLAGS: frozenset[str] = frozenset(
    {"--script", "--script-args", "--datadir", "-iL", "-iR", "--interactive", "--resume",
     "-D", "-S", "--spoof-mac", "--data", "--data-string"}
)

SAFE_TARGET_RE = re.compile(r"^[A-Za-z0-9.\-:]{1,253}$")
SAFE_URL_TARGET_RE = re.compile(
    r"^https?://[A-Za-z0-9](?:[A-Za-z0-9.\-]{0,251})(?::[0-9]{1,5})?"
    r"(?:/[A-Za-z0-9._~%!$&'()*+,;=:@/\-?]*)?$"
)
SAFE_PATH_RE = re.compile(r"^/[A-Za-z0-9._~!$&'()*+,;=:@/\-?%]{0,127}$")
SAFE_PORT_SPEC_RE = re.compile(r"^[0-9,\-]{1,32}$")

SECURITY_HEADERS_OF_INTEREST: tuple[str, ...] = (
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cache-control",
    "server",
)


class ToolParamValidationError(ValueError):
    """Raised when tool parameters violate the strict whitelist policy."""


@dataclass(frozen=True)
class MCPToolDefinition:
    """MCP-compliant tool descriptor with JSON Schema for input parameters."""

    name: str
    description: str
    input_schema: dict[str, Any]
    default_risk: str


MCP_TOOL_CATALOG: dict[str, MCPToolDefinition] = {
    "http_headers": MCPToolDefinition(
        name="http_headers",
        description=(
            "Perform a single non-redirecting HEAD or GET request to inspect HTTP status "
            "and defensive security headers on an allowlisted target."
        ),
        default_risk="low",
        input_schema={
            "type": "object",
            "additionalProperties": False,
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Allowlisted hostname or IP."},
                "scheme": {"type": "string", "enum": ["http", "https"], "default": "https"},
                "method": {"type": "string", "enum": ["HEAD", "GET"], "default": "HEAD"},
                "port": {"type": "integer", "enum": [80, 443, 8000, 8080, 8443]},
                "path": {"type": "string", "default": "/", "maxLength": 128},
            },
        },
    ),
    "tls_inspect": MCPToolDefinition(
        name="tls_inspect",
        description=(
            "Inspect TLS handshake protocol, cipher suite, and leaf X.509 certificate "
            "validity/expiry on an allowlisted target."
        ),
        default_risk="low",
        input_schema={
            "type": "object",
            "additionalProperties": False,
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Allowlisted hostname or IP."},
                "port": {"type": "integer", "enum": [443, 8443], "default": 443},
            },
        },
    ),
    "dns_lookup": MCPToolDefinition(
        name="dns_lookup",
        description="Query standard DNS records (A, AAAA, MX, TXT, NS, CNAME) for an in-scope domain.",
        default_risk="low",
        input_schema={
            "type": "object",
            "additionalProperties": False,
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Allowlisted domain name."},
                "record_type": {
                    "type": "string",
                    "enum": ["A", "AAAA", "MX", "TXT", "NS", "CNAME"],
                    "default": "A",
                },
            },
        },
    ),
    "tcp_port_probe": MCPToolDefinition(
        name="tcp_port_probe",
        description=(
            "Low-noise TCP connection verification against up to 10 explicit ports "
            "with inter-probe pacing."
        ),
        default_risk="low",
        input_schema={
            "type": "object",
            "additionalProperties": False,
            "required": ["target", "ports"],
            "properties": {
                "target": {"type": "string", "description": "Allowlisted hostname or IP."},
                "ports": {
                    "type": "array",
                    "items": {"type": "integer", "minimum": 1, "maximum": 65535},
                    "minItems": 1,
                    "maxItems": 10,
                },
            },
        },
    ),
    "nmap": MCPToolDefinition(
        name="nmap",
        description=(
            "Constrained Nmap service identification restricted to low-noise timing "
            "(-T1/-T2) and approved flags (-sV, -sC, -sT, -Pn, --open)."
        ),
        default_risk="medium",
        input_schema={
            "type": "object",
            "additionalProperties": False,
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Allowlisted hostname or IP."},
                "flags": {
                    "type": "array",
                    "items": {
                        "type": "string",
                        "enum": ["-sV", "-sC", "-sT", "-T1", "-T2", "-Pn", "--open"],
                    },
                    "default": ["-sV", "-T2", "--open"],
                    "maxItems": 6,
                },
                "ports": {
                    "type": "string",
                    "description": "Comma/range port list, e.g. '80,443' or '8000-8010'.",
                    "default": "80,443",
                    "maxLength": 32,
                },
            },
        },
    ),
    "nmap_aggressive": MCPToolDefinition(
        name="nmap_aggressive",
        description="High-rate Nmap scan (-T4) — DISABLED by default; requires explicit approval.",
        default_risk="high",
        input_schema={
            "type": "object",
            "additionalProperties": False,
            "required": ["target"],
            "properties": {
                "target": {"type": "string"},
                "flags": {"type": "array", "items": {"type": "string"}},
                "ports": {"type": "string", "default": "80,443"},
            },
        },
    ),
    "sqlmap": MCPToolDefinition(
        name="sqlmap",
        description=(
            "SQL injection verification wrapper — DISABLED by default; requires approval. "
            "OS/shell/file flags (--os-shell, --file-write, etc.) are permanently prohibited."
        ),
        default_risk="critical",
        input_schema={
            "type": "object",
            "additionalProperties": False,
            "required": ["target"],
            "properties": {
                "target": {"type": "string"},
                "flags": {"type": "array", "items": {"type": "string"}},
            },
        },
    ),
    "hydra": MCPToolDefinition(
        name="hydra",
        description="Online authentication auditor — DISABLED by default due to lockout risk.",
        default_risk="critical",
        input_schema={
            "type": "object",
            "additionalProperties": False,
            "required": ["target"],
            "properties": {
                "target": {"type": "string"},
                "flags": {"type": "array", "items": {"type": "string"}},
            },
        },
    ),
    "john": MCPToolDefinition(
        name="john",
        description="Offline hash auditor — DISABLED by default; requires explicit approval.",
        default_risk="high",
        input_schema={
            "type": "object",
            "additionalProperties": False,
            "required": ["target"],
            "properties": {
                "target": {"type": "string"},
                "flags": {"type": "array", "items": {"type": "string"}},
            },
        },
    ),
}


def validate_target_token(target: str) -> str:
    """Ensure a target string cannot inject CLI flags or shell characters."""
    cleaned = target.strip()
    if not cleaned or cleaned.startswith("-"):
        raise ToolParamValidationError("Target must be non-empty and must not start with '-'.")
    if SAFE_TARGET_RE.match(cleaned):
        return cleaned
    # 2.3: catalogued web tools take URLs. Accept them only when the whole string
    # is a well-formed http(s) URL, never when it merely contains "://".
    if SAFE_URL_TARGET_RE.match(cleaned):
        return cleaned
    raise ToolParamValidationError(f"Target '{cleaned}' contains disallowed characters.")


def validate_tool_params(
    tool_name: str,
    params: dict[str, Any],
    allowed_params_policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Validate and normalize tool arguments against strict whitelists.

    Returns a sanitized parameter dict safe for subprocess/network execution,
    or raises ToolParamValidationError with an auditable reason.
    """
    if tool_name not in MCP_TOOL_CATALOG:
        raise ToolParamValidationError(f"Unknown MCP tool '{tool_name}'.")

    policy = allowed_params_policy or {}
    schema_props = MCP_TOOL_CATALOG[tool_name].input_schema.get("properties", {})
    unknown_keys = set(params.keys()) - set(schema_props.keys()) - {"target"}
    if unknown_keys:
        raise ToolParamValidationError(
            f"Disallowed parameter keys for '{tool_name}': {sorted(unknown_keys)}"
        )

    if tool_name == "http_headers":
        allowed_schemes = set(policy.get("schemes", ["http", "https"]))
        allowed_methods = set(policy.get("methods", ["HEAD", "GET"]))
        allowed_ports = set(policy.get("allowed_ports", [80, 443, 8000, 8080, 8443]))
        max_path_len = int(policy.get("max_path_length", 128))

        scheme = str(params.get("scheme", "https")).lower()
        method = str(params.get("method", "HEAD")).upper()
        default_port = 443 if scheme == "https" else 80
        port = int(params.get("port", default_port))
        path = str(params.get("path", "/"))

        if scheme not in allowed_schemes:
            raise ToolParamValidationError(f"Scheme '{scheme}' not in whitelist {sorted(allowed_schemes)}.")
        if method not in allowed_methods:
            raise ToolParamValidationError(f"HTTP method '{method}' not in whitelist {sorted(allowed_methods)}.")
        if port not in allowed_ports:
            raise ToolParamValidationError(f"Port {port} not in whitelist {sorted(allowed_ports)}.")
        if len(path) > max_path_len or not SAFE_PATH_RE.match(path):
            raise ToolParamValidationError(f"Path '{path}' fails whitelist validation.")
        return {"scheme": scheme, "method": method, "port": port, "path": path}

    if tool_name == "tls_inspect":
        allowed_ports = set(policy.get("allowed_ports", [443, 8443]))
        port = int(params.get("port", 443))
        if port not in allowed_ports:
            raise ToolParamValidationError(f"TLS port {port} not in whitelist {sorted(allowed_ports)}.")
        return {"port": port}

    if tool_name == "dns_lookup":
        allowed_types = set(policy.get("record_types", ["A", "AAAA", "MX", "TXT", "NS", "CNAME"]))
        record_type = str(params.get("record_type", "A")).upper()
        if record_type not in allowed_types:
            raise ToolParamValidationError(
                f"DNS record type '{record_type}' not in whitelist {sorted(allowed_types)}."
            )
        return {"record_type": record_type}

    if tool_name == "tcp_port_probe":
        raw_ports = params.get("ports")
        max_ports = int(policy.get("max_ports", 10))
        if not isinstance(raw_ports, list) or not (1 <= len(raw_ports) <= max_ports):
            raise ToolParamValidationError(f"'ports' must be a non-empty list of at most {max_ports} integers.")
        clean_ports: list[int] = []
        for p in raw_ports:
            if not isinstance(p, int) or isinstance(p, bool) or not (1 <= p <= 65535):
                raise ToolParamValidationError(f"Invalid TCP port value: {p!r}.")
            if p not in clean_ports:
                clean_ports.append(p)
        return {"ports": clean_ports}

    if tool_name == "nmap":
        # Timing and NSE flags are governed by the policy row: ``tool:nmap``
        # allows -T1/-T2, ``tool:nmap_aggressive`` adds -T3/-T4 for engagements
        # that consented to the extra noise. NSE (``--script``) stays refused.
        allowed_flags = [str(f) for f in policy.get("allowed_flags", ["-sV", "-sT", "-T1", "-T2", "-Pn", "--open"])]
        refused_flags = [str(f) for f in policy.get("refused_flags", [])]
        raw_flags = params.get("flags", ["-sV", "-T2", "--open"])
        if not isinstance(raw_flags, list) or len(raw_flags) > 6:
            raise ToolParamValidationError("nmap 'flags' must be a list of at most 6 whitelisted flags.")

        clean_flags: list[str] = []
        floor = set(PERMANENTLY_BANNED_NMAP_FLAGS) | set(refused_flags)
        for flg in raw_flags:
            if not isinstance(flg, str):
                raise ToolParamValidationError("Every nmap flag must be a string.")
            base_flag = flg.split("=", 1)[0].strip()
            if flg in floor or base_flag in floor:
                raise ToolParamValidationError(
                    f"Nmap flag '{flg}' is refused by policy (scripting, evasion, "
                    "file-write, or raw-packet options are not allowed)."
                )
            if flg not in allowed_flags and base_flag not in allowed_flags:
                raise ToolParamValidationError(
                    f"Nmap flag '{flg}' is not in this engagement's allowed_flags "
                    f"{sorted(allowed_flags)}."
                )
            if flg not in clean_flags:
                clean_flags.append(flg)

        # Keep the run quiet by default, but do not override an explicit timing
        # choice the policy allowed (-T3/-T4 under tool:nmap_aggressive).
        if not any(f.startswith("-T") for f in clean_flags):
            clean_flags.append("-T2")

        ports = str(params.get("ports", "80,443")).strip()
        if not SAFE_PORT_SPEC_RE.match(ports):
            raise ToolParamValidationError(
                f"Invalid nmap port specification '{ports}'; only digits, commas, and hyphens allowed."
            )
        return {"flags": clean_flags, "ports": ports}

    if tool_name == "sqlmap":
        raw_flags = params.get("flags", [])
        if not isinstance(raw_flags, list):
            raise ToolParamValidationError("sqlmap 'flags' must be a list.")
        allowed_flags = set(policy.get("allowed_flags", ["--batch", "--level=1", "--risk=1"]))
        refused = set(BASELINE_REFUSED_FLAGS["sqlmap"]) | set(policy.get("refused_flags", []))
        for flg in raw_flags:
            base = str(flg).split("=", 1)[0].strip().lower()
            if base in refused:
                raise ToolParamValidationError(
                    f"sqlmap flag '{flg}' is refused: it turns an injection finding into "
                    "an OS-level compromise, which no Redstrike posture permits."
                )
            if str(flg) not in allowed_flags and base not in allowed_flags:
                raise ToolParamValidationError(
                    f"sqlmap flag '{flg}' not in this engagement's allowed_flags {sorted(allowed_flags)}."
                )
        return {"flags": [str(f) for f in raw_flags]}

    if tool_name in {"nmap_aggressive", "hydra", "john"}:
        allowed_flags = set(policy.get("allowed_flags", []))
        raw_flags = params.get("flags", [])
        if not isinstance(raw_flags, list):
            raise ToolParamValidationError(f"{tool_name} 'flags' must be a list.")
        refused = set(policy.get("refused_flags", [])) | set(BASELINE_REFUSED_FLAGS.get(tool_name, ()))
        for flg in raw_flags:
            base = str(flg).split("=", 1)[0].strip()
            if str(flg) in refused or base in refused:
                raise ToolParamValidationError(f"{tool_name} flag '{flg}' is refused by policy.")
            if str(flg) not in allowed_flags and base not in allowed_flags:
                raise ToolParamValidationError(
                    f"{tool_name} flag '{flg}' is not in this engagement's allowed_flags "
                    f"{sorted(allowed_flags)}."
                )
        return {"flags": [str(f) for f in raw_flags]}

    raise ToolParamValidationError(f"No parameter validator configured for '{tool_name}'.")


# ---------------------------------------------------------------------------
# Generic catalog-tool surface (2.3)
# ---------------------------------------------------------------------------
#: Parameters accepted by any catalogued external tool.
CATALOG_TOOL_INPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["target", "tool"],
    "properties": {
        "tool": {"type": "string", "description": "Catalogued tool name (see /api/v1/offensive/tools)."},
        "target": {"type": "string", "description": "Scope-validated host, URL, or artifact."},
        "flags": {
            "type": "array",
            "items": {"type": "string"},
            "maxItems": 12,
            "description": "Flags; each must appear in the tool policy's allowed_flags.",
        },
    },
}


def validate_catalog_tool_params(
    tool_name: str,
    params: dict[str, Any],
    policy: dict[str, Any] | None = None,
    *,
    binary_path: str | None = None,
) -> dict[str, Any]:
    """Validate a call to any tool in :mod:`mcp_server.catalog`.

    Returns ``{"tool": ..., "argv": [...], "flags": [...]}``. ``argv`` is the
    complete, ready-to-exec argv vector including the binary; the caller must
    execute it without a shell.
    """
    from mcp_server.catalog import get_entry

    entry = get_entry(tool_name)
    if entry is None:
        raise ToolParamValidationError(f"Tool '{tool_name}' is not in the catalog.")

    unknown = set(params) - {"target", "flags", "tool"}
    if unknown:
        raise ToolParamValidationError(f"Disallowed parameter keys for '{tool_name}': {sorted(unknown)}")

    clean_target = validate_target_token(str(params.get("target", "")))
    raw_flags = params.get("flags", [])
    if not isinstance(raw_flags, list) or not all(isinstance(f, str) for f in raw_flags):
        raise ToolParamValidationError(f"{tool_name} 'flags' must be a list of strings.")

    policy = policy or {}
    try:
        argv = build_argv(
            tool_name,
            clean_target,
            flags=raw_flags,
            allowed_flags=policy.get("allowed_flags", []),
            refused_flags=policy.get("refused_flags", []),
            target_flag=policy.get("target_flag"),
            binary_path=binary_path or entry.binary,
        )
    except ArgvBuildError as exc:
        raise ToolParamValidationError(str(exc)) from exc
    return {
        "tool": tool_name,
        "argv": argv,
        "flags": [a for a in argv[1:] if a.startswith("-") and a != "--"],
    }
