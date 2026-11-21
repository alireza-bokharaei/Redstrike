"""Isolated, bounded-concurrency execution engine for Layer 2 MCP tools.

All subprocess invocations use argument vectors (never shell=True), sanitized
environments, strict timeouts, concurrency semaphores, and output byte caps.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import ipaddress
import json
import os
import shutil
import socket
import ssl
import time
from dataclasses import asdict, dataclass
from typing import Any

import httpx

from mcp_server.catalog import CATALOG, get_entry
from mcp_server.tools import (
    SECURITY_HEADERS_OF_INTEREST,
    ToolParamValidationError,
    validate_catalog_tool_params,
    validate_target_token,
    validate_tool_params,
)


@dataclass
class ToolExecutionResult:
    """Structured output returned by every MCP tool call."""

    tool_name: str
    target: str
    sanitized_params: dict[str, Any]
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int
    started_at: str
    finished_at: str
    timed_out: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class MCPToolExecutor:
    """Executes policy-approved tools with timeout, semaphore, and output isolation."""

    def __init__(
        self,
        max_concurrent: int = 4,
        max_output_bytes: int = 65536,
        artifact_root: str | None = None,
    ) -> None:
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._max_output_bytes = max_output_bytes
        # Binary tooling reads files the operator already has. The root is explicit
        # so "vuln.elf" means the same file to the Gateway, the MCP service and the
        # executor, instead of whatever the process cwd happens to be.
        self._artifact_root = artifact_root or os.environ.get("REDGATE_ARTIFACT_DIR", "")

    def _truncate(self, text: str) -> str:
        encoded = text.encode("utf-8", errors="replace")
        if len(encoded) <= self._max_output_bytes:
            return text
        return encoded[: self._max_output_bytes].decode("utf-8", errors="ignore") + "\n...[truncated]"

    async def execute(
        self,
        tool_name: str,
        target: str,
        params: dict[str, Any],
        timeout_sec: int = 20,
        allowed_params_policy: dict[str, Any] | None = None,
        pinned_ips: list[str] | None = None,
    ) -> ToolExecutionResult:
        """Validate target + params, acquire semaphore, run tool, and bound output."""
        clean_target = validate_target_token(target)
        if tool_name in CATALOG:
            clean_params = validate_catalog_tool_params(
                tool_name, {**params, "target": clean_target}, allowed_params_policy or {}
            )
        else:
            clean_params = validate_tool_params(tool_name, params, allowed_params_policy)
        bounded_timeout = max(1, min(int(timeout_sec), 300))

        started_at = dt.datetime.now(dt.timezone.utc).isoformat()
        t0 = time.monotonic()

        async with self._semaphore:
            try:
                exit_code, stdout, stderr = await asyncio.wait_for(
                    self._dispatch(
                        tool_name,
                        clean_target,
                        clean_params,
                        bounded_timeout,
                        pinned_ips or [],
                        allowed_params_policy or {},
                    ),
                    timeout=bounded_timeout,
                )
                timed_out = False
            except asyncio.TimeoutError:
                exit_code = 124
                stdout = ""
                stderr = f"Tool '{tool_name}' exceeded hard timeout of {bounded_timeout}s."
                timed_out = True
            except ToolParamValidationError:
                raise
            except Exception as exc:  # noqa: BLE001
                exit_code = 1
                stdout = ""
                stderr = f"Tool execution error ({type(exc).__name__}): {exc}"
                timed_out = False

        finished_at = dt.datetime.now(dt.timezone.utc).isoformat()
        duration_ms = int((time.monotonic() - t0) * 1000)

        return ToolExecutionResult(
            tool_name=tool_name,
            target=clean_target,
            sanitized_params=clean_params,
            exit_code=exit_code,
            stdout=self._truncate(stdout),
            stderr=self._truncate(stderr),
            duration_ms=duration_ms,
            started_at=started_at,
            finished_at=finished_at,
            timed_out=timed_out,
        )

    async def _dispatch(
        self,
        tool_name: str,
        target: str,
        params: dict[str, Any],
        timeout_sec: int,
        pinned_ips: list[str],
        policy: dict[str, Any],
    ) -> tuple[int, str, str]:
        if tool_name == "http_headers":
            return await self._run_http_headers(target, params, timeout_sec, pinned_ips)
        if tool_name == "tls_inspect":
            return await self._run_tls_inspect(target, params, timeout_sec, pinned_ips)
        if tool_name == "dns_lookup":
            return await self._run_dns_lookup(target, params, timeout_sec)
        if tool_name == "tcp_port_probe":
            return await self._run_tcp_port_probe(target, params, pinned_ips, policy)
        if tool_name == "nmap":
            return await self._run_nmap(target, params, timeout_sec, pinned_ips)
        if tool_name in {"nmap_aggressive", "sqlmap", "hydra", "john"}:
            return await self._run_external_gated_binary(tool_name, target, params, timeout_sec)
        if tool_name in CATALOG:
            return await self._run_catalog_tool(tool_name, target, params, timeout_sec, pinned_ips)
        raise ToolParamValidationError(f"Unsupported tool '{tool_name}'.")

    async def _run_http_headers(
        self,
        target: str,
        params: dict[str, Any],
        timeout_sec: int,
        pinned_ips: list[str],
    ) -> tuple[int, str, str]:
        scheme = params["scheme"]
        method = params["method"]
        port = params["port"]
        path = params["path"]

        default_port = 443 if scheme == "https" else 80
        host_literal = f"[{target}]" if ":" in target else target
        host_part = host_literal if port == default_port else f"{host_literal}:{port}"
        url = f"{scheme}://{host_part}{path}"
        pins = list(pinned_ips)
        if not pins:
            try:
                pins = [str(ipaddress.ip_address(target))]
            except ValueError as exc:
                raise ToolParamValidationError("HTTP requests require a gateway-resolved DNS pin.") from exc
        pin = str(ipaddress.ip_address(pins[0]))
        # Dial the pin, but retain the original HTTP Host and TLS SNI/certificate
        # name. Passing pins in a JSON report alone does not prevent rebinding.
        connect_url = httpx.URL(url).copy_with(host=pin)
        req_timeout = min(float(timeout_sec), 15.0)
        async with httpx.AsyncClient(
            follow_redirects=False, trust_env=False,
            timeout=req_timeout, verify=True,
            headers={"User-Agent": "Redstrike-PolicyScanner/2.1 (Authorized Security Audit)"},
        ) as client:
            # Header inspection must not buffer an unbounded response body.
            async with client.stream(method, connect_url, headers={"Host": host_part},
                                     extensions={"sni_hostname": target}) as resp:
                response_status = resp.status_code
                response_headers = dict(resp.headers)

        present: dict[str, str] = {}
        missing: list[str] = []
        lower_headers = {k.lower(): v for k, v in response_headers.items()}
        for hdr in SECURITY_HEADERS_OF_INTEREST:
            if hdr in lower_headers:
                present[hdr] = lower_headers[hdr]
            elif hdr != "server":
                missing.append(hdr)

        report = {
            "url": url,
            "method": method,
            "pinned_ips": pins,
            "connected_ip": pin,
            "status_code": response_status,
            "present_security_headers": present,
            "missing_recommended_headers": missing,
        }
        return 0, json.dumps(report, indent=2), ""

    async def _run_tls_inspect(
        self,
        target: str,
        params: dict[str, Any],
        timeout_sec: int,
        pinned_ips: list[str],
    ) -> tuple[int, str, str]:
        port = int(params["port"])
        connect_host = pinned_ips[0] if pinned_ips else target

        def _handshake() -> dict[str, Any]:
            ctx = ssl.create_default_context()
            with socket.create_connection((connect_host, port), timeout=min(timeout_sec, 10)) as sock:
                with ctx.wrap_socket(sock, server_hostname=target) as tls_sock:
                    cert = tls_sock.getpeercert() or {}
                    cipher = tls_sock.cipher()
                    not_after = cert.get("notAfter", "")
                    days_remaining: int | None = None
                    if not_after:
                        exp = dt.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                            tzinfo=dt.timezone.utc
                        )
                        days_remaining = (exp - dt.datetime.now(dt.timezone.utc)).days
                    subject = {k: v for item in cert.get("subject", ()) for k, v in item}
                    issuer = {k: v for item in cert.get("issuer", ()) for k, v in item}
                    sans = [val for typ, val in cert.get("subjectAltName", ()) if typ == "DNS"]
                    return {
                        "target": target,
                        "connected_ip": connect_host,
                        "port": port,
                        "tls_version": tls_sock.version(),
                        "cipher_suite": cipher[0] if cipher else None,
                        "cipher_bits": cipher[2] if cipher else None,
                        "subject": subject,
                        "issuer": issuer,
                        "not_before": cert.get("notBefore"),
                        "not_after": not_after,
                        "days_until_expiry": days_remaining,
                        "san_dns_count": len(sans),
                        "san_sample": sans[:10],
                    }

        info = await asyncio.to_thread(_handshake)
        return 0, json.dumps(info, indent=2), ""

    async def _run_dns_lookup(
        self, target: str, params: dict[str, Any], timeout_sec: int
    ) -> tuple[int, str, str]:
        record_type = params["record_type"]
        dig_bin = shutil.which("dig")
        if dig_bin:
            argv = [dig_bin, "+time=3", "+tries=1", "+short", target, record_type]
            return await self._run_subprocess(argv, timeout_sec)

        # Fallback to stdlib resolver for A/AAAA when dig is absent.
        if record_type in {"A", "AAAA"}:
            family = socket.AF_INET if record_type == "A" else socket.AF_INET6
            infos = await asyncio.to_thread(socket.getaddrinfo, target, None, family)
            addrs = sorted({entry[4][0] for entry in infos})
            return 0, "\n".join(addrs) + ("\n" if addrs else ""), ""
        return 127, "", "dig binary not installed in MCP container."

    async def _run_tcp_port_probe(
        self,
        target: str,
        params: dict[str, Any],
        pinned_ips: list[str],
        policy: dict[str, Any],
    ) -> tuple[int, str, str]:
        connect_host = pinned_ips[0] if pinned_ips else target
        ports: list[int] = params["ports"]
        per_timeout = float(policy.get("per_port_timeout_sec", 2.0))
        delay_sec = max(0.05, int(policy.get("inter_probe_delay_ms", 150)) / 1000.0)

        results: list[dict[str, Any]] = []
        for idx, port in enumerate(ports):
            if idx > 0:
                await asyncio.sleep(delay_sec)
            p_start = time.monotonic()
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(connect_host, port), timeout=per_timeout
                )
                writer.close()
                await writer.wait_closed()
                state = "open"
            except asyncio.TimeoutError:
                state = "filtered_or_timeout"
            except ConnectionRefusedError:
                state = "closed"
            except OSError as exc:
                state = f"unreachable ({exc.errno})"
            results.append(
                {
                    "port": port,
                    "state": state,
                    "rtt_ms": int((time.monotonic() - p_start) * 1000),
                }
            )

        payload = {
            "target": target,
            "connected_ip": connect_host,
            "pacing_delay_ms": int(delay_sec * 1000),
            "results": results,
        }
        return 0, json.dumps(payload, indent=2), ""

    async def _run_nmap(
        self,
        target: str,
        params: dict[str, Any],
        timeout_sec: int,
        pinned_ips: list[str],
    ) -> tuple[int, str, str]:
        scan_host = pinned_ips[0] if pinned_ips else target
        flags: list[str] = params["flags"]
        ports: str = params["ports"]
        nmap_bin = shutil.which("nmap")
        argv = [nmap_bin or "nmap", *flags, "-p", ports, "--", scan_host]
        if not nmap_bin:
            return (
                127,
                json.dumps({"validated_argv": argv, "target": target, "pinned_ip": scan_host}, indent=2),
                "nmap binary is not installed on this runner image; install nmap in mcp-server container to execute.",
            )
        return await self._run_subprocess(argv, timeout_sec)

    async def _run_external_gated_binary(
        self, tool_name: str, target: str, params: dict[str, Any], timeout_sec: int
    ) -> tuple[int, str, str]:
        bin_name = "nmap" if tool_name == "nmap_aggressive" else tool_name
        flags: list[str] = params.get("flags", [])
        entry = get_entry(bin_name)
        resolved = shutil.which(entry.binary if entry else bin_name)
        if not resolved:
            return (
                127,
                json.dumps({"tool": tool_name, "validated_flags": flags, "target": target}, indent=2),
                f"Binary '{bin_name}' is not installed on this runner image.",
            )
        argv = [resolved, *flags, "--", target]
        return await self._run_subprocess(argv, timeout_sec)

    async def _run_catalog_tool(
        self,
        tool_name: str,
        target: str,
        params: dict[str, Any],
        timeout_sec: int,
        pinned_ips: list[str],
    ) -> tuple[int, str, str]:
        """Execute a catalogued tool with the pre-validated argv vector.

        ``params["argv"]`` was produced by :func:`mcp_server.catalog.build_argv`
        during validation, so the flag surface has already been checked against
        the policy row. Two things are re-asserted here because they are
        execution-boundary guarantees, not parameter hygiene:

        * the resolved binary must be the catalogued one (no PATH shadowing of
          e.g. ``nmap`` by a planted script);
        * a network tool must receive the pinned IP, never a re-resolved name, so
          DNS rebinding cannot redirect an in-flight run.
        """
        entry = get_entry(tool_name)
        assert entry is not None  # dispatch only routes catalog tools here
        argv = list(params.get("argv") or [])
        if not argv:
            raise ToolParamValidationError(f"No validated argv was produced for '{tool_name}'.")

        resolved = shutil.which(entry.binary)
        if not resolved:
            return (
                127,
                json.dumps(
                    {
                        "tool": tool_name,
                        "binary": entry.binary,
                        "validated_argv": argv,
                        "target": target,
                        "installed_tools": self._installed_tools(),
                    },
                    indent=2,
                ),
                (
                    f"Binary '{entry.binary}' is not installed on this runner image. "
                    "argv was validated but nothing was executed."
                ),
            )
        argv[0] = resolved

        if entry.offline and entry.category != "binary":
            raise ToolParamValidationError(f"'{tool_name}' is offline-only and takes no target.")

        from mcp_server.catalog import takes_artifact

        if takes_artifact(entry):
            return await self._run_artifact_tool(tool_name, entry.binary, target, argv, timeout_sec)

        if not entry.offline and pinned_ips:
            pinned = pinned_ips[0]
            for idx in range(len(argv) - 1, -1, -1):
                if argv[idx] == target:
                    argv[idx] = pinned
                    break
            else:
                if target in argv:
                    argv = [pinned if a == target else a for a in argv]

        return await self._run_subprocess(argv, timeout_sec)

    @staticmethod
    def _installed_tools() -> dict[str, str]:
        """Which catalog binaries actually exist on this image (honest reporting)."""
        from mcp_server.catalog import is_path_binary

        found: dict[str, str] = {}
        for name, entry in CATALOG.items():
            if not is_path_binary(entry):
                continue
            path = shutil.which(entry.binary)
            if path:
                found[name] = path
        return found

    async def _run_artifact_tool(
        self,
        tool_name: str,
        binary: str,
        target: str,
        argv: list[str],
        timeout_sec: int,
    ) -> tuple[int, str, str]:
        """Run a binary-tooling command against a file inside the artifact root.

        The operator supplies a *name*, never a path. Resolution happens here so
        the containment check is a real containment check (``resolve()`` first,
        then compare parents), not a string-prefix guess.
        """
        from pathlib import Path

        if not self._artifact_root:
            raise ToolParamValidationError(
                "Binary tooling needs REDGATE_ARTIFACT_DIR; no artifact root is configured."
            )
        if "/" in target or "\\" in target or target in {".", ".."}:
            raise ToolParamValidationError(
                f"'{tool_name}' takes an artifact name inside the configured root, not a path."
            )
        root = Path(self._artifact_root).resolve()
        candidate = (root / target).resolve()
        if candidate != root and root not in candidate.parents:
            raise ToolParamValidationError("Artifact path escapes the configured root.")
        if not candidate.is_file():
            return (
                127,
                json.dumps({"artifact": target, "artifact_root": str(root)}, indent=2),
                f"Artifact '{target}' was not found in the configured root.",
            )
        rewritten = [str(candidate) if a == target else a for a in argv]
        return await self._run_subprocess(rewritten, timeout_sec)

    async def _run_subprocess(self, argv: list[str], timeout_sec: int) -> tuple[int, str, str]:
        safe_env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8"}
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=safe_env,
        )
        try:
            out_b, err_b = await asyncio.wait_for(proc.communicate(), timeout=timeout_sec)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            raise
        return (
            proc.returncode if proc.returncode is not None else 1,
            out_b.decode("utf-8", errors="replace"),
            err_b.decode("utf-8", errors="replace"),
        )
