"""Read-only deep SSL/TLS analysis — mandatory for TLS-bearing engagements in 2.2.

The component is deliberately *passive*: it performs bounded handshakes against a
single pinned IP that the scope engine has already validated, never sends
application data beyond an HTTP HEAD used to read the HSTS header, and never
drives an external scanner unless a separate approval-gated adapter is invoked.

Design invariants:

* The socket dials the pinned IP while keeping the original SNI / ``Host``.
* Only ports present both in policy and in the manifest are reachable.
* A verified handshake is attempted first; certificate details from an
  unverified handshake are only reported so an untrusted chain can be described,
  and the trust failure itself is recorded as a finding.
* Result sets are fixed-size and JSON-serialisable so hashing is stable.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
import json
import socket
import ssl
from dataclasses import dataclass
from typing import Any

from gateway.auth import OperatorPrincipal
from gateway.db import Database
from gateway.policy import ScopePolicyEngine
from gateway.workspace_store import WorkspaceStore
from gateway.x509_lite import X509Error, parse_certificate_der

TLS_TOOL = "tls_inspect"
HSTS_TOOL = "http_headers"


class TLSAuditError(RuntimeError):
    """A deep TLS analysis could not be performed safely or at all."""


_PROTOCOL_MAP: dict[str, ssl.TLSVersion] = {
    "TLSv1.3": ssl.TLSVersion.TLSv1_3,
    "TLSv1.2": ssl.TLSVersion.TLSv1_2,
    "TLSv1.1": ssl.TLSVersion.TLSv1_1,
    "TLSv1": ssl.TLSVersion.TLSv1,
    "SSLv3": ssl.TLSVersion.SSLv3,
}
_VERSION_LABEL: dict[ssl.TLSVersion, str] = {v: k for k, v in _PROTOCOL_MAP.items()}
_DEFAULT_PROTOCOLS = ("TLSv1.3", "TLSv1.2", "TLSv1.1", "TLSv1")
_DEFAULT_DEPRECATED = frozenset({"TLSv1", "TLSv1.1", "SSLv3"})


@dataclass(frozen=True)
class TLSProbeProfile:
    """Validated, immutable analysis profile derived from ``capabilities.yaml``."""

    allowed_ports: tuple[int, ...] = (443, 8443)
    timeout_sec: float = 10.0
    protocols: tuple[str, ...] = _DEFAULT_PROTOCOLS
    deprecated: frozenset[str] = _DEFAULT_DEPRECATED
    minimum_acceptable: str = "TLSv1.2"
    weak_cipher_markers: tuple[str, ...] = (
        "RC4",
        "3DES",
        "DES-CBC3",
        "NULL",
        "EXPORT",
        "MD5",
    )
    weak_rsa_bits: int = 2048
    weak_ec_bits: int = 224
    expiring_warning_days: int = 30
    expiring_critical_days: int = 14
    weak_signature_algorithms: tuple[str, ...] = ("md5", "sha1")
    hsts_min_max_age: int = 15552000

    @classmethod
    def from_manifest(cls, cfg: dict[str, Any] | None) -> TLSProbeProfile:
        cfg = dict(cfg or {})
        protocols = tuple(
            p for p in cfg.get("probe_protocols", _DEFAULT_PROTOCOLS) if p in _PROTOCOL_MAP
        ) or _DEFAULT_PROTOCOLS
        cert = dict(cfg.get("certificate") or {})
        hsts = dict(cfg.get("hsts") or {})
        weak_key = dict(cfg.get("weak_key_bits") or {})
        ports = tuple(
            int(p) for p in cfg.get("allowed_ports", (443, 8443)) if 1 <= int(p) <= 65535
        ) or (443, 8443)
        timeout = min(max(float(cfg.get("timeout_sec", 10)), 2.0), 30.0)
        return cls(
            allowed_ports=ports,
            timeout_sec=timeout,
            protocols=protocols,
            deprecated=frozenset(str(p) for p in cfg.get("deprecated_protocols", ()))
            or _DEFAULT_DEPRECATED,
            minimum_acceptable=str(cfg.get("minimum_acceptable_protocol", "TLSv1.2")),
            weak_cipher_markers=tuple(
                str(m).upper() for m in cfg.get("weak_cipher_markers", ()) or ()
            )
            or ("RC4", "3DES", "NULL", "EXPORT", "MD5"),
            weak_rsa_bits=int(weak_key.get("rsa", 2048)),
            weak_ec_bits=int(weak_key.get("ec", 224)),
            expiring_warning_days=int(cert.get("expiring_warning_days", 30)),
            expiring_critical_days=int(cert.get("expiring_critical_days", 14)),
            weak_signature_algorithms=tuple(
                str(a).lower() for a in cert.get("weak_signature_algorithms", ("md5", "sha1"))
            ),
            hsts_min_max_age=int(hsts.get("minimum_max_age_seconds", 15552000)),
        )


def _fingerprint_sha256(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest()


def _parse_iso(raw: Any) -> dt.datetime | None:
    if not raw:
        return None
    try:
        parsed = dt.datetime.fromisoformat(str(raw))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.timezone.utc)


def _parse_cert_time(raw: str | None) -> dt.datetime | None:
    if not raw:
        return None
    try:
        return dt.datetime.strptime(raw, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=dt.timezone.utc)
    except ValueError:
        return None


def _client_context(
    *,
    maximum: ssl.TLSVersion,
    minimum: ssl.TLSVersion | None = None,
    verify: bool,
) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED if verify else ssl.CERT_NONE
    ctx.minimum_version = minimum or ssl.TLSVersion.MINIMUM_SUPPORTED
    ctx.maximum_version = maximum
    if not verify:
        # Analysis of legacy protocols requires bringing the client floor down;
        # no data is trusted from an unverified session beyond the certificate map.
        try:
            ctx.set_ciphers("ALL:@SECLEVEL=0")
        except ssl.SSLError:  # pragma: no cover - platform specific
            pass
    ctx.options |= ssl.OP_NO_COMPRESSION
    return ctx


def _handshake(
    connect_ip: str,
    port: int,
    server_name: str,
    *,
    maximum: ssl.TLSVersion,
    minimum: ssl.TLSVersion | None,
    verify: bool,
    timeout: float,
) -> dict[str, Any]:
    """Perform exactly one pinned handshake and return its negotiated facts."""
    ctx = _client_context(maximum=maximum, minimum=minimum, verify=verify)
    with socket.create_connection((connect_ip, port), timeout=timeout) as raw:
        raw.settimeout(timeout)
        with ctx.wrap_socket(raw, server_hostname=server_name) as tls:
            cipher = tls.cipher()
            cert: dict[str, Any] = {}
            der: bytes | None = None
            try:
                cert = tls.getpeercert() or {}
            except ValueError:
                cert = {}
            if verified_endpoint := tls.getpeercert(binary_form=True):
                der = verified_endpoint
            details: dict[str, Any] = {}
            if der:
                # The stdlib mapping is empty for an unverified session, so the
                # DER blob is always parsed; it is the authoritative description.
                try:
                    details = parse_certificate_der(der)
                except X509Error as exc:
                    details = {"parse_error": str(exc)[:200]}
            return {
                "tls_version": tls.version(),
                "cipher_suite": cipher[0] if cipher else None,
                "cipher_protocol": cipher[1] if cipher else None,
                "cipher_bits": cipher[2] if cipher else None,
                "certificate": cert,
                "certificate_details": details,
                "certificate_sha256": _fingerprint_sha256(der) if der else None,
                "verified": verify,
            }


def probe_pinned(
    *,
    server_name: str,
    connect_ip: str,
    port: int,
    profile: TLSProbeProfile,
) -> dict[str, Any]:
    """Run the bounded protocol sweep against one pinned IP. Blocking by design.

    Every failure mode returns a structured reason instead of raising, so the
    caller can distinguish "protocol not supported" from "host unreachable".
    """
    result: dict[str, Any] = {
        "server_name": server_name,
        "connect_ip": connect_ip,
        "port": port,
        "protocols": {},
        "verified_handshake": None,
        "certificate": None,
        "certificate_details": {},
        "certificate_sha256": None,
        "errors": {},
    }

    # 1. Verified handshake first: establishes trust status and the full chain.
    try:
        verified = _handshake(
            connect_ip,
            port,
            server_name,
            maximum=ssl.TLSVersion.MAXIMUM_SUPPORTED,
            minimum=None,
            verify=True,
            timeout=profile.timeout_sec,
        )
        result["verified_handshake"] = {
            k: verified[k] for k in ("tls_version", "cipher_suite", "cipher_bits")
        }
        result["certificate"] = verified["certificate"]
        result["certificate_details"] = verified.get("certificate_details") or {}
        result["certificate_sha256"] = verified["certificate_sha256"]
        result["trusted"] = True
        best = verified
    except (ssl.SSLCertVerificationError, ssl.SSLError) as exc:
        result["trusted"] = False
        result["errors"]["verified_handshake"] = f"{type(exc).__name__}: {exc}"[:400]
        best = None
        # Trust failed; still describe the certificate from an unverified session.
        try:
            unverified = _handshake(
                connect_ip,
                port,
                server_name,
                maximum=ssl.TLSVersion.MAXIMUM_SUPPORTED,
                minimum=None,
                verify=False,
                timeout=profile.timeout_sec,
            )
            result["certificate"] = unverified["certificate"]
            result["certificate_details"] = unverified.get("certificate_details") or {}
            result["certificate_sha256"] = unverified["certificate_sha256"]
            result["verified_handshake"] = {
                k: unverified[k] for k in ("tls_version", "cipher_suite", "cipher_bits")
            }
            best = unverified
        except (ssl.SSLError, OSError) as exc2:
            result["errors"]["unverified_handshake"] = f"{type(exc2).__name__}: {exc2}"[:400]
    except OSError as exc:
        result["errors"]["connect"] = f"{type(exc).__name__}: {exc}"[:400]
        result["trusted"] = False
        return result

    # 2. Per-protocol sweep to discover deprecated floor support.
    for proto_name in profile.protocols:
        version = _PROTOCOL_MAP.get(proto_name)
        if version is None:
            continue
        try:
            negotiated = _handshake(
                connect_ip,
                port,
                server_name,
                maximum=version,
                minimum=version,
                verify=False,
                timeout=profile.timeout_sec,
            )
            result["protocols"][proto_name] = {
                "supported": True,
                "cipher_suite": negotiated["cipher_suite"],
                "cipher_bits": negotiated["cipher_bits"],
            }
        except (ssl.SSLError, OSError, ValueError) as exc:
            result["protocols"][proto_name] = {
                "supported": False,
                "reason": f"{type(exc).__name__}"[:80],
            }

    if best is not None:
        result["negotiated"] = best["tls_version"]
    result["server_default_cipher"] = {
        "suite": (best or {}).get("cipher_suite"),
        "bits": (best or {}).get("cipher_bits"),
    }
    return result


def _finding(
    *,
    key: str,
    title: str,
    severity: str,
    evidence: str,
    remediation: str,
    score: int,
    confidence: float = 0.95,
    human: bool = False,
    reason: str = "",
) -> dict[str, Any]:
    return {
        "finding_key": key,
        "category": "tls_configuration",
        "title": title,
        "severity": severity,
        "priority_score": max(0, min(100, score)),
        "ai_confidence": confidence,
        "evidence": evidence,
        "remediation": remediation,
        "requires_human_judgment": human,
        "human_judgment_reason": reason,
        "dual_verified": True,  # deterministic handshake observation, re-runnable
    }


def evaluate_probe(
    *,
    target: str,
    port: int,
    probe: dict[str, Any],
    profile: TLSProbeProfile,
    hsts: dict[str, Any] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Turn raw probe output into deterministic findings plus a summary."""
    findings: list[dict[str, Any]] = []
    protocols = probe.get("protocols", {})
    supported = sorted(k for k, v in protocols.items() if v.get("supported"))
    deprecated_enabled = sorted(set(supported) & set(profile.deprecated))

    cert = probe.get("certificate") or {}
    details = probe.get("certificate_details") or {}
    # DER-derived facts win over the stdlib mapping (which is empty whenever the
    # handshake was unverified) so an untrusted chain is still fully described.
    not_after = (
        _parse_iso(details.get("not_after"))
        if details.get("not_after")
        else _parse_cert_time(cert.get("notAfter"))
    )
    days_left = (
        (not_after - dt.datetime.now(dt.timezone.utc)).days if not_after is not None else None
    )
    san_dns = (
        list(details.get("san_dns") or [])
        if details.get("san_dns")
        else [v for k, v in (cert.get("subjectAltName") or ()) if k == "DNS"]
    )
    # iPAddress SANs matter for literal-IP targets (common in lab and internal PKI).
    san_all = list(details.get("san_names") or san_dns)
    subject_cn = details.get("subject_cn") or next(
        (v for item in (cert.get("subject") or ()) for k, v in item if k == "commonName"), None
    )

    # --- protocol floor -------------------------------------------------------
    modern = {"TLSv1.3", "TLSv1.2"} & set(supported)
    if not modern:
        findings.append(
            _finding(
                key="tls:no-modern-protocol",
                title="No TLS 1.2 or TLS 1.3 endpoint could be negotiated",
                severity="critical",
                evidence=f"Supported protocols observed: {supported or 'none'}.",
                remediation="Enable TLS 1.2+ and disable SSLv3/TLS 1.0/TLS 1.1 entirely.",
                score=92,
                human=True,
                reason="A middlebox or SNI mismatch can also explain this; confirm manually.",
            )
        )
    for proto in deprecated_enabled:
        sev = "high" if proto in {"SSLv3", "TLSv1"} else "medium"
        findings.append(
            _finding(
                key=f"tls:deprecated-protocol:{proto}",
                title=f"Deprecated protocol {proto} is still negotiable",
                severity=sev,
                evidence=(
                    f"A handshake restricted to {proto} succeeded with cipher "
                    f"{protocols[proto].get('cipher_suite')}."
                ),
                remediation=f"Remove {proto} from the server's enabled protocol list.",
                score=80 if sev == "high" else 58,
            )
        )

    # --- cipher strength ------------------------------------------------------
    for proto, detail in sorted(protocols.items()):
        if not detail.get("supported"):
            continue
        suite = str(detail.get("cipher_suite") or "").upper()
        bits = int(detail.get("cipher_bits") or 0)
        weak = next((m for m in profile.weak_cipher_markers if m in suite), None)
        if weak or (bits and bits < 128):
            findings.append(
                _finding(
                    key=f"tls:weak-cipher:{proto}",
                    title=f"Weak cipher negotiated on {proto} ({suite or 'unknown'})",
                    severity="medium" if not weak else "high",
                    evidence=(
                        f"Cipher {suite} ({bits} bits) negotiated when restricted to {proto}; "
                        f"matched weak marker '{weak or 'short-key'}'."
                    ),
                    remediation="Restrict to AEAD suites (AES-GCM/CHACHA20) with ≥128-bit keys.",
                    score=70 if weak else 55,
                )
            )

    # --- certificate ----------------------------------------------------------
    if probe.get("trusted") is False:
        err = str((probe.get("errors") or {}).get("verified_handshake", "certificate not trusted"))
        findings.append(
            _finding(
                key="tls:certificate-untrusted",
                title="Certificate chain failed validation",
                severity="high",
                evidence=f"Verified handshake failed: {err}",
                remediation="Deploy the full chain to a public/enterprise-trusted root.",
                score=78,
                human=True,
                reason="Private-PKI engagements may accept this by policy; confirm with the owner.",
            )
        )
    if not_after is None and probe.get("certificate") is not None:
        findings.append(
            _finding(
                key="tls:certificate-metadata-unavailable",
                title="Certificate validity dates could not be parsed",
                severity="low",
                evidence="The peer certificate omitted parseable notBefore/notAfter values.",
                remediation="Inspect the certificate manually and re-run the audit.",
                score=25,
                human=True,
                reason="Observation is incomplete, not a confirmed defect.",
            )
        )
    if days_left is not None:
        if days_left < 0:
            findings.append(
                _finding(
                    key="tls:certificate-expired",
                    title="Certificate has expired",
                    severity="high",
                    evidence=f"notAfter={cert.get('notAfter')} ({abs(days_left)} days ago).",
                    remediation="Renew the certificate and automate renewal monitoring.",
                    score=85,
                )
            )
        elif days_left <= profile.expiring_critical_days:
            findings.append(
                _finding(
                    key="tls:certificate-expiring",
                    title=f"Certificate expires in {days_left} days",
                    severity="high",
                    evidence=f"notAfter={cert.get('notAfter')}.",
                    remediation="Renew immediately; verify the renewal automation.",
                    score=72,
                )
            )
        elif days_left <= profile.expiring_warning_days:
            findings.append(
                _finding(
                    key="tls:certificate-expiring",
                    title=f"Certificate expires in {days_left} days",
                    severity="medium",
                    evidence=f"notAfter={cert.get('notAfter')}.",
                    remediation="Schedule renewal before the expiry window closes.",
                    score=48,
                )
            )

    if target and san_all:
        lowered = [str(name).lower() for name in san_all]
        bare = target.lower()
        matches = any(
            name == bare or (name.startswith("*.") and bare.endswith(name[1:]) and bare != name[2:])
            for name in lowered
        )
        if not matches:
            findings.append(
                _finding(
                    key="tls:certificate-hostname-mismatch",
                    title="Certificate SANs do not cover the assessed hostname",
                    severity="high",
                    evidence=f"Host '{target}' not present in SAN list {lowered[:10]}.",
                    remediation="Issue a certificate whose SAN set covers every served name.",
                    score=76,
                    human=True,
                    reason="Wildcard depth rules differ per CA; confirm against the served name.",
                )
            )

    signature = str(details.get("signature_algorithm") or "").lower()
    if any(alg in signature for alg in profile.weak_signature_algorithms):
        findings.append(
            _finding(
                key="tls:weak-signature-algorithm",
                title="Certificate is signed with a deprecated digest",
                severity="medium",
                evidence=f"Signature algorithm observed: {details.get('signature_algorithm')}.",
                remediation="Re-issue the certificate with SHA-256 or stronger.",
                score=52,
            )
        )

    key_type = str(details.get("key_type") or "")
    key_bits = int(details.get("key_bits") or 0)
    weak_bits = (
        profile.weak_rsa_bits if key_type.startswith("RSA") else profile.weak_ec_bits
    )
    if key_bits and key_bits < weak_bits:
        findings.append(
            _finding(
                key="tls:weak-certificate-key",
                title=f"Certificate public key is only {key_bits} bits ({key_type})",
                severity="medium",
                evidence=f"Parsed SubjectPublicKeyInfo reports {key_type} {key_bits} bits.",
                remediation=f"Re-issue with at least {weak_bits} bits or a modern curve.",
                score=50,
            )
        )

    # --- HSTS -----------------------------------------------------------------
    hsts_result: dict[str, Any] = {"checked": False}
    if hsts is not None:
        hsts_result = dict(hsts)
        header = str(hsts.get("value") or "")
        if hsts.get("checked"):
            if not header:
                findings.append(
                    _finding(
                        key="tls:hsts-missing",
                        title="Strict-Transport-Security header is absent",
                        severity="medium",
                        evidence="The HTTPS response carried no Strict-Transport-Security header.",
                        remediation=(
                            "Send 'Strict-Transport-Security: max-age=31536000; includeSubDomains'."
                        ),
                        score=55,
                    )
                )
            else:
                max_age = 0
                for part in header.split(";"):
                    part = part.strip()
                    if part.lower().startswith("max-age="):
                        try:
                            max_age = int(part.split("=", 1)[1])
                        except ValueError:
                            max_age = 0
                if max_age < profile.hsts_min_max_age:
                    findings.append(
                        _finding(
                            key="tls:hsts-max-age-short",
                            title="HSTS max-age is below one year",
                            severity="low",
                            evidence=f"Header value: {header[:200]} (max-age={max_age}).",
                            remediation=(
                                f"Raise max-age to at least {profile.hsts_min_max_age} seconds."
                            ),
                            score=28,
                        )
                    )

    # --- summary --------------------------------------------------------------
    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    worst = max(
        (severity_rank.get(f["severity"], 0) for f in findings),
        default=0,
    )
    summary = {
        "protocols_supported": supported,
        "deprecated_enabled": deprecated_enabled,
        "minimum_acceptable": profile.minimum_acceptable,
        "meets_minimum": not deprecated_enabled and bool(modern),
        "certificate": {
            "subject_cn": subject_cn,
            "issuer_cn": details.get("issuer_cn"),
            "san_dns_count": len(san_dns),
            "san_sample": san_dns[:10],
            "not_before": details.get("not_before"),
            "not_after": details.get("not_after") or cert.get("notAfter"),
            "days_until_expiry": days_left,
            "signature_algorithm": details.get("signature_algorithm"),
            "key_type": key_type,
            "key_bits": key_bits,
            "self_issued": details.get("self_issued"),
            "sha256": probe.get("certificate_sha256"),
            "trusted": probe.get("trusted"),
            "parse_error": details.get("parse_error"),
        },
        "hsts": hsts_result,
        "server_default_cipher": probe.get("server_default_cipher"),
        "risk": {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "info"}[worst],
        "finding_count": len(findings),
    }
    return findings, summary


class TLSAuditService:
    """Governed orchestration: scope -> pinned probe -> findings -> immutable record."""

    def __init__(
        self,
        *,
        db: Database,
        scope: ScopePolicyEngine,
        store: WorkspaceStore,
        profile: TLSProbeProfile,
        evidence_gate: Any | None = None,
    ) -> None:
        self.db = db
        self.scope = scope
        self.store = store
        self.profile = profile
        self.evidence_gate = evidence_gate

    async def analyze(
        self,
        *,
        principal: OperatorPrincipal,
        engagement_id: str,
        target: str,
        port: int = 443,
        mission_id: str | None = None,
        include_hsts: bool = True,
    ) -> dict[str, Any]:
        if not principal.can_access_engagement(engagement_id):
            raise PermissionError("This engagement is not assigned to the operator.")
        if port not in self.profile.allowed_ports:
            raise TLSAuditError(
                f"Port {port} is outside the TLS analysis profile {self.profile.allowed_ports}."
            )
        policy = self.db.get_tool_policy(TLS_TOOL)
        if (
            not policy
            or not policy["enabled"]
            or policy["requires_approval"]
            or policy["risk_level"] not in {"low", "medium"}
        ):
            raise PermissionError(
                "TLS analysis requires an enabled, low/medium-risk, non-gated tls_inspect policy."
            )
        allowed_ports = [int(p) for p in (policy["allowed_params"] or {}).get("allowed_ports", [])]
        if allowed_ports and port not in allowed_ports:
            raise PermissionError(f"Port {port} is not in the tls_inspect policy allowlist.")

        import asyncio

        scope = await asyncio.to_thread(
            self.scope.evaluate_target, engagement_id, target, resolve_dns=True
        )
        if not scope.allowed:
            raise PermissionError(scope.reason or "Target is out of scope.")
        if not scope.resolved_ips:
            raise PermissionError("No safe DNS pin is available; TLS analysis fails closed.")

        pin = scope.resolved_ips[0]
        try:
            ipaddress.ip_address(pin)
        except ValueError as exc:  # pragma: no cover - defensive
            raise TLSAuditError("Resolver returned a non-address pin.") from exc

        probe = await asyncio.to_thread(
            probe_pinned,
            server_name=scope.normalized_target,
            connect_ip=pin,
            port=port,
            profile=self.profile,
        )
        if "connect" in (probe.get("errors") or {}):
            raise TLSAuditError(
                f"Could not open a TCP/TLS session to {scope.normalized_target}:{port} "
                f"({probe['errors']['connect']})."
            )

        hsts = (
            await self._check_hsts(
                principal=principal,
                engagement_id=engagement_id,
                target=scope.normalized_target,
                pin=pin,
                port=port,
            )
            if include_hsts
            else {"checked": False, "reason": "HSTS check disabled for this run."}
        )

        findings, summary = evaluate_probe(
            target=scope.normalized_target,
            port=port,
            probe=probe,
            profile=self.profile,
            hsts=hsts,
        )
        gate = None
        if self.evidence_gate is not None and findings:
            gate = self.evidence_gate.evaluate_many(
                findings,
                context={
                    "engagement_id": engagement_id,
                    "target": scope.normalized_target,
                    "evidence_available": bool(probe.get("certificate_sha256")),
                },
            )
            for index, finding in enumerate(findings):
                if gate and index < len(gate):
                    finding["evidence_gate"] = gate[index]["status"]

        record = self.store.save_tls_audit(
            engagement_id=engagement_id,
            target=scope.normalized_target,
            port=port,
            requested_by=principal.operator_id,
            mission_id=mission_id,
            payload={
                "probe": probe,
                "summary": summary,
                "findings": findings,
                "profile": {
                    "protocols": list(self.profile.protocols),
                    "minimum_acceptable": self.profile.minimum_acceptable,
                    "checks": ["protocols", "ciphers", "certificate", "hsts"],
                    "external_adapters": "not_invoked",
                },
            },
        )
        self.db.write_audit_log(
            engagement_id=engagement_id,
            operator_id=principal.operator_id,
            target=scope.normalized_target,
            resolved_ips=scope.resolved_ips,
            tool_or_script=f"tls_deep_analysis:{record['audit_id']}",
            params={
                "port": port,
                "pinned_ip": pin,
                "sha256": record["sha256"],
                "findings": len(findings),
                "risk": summary["risk"],
            },
            exit_code=0,
            stdout_summary=(
                f"TLS audit risk={summary['risk']}; protocols={summary['protocols_supported']}; "
                f"deprecated={summary['deprecated_enabled'] or 'none'}"
            ),
            status="completed",
        )
        return {
            **record,
            "summary": summary,
            "findings": findings,
            "pinned_ip": pin,
            "evidence_gate": gate,
        }

    async def _check_hsts(
        self,
        *,
        principal: OperatorPrincipal,
        engagement_id: str,
        target: str,
        pin: str,
        port: int,
    ) -> dict[str, Any]:
        """Read the HSTS header through the governed MCP bridge, never directly."""
        from mcp_server.tools import validate_tool_params

        mcp = getattr(self, "mcp", None)
        policy = self.db.get_tool_policy(HSTS_TOOL)
        if mcp is None:
            return {"checked": False, "reason": "MCP bridge unavailable in this runtime."}
        if not policy or not policy["enabled"] or policy["requires_approval"]:
            return {"checked": False, "reason": "http_headers policy is disabled or gated."}
        try:
            params = validate_tool_params(
                HSTS_TOOL,
                {"scheme": "https", "method": "HEAD", "port": port, "path": "/"},
                policy["allowed_params"],
            )
        except Exception as exc:  # noqa: BLE001 - policy refusal is not fatal here
            return {"checked": False, "reason": f"Parameter refusal: {exc}"[:200]}
        try:
            result = await mcp.call_tool(
                tool_name=HSTS_TOOL,
                target=target,
                params=params,
                max_timeout=min(int(policy["max_timeout"]), 15),
                allowed_params=policy["allowed_params"],
                pinned_ips=[pin],
            )
        except Exception as exc:  # noqa: BLE001 - correlate, do not fail the audit
            return {"checked": False, "reason": f"Header probe failed: {type(exc).__name__}"}
        if int(result.get("exit_code", 1)) != 0:
            return {"checked": False, "reason": "Header probe returned a non-zero status."}
        try:
            parsed = json.loads(result.get("stdout") or "{}")
        except ValueError:
            return {"checked": False, "reason": "Header probe output was not JSON."}
        headers = {
            str(k).lower(): v for k, v in (parsed.get("present_security_headers") or {}).items()
        }
        return {
            "checked": True,
            "value": headers.get("strict-transport-security", ""),
            "status_code": parsed.get("status_code"),
        }
