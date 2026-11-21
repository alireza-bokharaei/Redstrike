"""Advisory agent-role catalogue for 2.2, adapted from the pentest-agents workflow.

A role is a *planner*: it proposes which governed primitive to use, what to look
for, and what would refute the claim. A role can never call a tool, raise a
budget, widen scope, approve a request or mark a finding confirmed — those remain
Gateway/Gateway-policy/database decisions.

Each role declares the capabilities it needs so the Gateway can intersect them
with the active mode before a planner is allowed to run.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class AgentRole:
    role_id: str
    title: str
    phase: str
    capabilities: frozenset[str]
    primitives: tuple[str, ...]
    objective: str
    refutation: str
    outputs: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "role_id": self.role_id,
            "title": self.title,
            "phase": self.phase,
            "capabilities": sorted(self.capabilities),
            "primitives": list(self.primitives),
            "objective": self.objective,
            "refutation": self.refutation,
            "outputs": list(self.outputs),
            "can_execute": False,
            "can_approve": False,
            "can_widen_scope": False,
        }


def _role(
    role_id: str,
    title: str,
    phase: str,
    capabilities: tuple[str, ...],
    primitives: tuple[str, ...],
    objective: str,
    refutation: str,
    outputs: tuple[str, ...] = (),
) -> AgentRole:
    return AgentRole(
        role_id=role_id,
        title=title,
        phase=phase,
        capabilities=frozenset(capabilities),
        primitives=primitives,
        objective=objective,
        refutation=refutation,
        outputs=outputs,
    )


AGENT_ROLES: tuple[AgentRole, ...] = (
    # -- reconnaissance -------------------------------------------------------
    _role(
        "scope-cartographer",
        "Scope Cartographer",
        "recon",
        ("recon",),
        ("dns_lookup", "tcp_port_probe"),
        "Enumerate only in-scope names and reachable service ports; stop at the allowlist edge.",
        "Refutes itself when a discovered name resolves outside the engagement allowlist.",
        ("asset-inventory.json",),
    ),
    _role(
        "subdomain-expansion-planner",
        "Subdomain Expansion Planner",
        "recon",
        ("recon",),
        ("dns_lookup",),
        "Propose candidate subdomains from the mission's declared prefix budget.",
        "Every candidate is rejected unless the scope engine independently allows it.",
        ("subdomain-candidates.txt",),
    ),
    _role(
        "service-inventory-analyst",
        "Service Inventory Analyst",
        "recon",
        ("recon", "port_probe"),
        ("tcp_port_probe", "nmap"),
        "Describe exposed services and defensible follow-up checks per open port.",
        "Treats an open port as inventory, never as a finding.",
    ),
    # -- transport ------------------------------------------------------------
    _role(
        "tls-deep-analyst",
        "TLS Deep Analyst",
        "transport",
        ("tls_deep_analysis", "external_tls_adapters"),
        ("tls_inspect", "http_headers"),
        "Sweep protocol floor, cipher strength, certificate chain and HSTS posture.",
        "Re-probes any claimed weak protocol twice before it may be reported.",
        ("tls-summary.json",),
    ),
    _role(
        "certificate-lifecycle-analyst",
        "Certificate Lifecycle Analyst",
        "transport",
        ("tls_deep_analysis",),
        ("tls_inspect",),
        "Correlate expiry windows, SAN coverage and signature algorithm strength.",
        "Confirms an expiry finding against the parsed notAfter, not a model summary.",
    ),
    # -- web hunters ----------------------------------------------------------
    _role(
        "http-hardening-hunter",
        "HTTP Hardening Hunter",
        "web",
        ("http_header_audit",),
        ("http_headers",),
        "Detect missing or weak defensive headers on an approved endpoint and method.",
        "Downgrades a missing header to informational when a compensating proxy sets it.",
        ("http-hardening.md",),
    ),
    _role(
        "cors-posture-hunter",
        "CORS Posture Hunter",
        "web",
        ("http_header_audit",),
        ("http_headers",),
        "Read Access-Control-* behaviour allowed by the header allowlist.",
        "Discards any observation that would require an authenticated session or a custom origin.",
    ),
    _role(
        "cookie-flag-hunter",
        "Cookie Flag Hunter",
        "web",
        ("http_header_audit",),
        ("http_headers",),
        "Check Secure/HttpOnly/SameSite only when the collector is allowed to retain Set-Cookie.",
        "Reports 'not observable' rather than guessing when the header is discarded.",
    ),
    _role(
        "redirect-policy-analyst",
        "Redirect Policy Analyst",
        "web",
        ("http_header_audit",),
        ("http_headers",),
        "Describe a 3xx Location without following it.",
        "Never chases a redirect; a cross-host Location is reported, not visited.",
    ),
    # -- discovery / correlation ---------------------------------------------
    _role(
        "vulnerability-class-planner",
        "Vulnerability Class Planner",
        "discovery",
        ("recon", "http_header_audit", "tls_deep_analysis"),
        ("http_headers", "tls_inspect", "dns_lookup"),
        "Rank the vulnerability classes most likely to be reachable from observed surface.",
        "Marks every hypothesis as a hypothesis until a deterministic check supports it.",
    ),
    _role(
        "chain-builder",
        "Exploit Chain Builder (planning only)",
        "discovery",
        ("chain_analysis", "correlation"),
        (),
        "Describe how confirmed findings could combine, with the weakest link named.",
        "Refuses to combine a candidate-level finding into a confirmed chain.",
        ("chain-plan.md",),
    ),
    _role(
        "devils-advocate",
        "Devil's Advocate",
        "validation",
        ("correlation",),
        (),
        "Attempt to disprove every candidate: cache, CDN, proxy, honeypot, by-design, measurement error.",
        "If a counter-observation exists, the candidate may not be confirmed.",
        ("refutations.json",),
    ),
    _role(
        "evidence-validator",
        "Evidence Validator",
        "validation",
        ("correlation",),
        (),
        "Apply the seven-question gate and record which question failed and why.",
        "Cannot confirm anything itself; it can only reject or downgrade.",
        ("gate-results.json",),
    ),
    _role(
        "finding-correlator",
        "Finding Correlator",
        "correlation",
        ("correlation",),
        (),
        "Merge duplicate observations across hosts and record the shared root cause.",
        "Requires an identical finding key and a re-runnable check before merging.",
    ),
    # -- expansion ------------------------------------------------------------
    _role(
        "scope-expansion-negotiator",
        "Scope Expansion Negotiator",
        "governance",
        ("scope_expansion_request",),
        (),
        "Draft a scope or budget expansion request with the RoE clause it relies on.",
        "Cannot add a target itself; a different human must approve every expansion.",
    ),
    _role(
        "approval-drafter",
        "Approval Drafter",
        "governance",
        ("correlation",),
        (),
        "Prepare the human-readable justification for a gated action.",
        "A model-written justification is still subject to independent approval.",
    ),
    # -- bug bounty -----------------------------------------------------------
    _role(
        "bug-bounty-scope-sync",
        "Bug Bounty Scope Sync",
        "bug_bounty",
        ("recon",),
        (),
        "Reconcile the program's in-scope list with the local engagement allowlist.",
        "Any program asset absent locally is reported as 'not authorised here'.",
    ),
    _role(
        "duplicate-hinter",
        "Duplicate Hinter",
        "bug_bounty",
        ("duplicate_hinting",),
        (),
        "Flag findings whose class/endpoint is commonly already reported.",
        "Explicitly states it has no live platform lookup and cannot prove non-duplication.",
    ),
    _role(
        "report-writer",
        "Report Writer",
        "reporting",
        ("report_drafting",),
        (),
        "Draft a reproduction-first report from gate-confirmed findings only.",
        "Refuses to include a finding whose gate status is not 'confirmed'.",
        ("report-draft.md",),
    ),
    # -- ctf / binary --------------------------------------------------------
    _role(
        "binary-triage-analyst",
        "Binary Triage Analyst",
        "binary",
        ("binary_hardening_triage",),
        ("binary_hardening_triage",),
        "Read ELF hardening flags (NX, PIE, RELRO, canary, RPATH) from a local artifact.",
        "Reports only parsed header facts; no exploitation, no remote interaction.",
        ("binary-hardening.json",),
    ),
    _role(
        "challenge-solver",
        "Challenge Solver",
        "ctf",
        ("recon", "http_header_audit"),
        ("http_headers", "dns_lookup"),
        "Plan challenge-specific checks against the CTF's authorised host set.",
        "Cannot expand beyond the CTF engagement's declared allowlist.",
    ),
    # -- 2.3: expanded roster (pentest-agents lineage, 48-50 roles) ----------
    # Recon & asset discovery
    _role(
        "asset-graph-builder",
        "Asset Graph Builder",
        "recon",
        ("recon",),
        ("dns_lookup", "subfinder", "amass", "httpx"),
        "Assemble hosts, endpoints and technologies into one asset graph per engagement.",
        "Every node must trace to an observed response or a declared scope entry.",
        ("asset-graph.json",),
    ),
    _role(
        "cloud-exposure-hunter",
        "Cloud Exposure Hunter",
        "recon",
        ("recon", "cloud_posture"),
        ("cloud_enum", "s3scanner", "trivy"),
        "Find publicly reachable storage and misconfigured cloud endpoints in scope.",
        "A bucket is only reported if it resolves to the client's owned account namespace.",
    ),
    _role(
        "subdomain-takeover-analyst",
        "Subdomain Takeover Analyst",
        "recon",
        ("recon",),
        ("subjack", "dns_lookup"),
        "Detect dangling CNAMEs pointing at unclaimed third-party services.",
        "Requires a reproducible unclaimed-service response, not just a 404.",
    ),
    # Transport / TLS
    _role(
        "cipher-suite-analyst",
        "Cipher Suite Analyst",
        "transport",
        ("tls_deep_audit",),
        ("testssl.sh", "sslyze", "sslscan"),
        "Enumerate supported protocols and ciphers, flagging legacy and NULL suites.",
        "Distinguishes server-side support from client-offered configuration.",
        ("tls-ciphers.json",),
    ),
    _role(
        "hsts-preload-analyst",
        "HSTS & Preload Analyst",
        "transport",
        ("tls_deep_audit", "http_header_audit"),
        ("http_headers",),
        "Check HSTS max-age, includeSubDomains, preload eligibility and redirect parity.",
        "A header present only on some vhosts is reported as partial, not compliant.",
    ),
    # Web application
    _role(
        "authn-flow-analyst",
        "Authentication Flow Analyst",
        "web",
        ("active_web_checks",),
        ("http_headers", "ffuf"),
        "Trace login, session issuance, MFA and password-reset flows for logic gaps.",
        "A flow is not 'broken' unless an attacker without credentials can traverse it.",
    ),
    _role(
        "authz-matrix-analyst",
        "Authorization Matrix Analyst",
        "web",
        ("active_web_checks",),
        ("http_headers", "ffuf"),
        "Compare role/tenant access to the same object to find horizontal and vertical gaps.",
        "Requires a second identity's response as evidence, not an inference.",
    ),
    _role(
        "injection-class-planner",
        "Injection Class Planner",
        "discovery",
        ("active_web_checks", "vulnerability_discovery"),
        ("sqlmap", "commix", "dalfox"),
        "Choose the injection class most likely for each parameter and its cheapest proof.",
        "Every proposed probe must come with the negative result that would refute it.",
    ),
    _role(
        "ssti-xxe-ssrf-planner",
        "SSTI/XXE/SSRF Planner",
        "discovery",
        ("active_web_checks", "vulnerability_discovery"),
        ("ssrfmap", "xxeinjector"),
        "Plan server-side template, entity-expansion and request-forgery probes.",
        "Out-of-band proof must use a Gateway-controlled callback, never a third party.",
    ),
    _role(
        "business-logic-analyst",
        "Business Logic Analyst",
        "discovery",
        ("active_web_checks", "vulnerability_discovery"),
        ("http_headers", "ffuf"),
        "Model intended business rules and look for sequences that violate them.",
        "A logic finding needs the intended rule cited from a spec or observed control.",
    ),
    _role(
        "race-condition-analyst",
        "Race Condition Analyst",
        "discovery",
        ("active_web_checks", "vulnerability_discovery"),
        ("httpx", "ffuf"),
        "Plan concurrency probes where single requests look safe but parallel ones do not.",
        "Reproduction must show the invariant violated, not merely slow responses.",
    ),
    _role(
        "api-surface-analyst",
        "API Surface Analyst",
        "web",
        ("active_web_checks",),
        ("kiterunner", "arjun", "graphql-cop"),
        "Map REST/GraphQL endpoints and parameters, including shadow and versioned routes.",
        "Undocumented is not the same as unauthorized; authorization is proven separately.",
    ),
    _role(
        "http-smuggling-analyst",
        "HTTP Smuggling Analyst",
        "web",
        ("active_web_checks",),
        ("smuggler", "h2csmuggler"),
        "Test for request smuggling and connection-level desync on in-scope front ends.",
        "Requires a differential response between front end and back end, not a guess.",
    ),
    # Infrastructure & identity
    _role(
        "ad-path-analyst",
        "Active Directory Path Analyst",
        "ad",
        ("ad_enumeration",),
        ("bloodhound-python", "impacket-GetNPUsers", "ldapsearch"),
        "Model Kerberos and ACL paths toward privileged groups.",
        "Path exists only when each edge was observed from a live query.",
    ),
    _role(
        "network-segmentation-analyst",
        "Network Segmentation Analyst",
        "network",
        ("recon",),
        ("nmap", "naabu"),
        "Test whether reachable services respect the intended segmentation boundary.",
        "A reachable port is not a finding unless the segmentation model forbids it.",
    ),
    _role(
        "password-policy-analyst",
        "Password Policy Analyst",
        "password",
        ("password_audit",),
        ("hydra", "john"),
        "Assess lockout, throttling and password policy strength within the spend budget.",
        "Never reports a cracked password as a finding; reports the policy gap instead.",
    ),
    # Exploitation & validation
    _role(
        "poc-author",
        "Proof-of-Concept Author",
        "validation",
        ("exploitation_poc",),
        (),
        "Write the smallest PoC that demonstrates impact, with reproduction steps.",
        "Refuses any PoC whose blast radius exceeds the finding it proves.",
        ("poc.py", "repro-steps.md"),
    ),
    _role(
        "exploit-reproducer",
        "Exploit Reproducer",
        "validation",
        ("exploitation_poc",),
        (),
        "Re-run another operator's PoC and compare output digests.",
        "Reports a mismatch as unverified; never rationalises a difference away.",
    ),
    _role(
        "memory-corruption-analyst",
        "Memory Corruption Analyst",
        "binary",
        ("binary_exploitation",),
        ("checksec", "ropgadget", "pwntools"),
        "Assess mitigations and build a controlled crash-to-control POC for a local binary.",
        "A crash is not a finding until instruction-pointer control is demonstrated.",
    ),
    _role(
        "rop-chain-builder",
        "ROP Chain Builder",
        "binary",
        ("binary_exploitation",),
        ("ropgadget", "pwntools"),
        "Compose a minimal gadget chain for a challenge binary with a known offset.",
        "Refuses chains that need a gadget the binary does not contain.",
    ),
    # Bug bounty & reporting
    _role(
        "bounty-scope-diff-analyst",
        "Bounty Scope Diff Analyst",
        "bug_bounty",
        ("bug_bounty",),
        (),
        "Diff platform scope against the engagement allowlist and flag both directions.",
        "Never treats platform permission as a substitute for engagement permission.",
    ),
    _role(
        "remediation-designer",
        "Remediation Designer",
        "reporting",
        ("report_drafting",),
        (),
        "Propose a fix, a compensating control and a detection for each verified finding.",
        "Marks a recommendation as 'compensating only' when it is not a true fix.",
    ),
    _role(
        "quality-gate-reviewer",
        "Quality Gate Reviewer",
        "validation",
        ("validation",),
        (),
        "Apply the confirmation gate to every candidate before it can be reported.",
        "Blocks any candidate missing reproducible, independent evidence.",
    ),
    _role(
        "rules-of-engagement-auditor",
        "Rules of Engagement Auditor",
        "governance",
        ("governance",),
        (),
        "Check every planned action against the RoE window, allowlist and declared limits.",
        "Escalates rather than resolving ambiguity in the operator's favour.",
    ),
    # Governance & orchestration
    _role(
        "budget-steward",
        "Budget Steward",
        "governance",
        ("governance",),
        (),
        "Track action and time budgets and propose extensions before they are exhausted.",
        "Never raises a budget; only drafts the two-person request.",
    ),
    _role(
        "elevation-request-writer",
        "Elevation Request Writer",
        "governance",
        ("governance",),
        (),
        "Draft a privilege-elevation request naming the exact class and its justification.",
        "Refuses a request that does not name a declared privilege class.",
    ),
    _role(
        "posture-advisor",
        "Posture Advisor",
        "governance",
        ("governance",),
        (),
        "Recommend permissive, read-only or CTF posture for the engagement's risk profile.",
        "Recommends the narrowest posture that still satisfies the mission.",
    ),
    _role(
        "handover-writer",
        "Handover Writer",
        "governance",
        ("governance",),
        (),
        "Produce the session brief: mission, scope, RoE, budget, TLS status, layers.",
        "States remaining budget from the ledger, never from memory.",
    ),
    # -- 2.3.1: class-hunting, web-vector and static-analysis roles -----------
    # These name the hunting disciplines the referenced roster covers. Like every
    # other role they plan only: each states the evidence that would refute it, so
    # a hypothesis that cannot be disproved is visibly not a finding.
    _role(
        "xss-hunter",
        "XSS Hunter",
        "web",
        ("active_web_checks",),
        ("mcp:http_headers", "catalog:dalfox", "catalog:arjun"),
        "Test reflected, stored and DOM XSS classes with a benign marker payload.",
        "Refuted when the marker is encoded on output and the DOM sink is unreachable.",
        ("payload_matrix", "callback_record"),
    ),
    _role(
        "sqli-hunter",
        "SQL Injection Hunter",
        "web",
        ("active_web_checks",),
        ("mcp:http_headers", "catalog:sqlmap"),
        "Distinguish a real injection from an input-validation error using timing and boolean baselines.",
        "Refuted when the response time and body are indistinguishable across a 10x baseline spread.",
        ("baseline_table", "differential_record"),
    ),
    _role(
        "idor-hunter",
        "IDOR Hunter",
        "web",
        ("active_web_checks",),
        ("mcp:http_headers",),
        "Test object-level authorisation with two accounts and one shared object.",
        "Refuted when the second account receives the same 403/404 as an unauthenticated request.",
        ("two_account_matrix",),
    ),
    _role(
        "ssrf-hunter",
        "SSRF Hunter",
        "web",
        ("active_web_checks",),
        ("mcp:http_headers", "catalog:ssrfmap"),
        "Determine whether a user-supplied URL reaches an operator-controlled listener.",
        "Refuted when no out-of-band callback arrives and the response echoes a rejected URL.",
        ("callback_log",),
    ),
    _role(
        "ssti-hunter",
        "SSTI Hunter",
        "web",
        ("active_web_checks",),
        ("mcp:http_headers",),
        "Test template evaluation with an arithmetic probe before attempting any file read.",
        "Refuted when the expression renders literally under every encoding tried.",
        ("render_evidence",),
    ),
    _role(
        "xxe-hunter",
        "XXE Hunter",
        "web",
        ("active_web_checks",),
        ("mcp:http_headers", "catalog:xxeinjector"),
        "Test external-entity resolution with an out-of-band fetch, never an inline guess.",
        "Refuted when the parser rejects the DOCTYPE or never fetches the entity.",
        ("oob_fetch_log",),
    ),
    _role(
        "rce-hunter",
        "RCE Hunter",
        "web",
        ("active_web_checks", "exploitation_poc"),
        ("mcp:http_headers", "catalog:commix"),
        "Escalate a candidate injection to a bounded, benign command execution proof.",
        "Refuted when no marker output appears and the service behaviour is unchanged.",
        ("marker_output", "reproduction_steps"),
    ),
    _role(
        "auth-bypass-analyst",
        "Authentication Bypass Analyst",
        "web",
        ("active_web_checks",),
        ("mcp:http_headers", "catalog:jwt_tool"),
        "Test JWT handling, session invalidation and password-reset flows for bypass.",
        "Refuted when every tampered token is rejected and the reset token is single-use.",
        ("token_matrix",),
    ),
    _role(
        "cors-hunter",
        "CORS Misconfiguration Hunter",
        "web",
        ("http_header_audit",),
        ("mcp:http_headers", "catalog:corsy"),
        "Test whether an untrusted Origin is reflected with credentials allowed.",
        "Refuted when the response never echoes the origin and never sets credentials.",
        ("origin_reflection_matrix",),
    ),
    _role(
        "open-redirect-hunter",
        "Open Redirect Hunter",
        "web",
        ("http_header_audit",),
        ("mcp:http_headers",),
        "Test redirect parameters for off-host Location headers.",
        "Refuted when every candidate is canonicalised to a relative or same-host path.",
        ("location_header_log",),
    ),
    _role(
        "csrf-analyst",
        "CSRF Analyst",
        "web",
        ("active_web_checks",),
        ("mcp:http_headers",),
        "Test state-changing requests for missing anti-CSRF controls and SameSite enforcement.",
        "Refuted when a token is required, bound to the session, and SameSite blocks the cross-site send.",
        ("token_binding_evidence",),
    ),
    _role(
        "race-condition-analyst",
        "Race Condition Analyst",
        "web",
        ("active_web_checks",),
        ("mcp:http_headers",),
        "Test single-use actions for committed double effects under concurrent delivery.",
        "Refuted when the second request is rejected by a serialising constraint.",
        ("concurrency_log", "state_before_after"),
    ),
    _role(
        "graphql-auditor",
        "GraphQL Auditor",
        "web",
        ("active_web_checks",),
        ("mcp:http_headers", "catalog:graphql-cop"),
        "Test introspection exposure, field-level authorisation and query depth limits.",
        "Refuted when introspection is disabled and every unlisted field is denied.",
        ("introspection_result",),
    ),
    _role(
        "waf-profiler",
        "WAF Profiler",
        "web",
        ("http_header_audit",),
        ("mcp:http_headers", "catalog:wafw00f"),
        "Identify the edge defence so later tests are interpreted against it.",
        "Refuted when the vendor claim is not supported by at least two independent responses.",
        ("fingerprint_table",),
    ),
    _role(
        "mobile-app-analyst",
        "Mobile App Analyst",
        "binary",
        ("binary_hardening_triage",),
        ("catalog:apktool", "catalog:jadx", "catalog:aapt"),
        "Review an APK/IPA artifact for exported components, secrets and weak transport settings.",
        "Refuted when the manifest export is protected by a signature-level permission and no secret is stored.",
        ("manifest_excerpt", "secret_inventory"),
    ),
    _role(
        "wireless-survey-analyst",
        "Wireless Survey Analyst",
        "network",
        ("port_probe",),
        ("catalog:airodump-ng", "catalog:wash"),
        "Summarise an authorised RF survey: encryption posture, WPS exposure, rogue APs.",
        "Refuted when the capture shows only authorised infrastructure on WPA3/802.1X.",
        ("survey_summary",),
    ),
    _role(
        "forensics-examiner",
        "Forensics Examiner",
        "binary",
        ("binary_hardening_triage",),
        ("catalog:binwalk", "catalog:volatility3", "catalog:bulk_extractor"),
        "Extract and catalogue artefacts from an image or firmware artifact with hashes.",
        "Refuted when the artefact hashes do not match the acquisition record.",
        ("artefact_inventory", "hash_manifest"),
    ),
    _role(
        "coverage-auditor",
        "Coverage Auditor",
        "validation",
        ("validation",),
        (),
        "Compare the coverage ledger against the declared surface and name every gap.",
        "Refuses to call a surface covered unless a check is recorded for it.",
        ("coverage_gaps",),
    ),
    _role(
        "response-diff-analyst",
        "Response Diff Analyst",
        "validation",
        ("validation",),
        (),
        "Explain what changed between two observations of the same asset and who must re-check.",
        "Refuted when the change is explained by a declared deployment window.",
        ("diff_summary",),
    ),
    _role(
        "intel-ranker",
        "Intel Ranker",
        "discovery",
        ("vulnerability_discovery",),
        (),
        "Rank vulnerability classes from stated signals and recorded outcomes.",
        "Names the weights and the signals it used; refuses a score with no stated basis.",
        ("ranked_classes", "basis"),
    ),
    _role(
        "report-quality-reviewer",
        "Report Quality Reviewer",
        "reporting",
        ("report_drafting",),
        (),
        "Score a write-up against the pre-submission evidence checks before it is sent.",
        "Refuses to submit a report whose reproduction steps a second operator cannot follow.",
        ("evidence_score", "gaps"),
    ),
)


_BY_ID = {role.role_id: role for role in AGENT_ROLES}


class UnknownRole(KeyError):
    pass


def get_role(role_id: str) -> AgentRole:
    try:
        return _BY_ID[role_id]
    except KeyError as exc:
        raise UnknownRole(f"Unknown agent role '{role_id}'.") from exc


def list_roles() -> list[dict[str, Any]]:
    return [role.to_dict() for role in AGENT_ROLES]


def roles_for_capabilities(capabilities: set[str] | frozenset[str]) -> list[AgentRole]:
    """Roles whose required capabilities are all satisfied by the active mode."""
    return [role for role in AGENT_ROLES if role.capabilities <= set(capabilities)]


def plan(
    *,
    capabilities: set[str] | frozenset[str],
    mode_id: str,
    phase: str | None = None,
) -> dict[str, Any]:
    """Return the advisory plan for a mode; contains no executable action."""
    available = roles_for_capabilities(capabilities)
    if phase:
        available = [r for r in available if r.phase == phase]
    blocked = [r for r in AGENT_ROLES if r.role_id not in {a.role_id for a in available}]
    return {
        "mode": mode_id,
        "phase": phase,
        "roles": [r.to_dict() for r in available],
        "unavailable_roles": [
            {"role_id": r.role_id, "missing_capabilities": sorted(r.capabilities - set(capabilities))}
            for r in blocked
        ],
        "advisory_only": True,
        "note": (
            "Roles plan; the Gateway executes. No role output can approve, expand scope, "
            "raise a budget or confirm a finding."
        ),
    }
