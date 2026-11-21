# Redstrike 2.2 — Operational Modes, Governed Expansion and Deep TLS

Status: implemented in `2.2.0`.
Audience: engagement owners (IR/Red Team leads), approvers, platform administrators.

This document describes what 2.2 adds, **what it deliberately does not add**, and
how each new capability is bounded. It is a design record, not legal advice and
not a claim of feature parity with any referenced upstream project.

---

## 1. Where the new controls live

| Component | File | Role |
|---|---|---|
| Mode/capability policy | `config/capabilities.yaml` | Declarative ceilings, capability sets, TLS profile, expansion limits, gate questions |
| Policy engine | `gateway/capabilities.py` | Validates the manifest, resolves capabilities, enforces ceilings, composes modes, proposes next steps |
| Mode composition | `config/capabilities.yaml` (`composition:`) | Named combinations, `max_modes: 3`, and the one-directional merge rules |
| Deep TLS analysis | `gateway/tls_audit.py` | Pinned handshakes, protocol sweep, cipher/certificate/HSTS evaluation |
| DER reader | `gateway/x509_lite.py` | Dependency-free certificate facts (stdlib only) |
| Evidence gate | `gateway/evidence_gate.py` | Deterministic seven-question confirmation |
| Expansion engine | `gateway/expansion.py` | Request/decide/apply for scope, budget, quota, privilege |
| Agent role catalogue | `gateway/agents_registry.py` | 21 advisory roles, capability-intersected |
| Binary triage | `gateway/binary_triage.py` | Read-only ELF hardening inspection |
| API | `gateway/capability_api.py` | `/api/v1/capabilities`, `/tls/*`, `/expansion/*`, `/gate/*`, `/agents/*`, `/binary/*`, `/session/start` |
| Storage | `gateway/migrations/003_capability_modes.sql` | `tls_audits`, `expansion_requests`, `evidence_gate_results`, mission mode columns |
| Tests | `tests/test_capability_modes.py` | 65 tests (policy, gate, TLS, expansion, ELF, X.509) |
| Tests | `tests/test_mode_composition.py` | 23 tests (six modes, composition rules, aliases, decision engine, composed request contracts) |

---

## 2. The control chain

A 2.2 action is authorised only if **all** of these layers agree. Each one can
refuse independently, and every refusal is written to the hash-chained audit
ledger before the HTTP error is returned.

```
Bearer token (SHA-256, RBAC, RPM)
  -> engagement assignment (operator <-> engagement)
    -> signed RoE window (valid_from .. valid_until, engagement active)
      -> allowlist membership + DNS pinning + metadata/rebinding guard
        -> mode declaration (is the mode enabled? does it include the capability?)
          -> live tool policy (enabled? approval-gated? risk level?)
            -> mission ceiling (hosts / actions / seconds)
              -> independent approval (Two-Person Rule, enforced in SQL too)
                -> capability-specific guard (e.g. artifact root, port profile)
```

A capability name never grants anything by itself. `capabilities.py` intersects
the mode's declared set with the SQLite `tool_policy` row, so disabling a tool
still disables every capability that depends on it.

### Administrator kill switch

`tool_policy` row `redgate_capability_mode` (seeded by migration 003):

```json
{"enabled": true, "modes": null}
```

`modes: null` means "the manifest is authoritative". Setting
`{"enabled": false}` disables **all** modes without touching the manifest;
setting a list restricts the platform to those modes. Only an `admin` principal
may change it, and the change is audited.

---

## 3. Operational modes

Every mode has a validated ceiling which is clamped against hard model limits
(`MODEL_HARD_LIMITS`: 8 hosts, 128 actions, 3600 s). A manifest that declares a
larger ceiling is rejected at start-up, so a typo cannot widen the platform.

Six modes are declared:

| Mode | Intent | Mandatory capability | Notes |
|---|---|---|---|
| `vulnerability_discovery` | breadth-first, read-only | `tls_deep_analysis` | proposals for new targets |
| `bug_bounty` | in-program testing + reporting | `tls_deep_analysis` | report drafting, duplicate checks |
| `pentest` | full engagement | `tls_deep_analysis` | chain analysis, PoC lifecycle |
| `assessment` | review-oriented | `tls_deep_analysis` | correlation, reporting |
| `ssl_tls_analysis` | transport-only engagement | `tls_deep_analysis` | narrowest surface; no host fan-out |
| `ctf` | offline scenario | *none* | no network scope expansion |

Modes with a TLS surface declare `tls_deep_analysis` as a **mandatory**
capability, so it cannot be switched off while such a mode is active. The
session-start brief reports whether that duty is still pending. `ctf` has no
mandatory TLS duty and cannot request scope expansion.

### 3a. Composing modes

A real engagement is rarely one thing: a transport review is usually bolted onto
a web assessment. `config/capabilities.yaml` therefore declares named
compositions (`pentest_plus_tls`, `bug_bounty_plus_tls`, …) and accepts an
explicit `a+b` spec, which `CapabilityRegistry.parse_mode()` resolves.

```http
POST /api/v1/capabilities/compose
{"modes": ["pentest", "ssl_tls_analysis"]}
→ {"mode": {"id": "pentest+ssl_tls_analysis", "ceiling": {...},
            "mandatory_capabilities": ["tls_deep_analysis"], ...},
   "audit": {"mode_ids": [...], "capabilities_added": [], "ceiling": {...},
             "rule": "narrowest ceiling wins; mandatory capabilities cannot be removed"}}
```

Composition is deliberately **one-directional**. It widens the set of permitted
capabilities and nothing else:

| Rule | Enforced by |
|---|---|
| `capabilities = base ∪ add − remove` | `CapabilityRegistry.compose()` |
| mandatory capabilities are the union and are re-added after any `remove` | same |
| ceiling is the **minimum** of every part (`max_hosts`, `max_actions`, `max_seconds`, `concurrent_missions`) | same |
| expansion clauses are **intersected**, so composition cannot manufacture a widening clause | same |
| at most `max_modes: 3` parts, each part must be a declared mode | same |
| the result is still clamped by model hard limits, the admin mode toggle, posture, signed scope and the allowlist | `enforce_ceiling`, `resolve`, `scan_runner` |

A composed mode is accepted anywhere a mode id is accepted: `POST /missions`
(`mode_id: "pentest+ssl_tls_analysis"` or the shorthand `"pentest_plus_tls"`),
`/capabilities/resolve`, `/session/start`. The mission stores the resolved
ceiling **and** the composition audit under `mode_ceiling.composition`, so the
record shows which parts were merged and which shrank the ceiling.
`mode_enabled` requires **every** part to be on the administrator's allow-list:
composing cannot smuggle a disabled mode back in.

### 3b. Decision engine

`POST /api/v1/decide/approach` turns observations into a prioritised, governed
next step. It is a deterministic rule engine, not a model call:

```http
POST /api/v1/decide/approach
{"engagement_id": "ENG-2026-001", "target": "198.51.100.10",
 "mode_id": "pentest+ssl_tls_analysis",
 "observations": {"https": true, "server_header": "nginx", "forms": true}}
→ {"signals": ["tls_or_https", "input_surface"],
   "recommended": [{"tool": "testssl.sh", "policy": "tool:testssl.sh",
                    "why": "...", "priority": 10, "evidence": "tls_or_https"}, ...],
   "skipped_as_already_run": [], "advisory_only": true,
   "next_call": "POST /api/v1/offensive/tools/run with tool='testssl.sh'"}
```

- Signals: TLS/HTTPS, web surface, discoverable paths, input surface, injection
  hint, directory service, cloud naming. No signal at all falls back to `nmap`.
- Every step names the `tool:` policy row that governs it; nothing is executed
  by this endpoint — the operator (or the mission planner) still goes through
  `POST /offensive/tools/run`, scope, consent and policy.
- Anything already present in the audit history is reported in
  `skipped_as_already_run` instead of being silently dropped.
- The response is `advisory_only: true` with `basis` stating that no model was
  called, and the call itself is written to the audit ledger.

---

## 4. Deep SSL/TLS analysis

### How a handshake is made safe

1. The scope engine resolves the target and pins one IP.
2. The socket dials **the pinned IP**, while `server_hostname` keeps the
   original name for SNI and certificate matching.
3. Only ports present in **both** the analysis profile and the
   `tls_inspect` tool policy are reachable.
4. The listener's own protocol floor and cipher policy are used for the sweep;
   Redstrike never negotiates on behalf of the target.

### What is measured

- Protocol floor (TLS 1.3, 1.2, 1.1, 1.0; SSLv3 is probed only if the Python
  build supports it), and whether a deprecated protocol is still negotiable.
- Negotiated cipher suite and key size per protocol; weak markers
  (RC4, 3DES, NULL, EXPORT, MD5) and cipher suites under 128 bits.
- Certificate: subject/issuer CN, SAN set (DNS **and** IP), validity window,
  days until expiry, public-key type and size, signature algorithm, self-issue,
  SHA-256 fingerprint, and trust status.
- HSTS presence and `max-age` (read through the governed MCP `http_headers`
  tool, never with a private HTTP client).

An untrusted chain is a **finding**, not a reason to abort. Because Python's
`getpeercert()` returns an empty mapping on unverified sessions, the DER blob is
parsed by `gateway/x509_lite.py`, which adds no dependency.

### Determinism

Every finding produced here is derived from a re-runnable handshake, so it is
marked `dual_verified` and normally reaches `confirmed` through the evidence
gate. The one intentional exception is `tls:certificate-metadata-unavailable`,
which is flagged `requires_human_judgment` because "could not parse" is an
observation about the collector, not about the target.

### External adapters (testssl.sh / sslyze / sslscan)

`config/capabilities.yaml` declares them with an argv allow-list and a value
regex. They are **approval-gated** and their record explicitly reports
`external_adapters: "not_invoked"` unless an approved adapter run is executed.
A template that cannot be satisfied by an enabled policy never runs: the code
refuses rather than degrading silently.

---

## 5. Mid-engagement expansion

An operator may request four kinds of widening. **None is applied on submission.**

| Kind | Effect when approved | Hard limit |
|---|---|---|
| `targets` | Adds allowlist entries and new pending mission intents | 8 per request, mode host ceiling |
| `budget` | Raises `max_actions`/`max_seconds` and shifts the deadline by the same delta | +32 actions, +900 s, totals 128/3600 |
| `quota` | Raises the **current period's** quota ceilings for the requester | +200 calls, +200000 tokens |
| `privilege` | Records an authorisation reference only | Fixed enum of four classes |

Guards, in order:

1. Justification of at least 12 characters.
2. The engagement must declare `expansion_clauses` in `allowlist.yaml`.
3. The request must cite one of those clauses verbatim.
4. A per-mission cap on pending requests (default 5).
5. Targets pass `validate_allowlist_entry_syntax` (metadata denied, CIDR broader
   than /16 denied) and must **not** already be in scope.
6. `max_actions` still has to fit the mode ceiling.
7. The decision requires `approver`/`admin` **and** a different operator id —
   the existing `approval_queue` row supplies the second check at SQL level.

Applying an approved request writes a second audit entry containing the exact
before/after values, so the ledger shows *when* a limit moved and *who* moved it.

> A budget increase is not free time: a paused mission does not gain slack, and a
> terminal mission cannot be revived. Terminal states are refused outright.

---

## 6. The seven-question evidence gate

| Question | Blocking | Fails when |
|---|---|---|
| `reproducible_evidence` | yes | no hashed artifact, or empty evidence text |
| `in_scope` | yes | no engagement bound, or asset outside scope at check time |
| `security_impact` | yes | style/cosmetic key, or unknown severity |
| `not_by_design` | yes | analyst memory or context marks it accepted |
| `independent_validation` | yes | provenance is model-only (`llm`, `synthesis`, …) |
| `adversarial_review` | yes | confidence below the floor, or a refutation exists |
| `actionable_remediation` | no | no remediation text attached |

Verdicts:

- `confirmed` — all seven pass. The only status that may be reported as verified.
- `candidate` — every **validity** question passed but remediation is missing.
- `rejected` — any blocking question failed. Not reportable as a finding.

If the gate is disabled by policy, the best possible verdict is `candidate`:
the platform never auto-confirms without its own gate.

---

## 7. Agent roles

`gateway/agents_registry.py` defines 21 roles across recon, transport, web
hunters, discovery, validation, correlation, governance, bug bounty, reporting
and binary phases. Each role declares:

- the capabilities it needs (intersected with the active mode),
- the governed primitives it may *plan* against,
- its objective, and
- its own **refutation** condition (how it can be wrong).

Every role reports `can_execute: false`, `can_approve: false`,
`can_widen_scope: false`. `/api/v1/agents/plan` also returns
`unavailable_roles` with the exact capabilities a mode is missing, so a gap is
visible rather than silently ignored.

---

## 8. Binary layer: read-only by construction

`gateway/binary_triage.py` parses ELF headers, program headers, the dynamic
section and symbol tables to report NX, PIE, RELRO (none/partial/full), stack
canary, RPATH/RUNPATH, interpreter and writable+executable segments.

Deliberate omissions:

- No `pwntools` import, vendor copy or subprocess invocation.
- No ROP/shellcode/format-string generation.
- No debugger attachment, no remote process interaction.
- Reads are confined to `REDGATE_ARTIFACT_DIR`; `..`, absolute paths and
  symlink escapes are refused.

Every triage response states `"exploit_generation": "not_supported"`.

---

## 9. Reference projects and provenance

2.2 was designed after reviewing three public repositories by the same author.
**No source code, assets, agent markdown, hooks or dependencies were copied.**

| Reference | What informed 2.2 | What is *not* included |
|---|---|---|
| `alireza-bokharaei/hexstrike-ai` | Breadth of tool categories and the idea of a decision layer selecting tools | The 150+ tool server itself; the active catalogue remains Redstrike's curated, allow-listed set. Registry size is reported at runtime, not claimed. |
| `alireza-bokharaei/pentest-agents` | Specialist-role decomposition and an anti-Goodhart validation gate | Its 48 agents, 26 commands, hooks, CLI tools and MCP servers. Roles here are declarative and advisory. |
| `alireza-bokharaei/pwntools` | The idea of a binary-focused workflow | The library, exploit automation and any remote interaction. |

Neither `hexstrike-ai` nor `pentest-agents` declared a licence file at review
time, which is an additional reason their code is neither vendored nor
redistributed here.

---

## 10. What 2.2 still refuses — and how 2.3 changed it

> **Superseded in part by 2.3.** This section records the 2.2 boundary as it was
> shipped. 2.3 deliberately widens several of these items under the control model
> in [OFFENSIVE_SURFACE.md](OFFENSIVE_SURFACE.md). What changed and what did not:

| 2.2 refusal | 2.3 status |
|---|---|
| No password attacks or hash cracking | **Changed.** `hydra`, `john` and 6 more are catalogued; `hydra` is two-person, `john` needs operator consent. |
| No destructive exploitation | **Held.** Destructive PoCs are refused by pattern in every posture; `--os-shell` and file-write flags stay refused. |
| No unbounded or mass scanning | **Changed, with a budget.** Mass scanning is possible only under a two-person, expiring `scan_authorizations` row that depletes. |
| No exploit generation (binary layer reported facts only) | **Changed under control.** `pwntools` may assemble/disassemble/ROP-search/run a pinned script in an isolated child; no payload is built against a host. Reported `unavailable` when pwntools is absent. |
| No model-authorised confirmation | **Held.** A model cannot pass the gate, approve a request, raise a budget or widen scope; `verified` requires a human reproduction. |

What 2.2 stated and 2.3 keeps unchanged: the `destructive_confirmation`
privilege class still only records an authorisation reference, and a model still
cannot authorise anything.

---

## 11. Operational notes and limitations

- File handles: a TLS audit performs up to six short handshakes per target and
  is bounded by `timeout_sec` (default 10 s, hard cap 30 s).
- Certificate parsing is deliberately minimal: it reads the fields above and
  refuses anything it cannot parse rather than guessing. Revocation (OCSP/CRL)
  is **not** checked.
- Expansion of `targets` creates new *pending* intents; a running mission will
  not pick them up mid-flight unless it is resumed after the plan checkpoint.
- The `/api/v1/capabilities/summary` endpoint exposes only aggregate counts, not
  raw evidence, and is engagement-scoped.
- All 2.1 behaviour is preserved when `mode_id` is omitted, which is what the
  existing test-suite continues to assert.
- Composition refuses fewer than two distinct parts, more than three, and any id
  that is not a declared mode. A shorthand alias is accepted, but the stored
  `mode_id` is always the canonical `a+b` spelling.
- The decision engine only reads what the caller supplies plus stored assets and
  audit history. It never probes on its own, and an empty observation set is a
  legitimate answer (`no_signal` → `nmap`), not an error.
