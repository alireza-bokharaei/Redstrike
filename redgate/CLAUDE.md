# CLAUDE.md — Redstrike v2.3 Project Instructions for Claude Code

This repository implements **Redstrike v2.3**, an internal, policy-controlled, auditable security testing and personalized reconnaissance platform powered by local LLMs (Ollama / LM Studio / Hugging Face GGUF), composable **Skills**, persistent operator **Memory**, **MCP tools**, 4-language static validation (**Python, Bash, Go, JavaScript**), an isolated **Go Sandbox Runner**, the 2.2 **capability layer** (operational modes, mandatory deep TLS analysis, RoE-bound expansion requests, the seven-question evidence gate, advisory agent roles and read-only ELF triage), and the 2.3 **offensive surface** (posture/consent policy, a 144-tool catalogue, a PoC lifecycle, attack chains, recursive discovery, a bug-bounty workflow, a pwntools layer and 49 advisory agents with hunt loops and an append-only brain). See `docs/CAPABILITY_MODES.md` and `docs/OFFENSIVE_SURFACE.md`.

## Non-Negotiable Safety & Architecture Rules

1. **Scope First**: Never add code or tools that contact targets outside `allowlist` or bypass `gateway/policy.py` (engagement RoE window + DNS rebinding + cloud metadata block).
2. **Offensive capability lives behind policy, not behind a missing feature.** Ordinary active testing (nmap, nuclei, fuzzing, content discovery, TLS audits) is allowed on an operator's posture acknowledgement inside the signed scope. Evasion/persistence/credential-harvesting logic is still not built. High-impact actions — state-changing PoCs, credential handling, mass scanning beyond budget, online auth attempts — require two people (`approval_queue`). See rules 13–20.
3. **Zero Hardcoded Secrets/Targets**: Externalize all settings in `config/*.yaml` and `skills/*.yaml`; load secrets strictly via environment variables or `secrets/llm_api_key`.
4. **Untrusted AI Code**: Every generated script must pass `gateway/validators/` AND SHA-256 verification in `sandbox_runner/runner.go` inside `/tmp/sandbox`.
5. **Immutable Audit Trail**: Every new tool, skill run, policy toggle, or analyst verdict must write to `db.write_audit_log(...)` (protected by SQLite abort triggers + SHA-256 hash chain).

### 2.2 Capability-Layer Rules (widened boundary, same invariants)

6. **A mode is a ceiling, never a permission.** Always resolve capabilities through `gateway/capabilities.py`; never read `config/capabilities.yaml` directly in a handler and never treat a capability name as authorisation.
7. **No widening without a second person.** Anything that adds targets, budget, quota or a privilege class must go through `gateway/expansion.py` + the `approval_queue` row, cite a declared RoE clause, and be applied only in the `_apply` path. Never mutate `allowlist`, `missions.max_actions` or `quota` outside it.
8. **No config may defeat code-level safety.** `PERMANENTLY_BANNED_*` flag sets, `UNCONDITIONALLY_BLOCKED_NETS`, DNS pinning and the SQL Two-Person `CHECK` are untouchable. If new policy needs one of them relaxed, that is a security review, not a config change.
9. **Confirmation requires evidence.** Only `gateway/evidence_gate.py` may mark a finding `confirmed`. Model output is never sufficient input for a blocking question. New findings must supply `evidence`, `remediation` and a deterministic provenance.
10. **TLS analysis must stay pinned.** Any new TLS code must dial a scope-validated IP, keep the original SNI, honour the `tls_audit.allowed_ports` profile and the `tls_inspect` tool policy, and store an immutable hashed record. No private HTTP client for HSTS.
11. **The binary layer is governed, not forbidden.** `gateway/binary_triage.py` stays read-only (in-tree ELF parsing, no execution). `gateway/pwntools_layer.py` may assemble, disassemble, search ROP gadgets and run a pinned script **only** inside its child process, with a scrubbed env, no network, a temporary cwd, the artifact root enforced, and a destructive-script refusal. It must never import `pwn` in the Gateway process. If pwntools is absent, report `status: unavailable` — never synthesise its output.
12. **Agent roles are text.** Anything in `gateway/agents_registry.py` must keep `can_execute`/`can_approve`/`can_widen_scope` false and must never be wired to a tool call.

## Key Extension Points (Tool & Skill Authoring)

- **Add a new Recon Skill**: Create `skills/<skill-id>.yaml`, validate via `gateway.skills.validate_skill_spec`, and add a test in `tests/test_agent_v2.py`. (Or run `/project:new-skill`.)
- **Add a new MCP Tool**:
  1. Register JSON Schema + parameter whitelist in `mcp_server/tools.py`.
  2. Implement bounded, timeout-isolated handler in `mcp_server/executor.py` (`shell=False` argv only).
  3. Add default policy entry in `config/tool_policy.yaml`.
  4. Add positive + negative parameter tests in `tests/test_policy_and_audit.py`. (Or run `/project:new-mcp-tool`.)
- **Tune Local Model & Quantization**: Edit `config/local_models.yaml` or `config/Modelfile.redgate`, or run `./scripts/setup_local_llm.sh`.

## Verification Commands (Always Run Before Committing)

```bash
shellcheck scripts/*.sh
(cd sandbox_runner && go test -v ./... && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o ../bin/sandbox-runner .)
PYTHONPATH=. pytest -v tests/
ruff check .
```

The 2.2 layer has its own suite (`tests/test_capability_modes.py`). It stands up a
throwaway loopback TLS server with a locally minted certificate and needs only the
`openssl` binary; tests that require it skip when it is absent.

- **Add a capability**: declare it in `config/capabilities.yaml` under the modes that
  may use it, then intersect it with a `tool_policy` row in `gateway/capabilities.py`.
  Add a positive and a negative test in `tests/test_capability_modes.py`.
- **Compose modes**: combinations are declared under `composition:` in the manifest and
  merged by `CapabilityRegistry.compose()`. The merge is one-directional — capabilities
  union, mandatory capabilities union, ceilings take the minimum, expansion clauses
  intersect. Never add a merge rule that can raise a ceiling or drop an obligation, and
  keep `tests/test_mode_composition.py` green.
- **Decision engine**: `decide_approach()` is a deterministic rule engine over supplied
  observations. It may propose, never execute, and every step must name the policy row
  that governs it. Do not introduce a model call there.
- **Intel engine**: every score must expose its terms and weights. The only adaptive
  input is `intel_outcomes`; do not add hidden state or a model call to a ranking, and
  keep `tests/test_intel_and_coverage.py` green.
- **Coverage**: a surface is covered only when a check is recorded for it. Never infer
  coverage from "a scanner ran", and keep the `covered`-needs-a-check rule in
  `gateway/coverage.py`.
- **New tool families** (mobile/wireless/forensics): seed `BASELINE_REFUSED_FLAGS` for
  anything that hurts bystanders, mark root-dependent tooling `requires_root`, and make
  artifact-consuming tools pass `takes_artifact()`. An uninstalled binary must answer
  `unavailable`; never fake output.
- **Add a gate question**: append it to the manifest, decide whether it is blocking in
  `gateway/evidence_gate.py`, and add a failure fixture. More than one non-blocking
  question weakens `candidate`/`rejected` semantics.
- **Add an agent role**: extend `AGENT_ROLES`, declare its capabilities and a concrete
  refutation condition. It must remain advisory.

### 2.3 Offensive-Surface Rules

13. **Posture is not permission.** `posture:permissive_in_scope` is the default and it
    removes repeated asking — it must never add an allowlist entry, extend the RoE
    window, disable DNS pinning or unblock metadata. Any new posture must be evaluated
    through `gateway/offensive_policy.py`, never branched on in a handler.
14. **Two people, four actions.** `exploitation:proof_of_concept`,
    `credential:post_exploitation`, `mass_scan:expanded_budget` and `tool:hydra` are the
    two-person set (`HIGH_IMPACT_POLICIES` plus the hydra row). Do not add a fifth
    without a documented reason, and do not make anything else two-person "for safety" —
    that is how the permissive default gets quietly destroyed.
15. **argv is built, never assembled.** Every external tool call goes through
    `mcp_server.catalog.build_argv`. It is deny-by-default: a flag is accepted only if
    the policy row allows it, and `BASELINE_REFUSED_FLAGS` always wins. Never pass an
    operator-supplied string into a flag or shell position.
16. **Consent is hashed, not clicked.** A consent record stores the SHA-256 of the exact
    declaration. Editing a declaration must invalidate old consent; a consent for one
    policy must not silently satisfy a stricter one.
17. **Nothing is "Confirmed" without reproduction.** Only `gateway/exploitation.py` may
    move a finding to `verified`, and only when a *different* operator reproduces the
    exact recorded output. A mismatch demotes to `unverified` and is kept.
18. **Destructive PoCs are refused.** `scan_for_destructive` runs on every PoC body and
    script. A finding needs the smallest demonstrative proof; widening the blast radius
    is not "more evidence".
19. **The brain is append-only.** `brain_entries` rejects `UPDATE` and `DELETE` by
    trigger. Supersede with a new entry; a killed loop keeps its reason.
20. **Degrade honestly.** A missing binary is `status: unavailable` with the validated
    argv; missing pwntools is `unavailable` with the import error; missing bounty
    credentials mean `source: manual` and a duplicate check of `unverified`. Never
    fabricate a tool result, a sync timestamp or a `no_match`.

### 2.3 Extension points

- **Add a catalogued tool**: append a `_e(...)` row in `mcp_server/catalog.py`, add its
  flag policy to `config/policies.yaml` with `allowed_flags`/`refused_flags`, and add a
  positive + a refusal test in `tests/test_offensive_surface.py`. If it needs a flag
  refused in every posture, add it to `BASELINE_REFUSED_FLAGS` deliberately.
- **Add a posture**: declare it under `postures:` in `config/policies.yaml` with a
  `consent_required` level and a declaration the operator can read. Postures narrow;
  they never widen.
- **Add a hunt-loop question**: append to `SEVEN_QUESTIONS`. More than seven needs a
  justification, and every question must be answerable from stored evidence — a
  question nobody can answer just blocks everything.
