# Live Verification — 2.3 offensive surface

Everything below was executed against a **loopback Gateway** with three operators
and the RFC 5737 engagement from `config/allowlist.yaml`. No external host was
contacted. `alice` and `sara` are operators; `kaveh` is the admin/approver.

Reproduce with `.arena/live_run.sh` (gitignored scratch launcher) and
`uvicorn gateway.main:app --host 0.0.0.0 --port 8123`.

## Session Start Protocol

| # | Call | Result |
|---|---|---|
| 1 | `GET /api/v1/health` | `agent_roles_count: 49`, `tool_catalog_size: 4` (installed), `pwntools_layer: false` |
| 2 | `GET /offensive/brief` | mission `unclassified`; scope active with 4 allowlist entries; RoE `posture:permissive_in_scope`, `consent_met: false`, two-person list of 3; TLS `mandatory: true, pending: true`; layers `tool_execution: available`, `agents: available`, `pwntools: unavailable` |

## Control model

| # | Call | Result |
|---|---|---|
| 3 | `POST /decide` (`tool:nmap`, no consent) | `allowed: false`, `missing_consents: ["operator"]` |
| 4 | `POST /consent` (posture declaration) | `level: operator` recorded |
| 5 | `POST /decide` (`tool:nmap`, after consent) | `allowed: true`, `two_person_required: false` — *"Permitted by posture within declared scope."* |
| 6 | `POST /decide` (`tool:nmap_aggressive`) | `allowed: true`, `two_person_required: false` |
| 7 | `POST /decide` (`exploitation:proof_of_concept`) | `allowed: false`, `two_person_required: true` (operator consent alone is insufficient) |
| 8 | `POST /explore/mass-scan` (64 hosts / 5000 requests) | `pending_approval`, `apr-…` |

## Refusals

| # | Attempt | Result |
|---|---|---|
| 9 | `sqlmap --os-shell` | **422** `'sqlmap --os-shell' is refused by policy (destructive, evasive, or file-system affecting).` |
| 10 | `nmap 203.0.113.99` | **422** `Target '203.0.113.99' is NOT in active allowlist` |
| 11 | `nmap 169.254.169.254` | **422** `address … is in blocked cloud metadata range` |
| 12 | `nmap 198.51.100.10 -sV` | `status: unavailable`, argv `["nmap","-sV","--","198.51.100.10"]`, exit 127, *"argv was validated; nothing was executed"* |

## Exploitation lifecycle

| # | Step | Result |
|---|---|---|
| 13 | kaveh grants `approver` consent for `exploitation:proof_of_concept` | recorded |
| 14 | alice drafts a PoC | `status: drafted`, `two_person_required: true`, `approval_id: apr-…` |
| 15 | alice self-approves | **403** `Only 'approver' or 'admin' roles may decide…` |
| 16 | execute before approval | **422** `still awaiting independent approval` |
| 17 | execute with `execute_immediately: true` | approval status became `failed` — the approval is consumed by execution, so the operator must record the run explicitly |
| 19 | fresh PoC, approval with `execute_immediately: false` | approval `approved`; execution recorded, `output_sha256` returned |
| 20 | sara reproduces with different output | **422** → finding demoted to `unverified`, summary `confirmed: 0` |
| 21 | sara reproduces exactly | `status: verified`, `verified_by: sara` |
| 23 | chain from two verified findings | `chn-…`, `weakest_link: "Missing HSTS… (low)"` |
| 24 | chain including an unverified step | **422** `Not verified: exp-…` |

## Discovery, bounty, loops

| # | Call | Result |
|---|---|---|
| 25 | `POST /explore/discover` with 5 candidates | 3 in scope, 1 out of scope → proposal, 1 rejected (`Refusing to treat 'bad host; rm -rf /' as a host`); expansion request `xpn-…` `pending` |
| 26 | register hackerone program | `source: manual`, `last_synced_at: null`, `sync_error` set |
| 27 | `POST …/sync` with no credentials | `status: unavailable`, names `HACKERONE_API_USERNAME`, `HACKERONE_API_TOKEN`; scope stays manual |
| 28 | duplicate check | `outcome: unverified`, confidence 0.0 |
| 29 | report draft from verified finding | `body_chars: 871`, contains PoC and output SHA-256 |
| 31 | scope drift | both assets `testable`, none blocked by the allowlist |
| 32 | `GET /agents` | 49 roles, 14 phases |
| 33–34 | open loop, iterate, gate with `unknown`/`no` | `passed: false`, blocking `q3_security_impact(unknown)`, `q5_independent_validation(no)` |
| 35 | kill loop with reason | `status: killed`, reason stored |
| 36 | `GET /brain` | `{hypothesis:1, lesson:1, note:1, question:7, verdict:1}`, `loops: {killed: 1}` |
| 37 | direct `UPDATE`/`DELETE` on `brain_entries` | both refused by trigger |
| 38 | `GET /pwntools/status?refresh=true` | `available: false`, `ModuleNotFoundError: No module named 'pwn'` |

## Posture change and the floor

| # | Call | Result |
|---|---|---|
| 39 | `POST /posture` → `posture:ctf_aggressive` (kaveh) | applied; `risk: high`, `two_person: false` |
| 40 | out-of-scope target **and** `--os-shell` under CTF posture | both still **422** — the aggressive posture never widens reach or capability |
| 41 | `GET /api/v1/audit/verify` | `valid: true`, 35 entries, head hash `51281d4f…`, both append-only triggers present |

## Binary tooling through the live bridge

With a real MCP service on `:8001` (`catalog_size: 183`, 15 groups) and a copy of
`/bin/true` at `.arena/artifacts/vuln.elf`:

| Call | Result |
|---|---|
| `readelf vuln.elf -h` | **200**, `status: completed`, exit 0, argv `['readelf','-h','vuln.elf']`, ELF header printed |
| `readelf nope.elf -h` | exit 127, `Artifact 'nope.elf' was not found in the configured root.` |
| `readelf ../../etc/passwd -h` | **422**, path refused |
| gateway with the MCP service stopped | `status: unavailable` (bridge error quoted), **not** a 500 stack trace |

## Modes, composition and the decision engine

Run against the same live ledger (`.arena/live.db`, `ENG-2026-001`):

| Step | Request | Result |
|---|---|---|
| 42 | `GET /api/v1/capabilities` | `manifest_version: 2.3`, six modes, `composition.max_modes: 3`, six named combinations |
| 43 | `POST /capabilities/compose` `{pentest, ssl_tls_analysis}` | `pentest+ssl_tls_analysis`; ceiling 8/64/1800; `mandatory_capabilities: ["tls_deep_analysis"]` |
| 44 | `POST /capabilities/compose` with four modes | **422** `At most 3 modes may be composed (asked for 4).` |
| 45 | `POST /capabilities/compose` with `nope` | **422** `Unknown operational mode 'nope'. Available: [...]` |
| 46 | `POST /missions` `mode_id: "pentest+ssl_tls_analysis"` | **201** `msn-465ba09e15c94018a3ef`; `mode_ceiling.composition.mode_ids == ["pentest","ssl_tls_analysis"]` |
| 47 | `POST /missions` `mode_id: "pentest_plus_tls"` (shorthand) | **201** `msn-d8732a68e26846bfb89d`; stored as `pentest+ssl_tls_analysis`, `composition.requested_as: "pentest_plus_tls"` |
| 48 | `POST /decide/approach` `{https, server_header, forms}` | signals `tls_or_https`, `input_surface`; first step `testssl.sh` (priority 10), then `tls_inspect`, `arjun`, `dalfox`; `advisory_only: true` |
| 49 | `POST /decide/approach` with no observations | `no_signal`; single step `nmap`; `next_call` names `/offensive/tools/run` |
| 50 | `POST /session/start` `mode_id: "assessment+ssl_tls_analysis"` | **200**; audit row `Session declared: mode=assessment+ssl_tls_analysis tls_complete=False` |
| 51 | `audit_log` after the above | `capability:decide_approach` rows present (`Advisory plan: testssl.sh, tls_inspect, arjun, dalfox`) |

The important negative result is step 44: a composition cannot exceed three
parts, the narrowest ceiling always wins, and no combination can drop
`tls_deep_analysis`.

## Widened catalogue, intel engine, coverage, diffing (2.3.1)

Run against the same live ledger (`ENG-2026-001`) with the MCP bridge on `:8001`.

| Step | Request | Result |
|---|---|---|
| 52 | `GET /offensive/tools` | `count 183`; `mobile: 9`, `wireless: 14`, `forensics: 16`; only four binaries installed |
| 53 | `POST /tools/run` `binwalk` → `firmware.bin` | `status: unavailable`, `exit 127`, *"Binary 'binwalk' is not installed… argv was validated; nothing was executed"* |
| 54 | `POST /tools/run` `adb` with `flags:["install"]` | **422** `'adb install' is refused by policy` — refused before consent, not after |
| 55 | `POST /tools/run` `readelf` → `vuln.elf` (real bridge) | `status: completed`, `exit 0` (artifact contract still holds with 39 new entries) |
| 56 | `POST /intel/classes` `{spa, forms, api_listing, jwt}` + ROI | `xss 1.33`, `idor 1.09`, `auth_bypass 0.82`; every class carries `terms` and `reasons` |
| 57 | `POST /intel/outcomes` `idor=confirmed` then re-rank | `idor` rises to `1.13` with *"1 confirmed outcome(s) on this engagement"* |
| 58 | `POST /intel/budget` 90 min / 90k tokens | 67/22 min split, `unallocated` reported honestly |
| 59 | `POST /intel/cvss` `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | `9.8 critical`; v4.0 vector → **422** `CVSS v4.0 is not scored here` |
| 60 | `POST /intel/exhaustion` `{attempts:1}` | `ok: false`, *"not exhausted: attempts 1/3, evidence_items 0/2…"* |
| 61 | `POST /intel/chain` `[db_read]` | `db_read → auth_bypass`, `terminal_impact: critical` |
| 62 | `POST /intel/evidence-score` (thin finding) | `submit_with_gaps`, `failed: [remediation_stated, independent_reproduction]` |
| 63 | `POST /coverage` without `checks` | **422** `A covered surface must name at least one check it performed.` |
| 64 | `POST /coverage` with `checks`, then `GET ?expected=a,b` | `counts.covered 1`, `uncovered: ["https://b.example"]`, `coverage_ratio 0.5` |
| 65 | two `POST /responses/observe`, then `GET /responses/diff` | `changed: true`, `strict-transport-security max-age=100 → null`, interpretation *"only headers changed — check security-header regressions"* |

Step 53 and step 55 are the pair that matters: the new families are not
simulated. An installed binary runs; an uninstalled one is `unavailable`.

**Bug found during this run.** `POST /intel/classes` returned a 500 because the
handler read a `payload_json` column from `brain_entries`, which has
(`kind`, `content`, `verdict`). Fixed by reading the real columns and accepting a
brain signal only when the row names a class **and** carries a
`supported`/`refuted` verdict; regression test
`test_a_refuted_brain_verdict_reaches_the_ranking_through_the_db`.
`CoverageLedger.record` had the same class of bug (`checks_json` re-read after
`get()` had already normalised it to `checks`) — fixed, covered by
`test_coverage_upserts_and_merges_checks`.

## Two bugs found and fixed during this run

1. `POST /bounty/reports` with a non-existent `check_id` returned **500** via an
   `IntegrityError`. Fixed by validating the foreign keys first: it now returns
   **422** with `Unknown duplicate check '…'`. Regression test:
   `test_report_rejects_unknown_foreign_keys_with_a_reason`.
2. `POST /tools/run` with `tool: readelf, target: 127.0.0.1` was scope-checking a
   *file name* against the allowlist, and the executor resolved artifacts against
   the MCP process cwd. Both fixed: `takes_artifact()` splits network tools from
   binary tooling, `build_argv()` refuses path separators, and the executor
   resolves names against an explicit `REDGATE_ARTIFACT_DIR` with a real
   containment check. A downstream bridge failure is now a `status: unavailable`
   result instead of an unhandled 500. Regression tests:
   `test_binary_tools_take_artifacts_not_hosts`,
   `test_artifact_root_resolution_is_contained`,
   `test_executor_without_artifact_root_refuses_rather_than_guessing`.

## Test totals

```
tests/test_offensive_surface.py                                71 passed
tests/test_mode_composition.py                                 23 passed
tests/test_intel_and_coverage.py                               39 passed
tests/ (minus e2e / agent_v2 / collector)                     293 passed, 3 environmental failures
ruff check .                                                   clean
```

The three remaining failures are `tests/test_validators.py`, which needs
`shellcheck`/`go`/`eslint` on the image; the five errors are the e2e suites that
need `bin/sandbox-runner` and free ports 28001/28002.
