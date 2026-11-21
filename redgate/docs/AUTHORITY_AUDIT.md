# Authority audit — what the three referenced projects contain, and what this build added

The project brief references three repositories:

| Reference | Role in the brief |
|---|---|
| `alireza-bokharaei/pentest-agents` (fork of H-mmer/pentest-agents) | agent roster, hunting skills, coverage/brain/autopilot tooling |
| `alireza-bokharaei/hexstrike-ai` (fork of H-mmer/hexstrike-ai) | wide tool surface, decision engine, CVE intelligence, mobile/wireless/forensics |
| `alireza-bokharaei/pwntools` (fork, `dev`) | exploit-development framework behind the CTF surface |

**None of the three carries a licence.** They are therefore *referenced for
capability shape only*: no source file, prompt, wordlist, agent markdown or data
fixture is copied or vendored, and none is a runtime dependency. Everything below
is implemented natively, from the behaviour the brief describes. Where a module's
name echoes an upstream concept (intel engine, coverage record, response tracker),
that is a description of the job, not of the code.

## 1. Tool surface

| Category | Before 2.3.1 | After | Notes |
|---|---|---|---|
| dns | 14 | 14 | |
| network | 18 | 18 | |
| web | 41 | 41 | |
| injection | 5 | 5 | |
| tls | 5 | 5 | |
| cloud | 10 | 10 | |
| ad | 12 | 12 | |
| password | 7 | 7 | `hydra` stays two-person |
| osint | 12 | 12 | |
| binary | 13 | 13 | |
| web_search | 4 | 4 | |
| reporting | 3 | 3 | |
| **mobile** | — | **9** | `adb frida objection apktool jadx mobsf drozer aapt class-dump` |
| **wireless** | — | **14** | `airmon-ng airodump-ng aireplay-ng aircrack-ng wifite bettercap kismet reaver bully hostapd-wpe mdk4 wash eaphammer pixiewps` |
| **forensics** | — | **16** | `volatility volatility3 binwalk bulk_extractor foremost scalpel sleuthkit fls icat autopsy photorec testdisk dc3dd guymager regripper usn-journal-parser` |
| **total** | **144** | **183** | |

Every one of the 39 new entries is governed exactly like the rest of the catalogue:

* unknown flags are refused by `build_argv()`, not filtered;
* `BASELINE_REFUSED_FLAGS` seeds the refusal set for the families where misuse
  hurts third parties — `aireplay-ng --deauth/-0`, `mdk4` flood verbs,
  `eaphammer` hostile-portal/capture flags, `adb install/push/root/remount`,
  `frida --spawn/-U`;
* wireless tooling is marked `requires_root` and cannot run without it;
* forensics and offline mobile tooling take an **artifact** (absolute path under
  `REDGATE_ARTIFACT_DIR`), never a host: `takes_artifact()` now covers
  `category == "forensics"` and offline `mobile` entries;
* none of them is installed in the reference image, so `POST /tools/run` answers
  `status: unavailable` with `exit_code 127`. That is the honest result and it is
  never simulated.

## 2. Agent roster: 49 → 70

Twenty-one advisory roles were added for the hunting disciplines the referenced
roster covers and this build did not: `xss-hunter`, `sqli-hunter`, `idor-hunter`,
`ssrf-hunter`, `ssti-hunter`, `xxe-hunter`, `rce-hunter`, `auth-bypass-analyst`,
`cors-hunter` (the roster already had a CORS posture role; this one is scoped to
response reflection), `open-redirect-hunter`, `csrf-analyst`,
`race-condition-analyst`, `graphql-auditor`, `waf-profiler`, `mobile-app-analyst`,
`wireless-survey-analyst`, `forensics-examiner`, `coverage-auditor`,
`response-diff-analyst`, `intel-ranker`, `report-quality-reviewer`.

Each carries the two properties that make a role useful rather than decorative:
the **capabilities** it needs (so a mode can withhold it) and the **evidence that
would refute it** (so a hypothesis that cannot be falsified is visibly not a
finding). No role can execute, approve, expand scope or confirm.

## 3. Skills: 4 → 24

The skill registry is a *validated playbook* engine: 1-6 steps, each step limited
to `dns_lookup`, `tcp_port_probe`, `http_headers`, `tls_inspect`,
`sandbox_script`, with `nmap` forced into `recommend_approval`. A
"hunt-xss" playbook therefore cannot shell out to `dalfox` — and it does not
pretend to. What the 20 new playbooks encode is the workflow the referenced
skills describe:

* `xss_hunt`, `sqli_hunt`, `idor_hunt`, `ssrf_hunt`, `ssti_hunt`, `xxe_hunt`,
  `oauth_hunt`, `jwt_hunt`, `graphql_hunt` — one hunting discipline each;
* `sast_entry_mapping`, `sast_flow_trace` — static analysis as a route map;
* `triage_validation`, `coverage_review`, `response_diff_review`,
  `report_quality_review` — the review disciplines;
* `mobile_app_triage`, `wireless_survey`, `forensics_artifact_inventory` — the
  three new surfaces;
* `intel_ranking`, `transport_posture_sweep` — prioritisation and TLS-only work.

Each states its **refutation**: the observation that would make the hypothesis
false. That single field is what separates these from a checklist.

## 4. Intel engine (`gateway/intel_engine.py`)

| Capability | Behaviour |
|---|---|
| `rank_classes` | 17 vulnerability classes scored by **published fixed weights** over: base prior, matched tech/observation signals, program ROI, supporting/refuting brain entries, recorded outcomes. Every response carries `terms` (the contribution of each weight) and `reasons`. Deterministic. |
| `rank_surface` | Endpoints bucketed `P1/P2/P3/Kill` from declared surface traits, with the weight printed per trait. |
| `allocate_budget` | Splits a minutes/token budget proportionally to rank score; a class at zero gets nothing. |
| `exhaustion_gate` | "Exhausted" needs `attempts >= 3`, `evidence_items >= 2`, `variants_tried >= 2` and no open anomaly. A class cannot be closed by waiting. |
| `chain_plan` | Static **capability** graph (`db_read` → `auth_bypass` → …), not tool order, so the next hypothesis is an escalation rather than another scan. |
| `evidence_score` | Pre-submission checks (reproduction, request/response, impact, remediation, scope attestation, redaction, independent reproduction) with a `do_not_submit` / `submit_with_gaps` / `submit` decision. |
| `cvss_base` | CVSS **v3.1** base score, Appendix-A round-up. v2, v3.0 and v4.0 vectors are **refused**, not approximated. Verified against the reference calculator: `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` → 9.8, `…/S:C/C:L/I:L/A:N` → 7.2, `…/AC:H/PR:L/UI:R/C:L` → 2.6. |
| `OutcomeStore` | Append-only `intel_outcomes`; the **only** state the ranking learns from. |

Why the weights are visible: a score that cannot be explained cannot be argued
with. When a ranking puts `xss` first, the operator can see it was the matched
`forms`/`spa` signals plus an ROI of 0.9 plus one prior confirmation, and disagree
with the weight instead of the result.

## 5. Coverage ledger and response diff (`gateway/coverage.py`)

* `coverage_records` is keyed `(engagement, surface)` and upserts. A `covered`
  record **must** name at least one check performed; a `skipped` record **must**
  state why. Both rules are enforced in the service, not in a doc.
* `summary()` accepts the declared surface list and returns every surface with no
  record under `uncovered`. Silence is never coverage, and the percentage is
  computed against `expected ∪ recorded`, not against what was convenient.
* `response_fingerprints` stores a *shape*, not the body: digits collapse to `N`,
  whitespace collapses, volatile headers (`Date`, `Set-Cookie`, `ETag`, `CF-Ray`,
  …) are dropped. `diff()` compares the two most recent observations and names the
  changed fields and headers, plus who has to re-verify.

## 6. What was deliberately not taken

* **No autopilot loop.** The referenced tooling can drive a session unattended.
  Here every state-changing action still resolves posture, consent, scope and
  policy per call; the intel engine orders work, it does not perform it.
* **No coverage-by-scan.** Coverage is asserted by recorded checks, never inferred
  from "a scanner ran".
* **No CVE database vendoring.** `cve-search`/`nvd-lookup`/`searchsploit` remain
  catalogue entries that report `unavailable` when the local mirror is absent.
* **No exploit text generation.** The pwntools layer still runs a pinned script;
  nothing here writes a payload against a host.

## 7. Verification

`tests/test_intel_and_coverage.py` (see the count in
[VERIFICATION_2.3.md](VERIFICATION_2.3.md)) covers: the 39 new catalogue entries
and their refused flags, artifact-vs-host classification, the 21 roles'
refutation fields, all 24 skills validating, every intel function including the
CVSS refusals, the coverage rules (`covered` without a check is refused), and the
fingerprint diff. Live API checks are recorded in §5 of
[VERIFICATION_2.3.md](VERIFICATION_2.3.md).
