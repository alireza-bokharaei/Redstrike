# Offensive Surface — 2.3

2.3 implements the expanded architecture: a **wide tool surface** (183 catalogued
tools), **49 advisory agent roles**, a **persistent reasoning brain**, **recursive
discovery**, a **bug-bounty workflow**, an **exploitation lifecycle**, and a
**pwntools layer** — all still behind one Gateway, one audit ledger, and one
signed scope.

The control model is the part that matters most, so it comes first.

---

## 1. The control model

> Default posture is permissive within the declared engagement scope. Two-person
> approval is required **only** for high-impact actions.

That sentence is implemented literally, and it is enforced by data
(`config/policies.yaml`), not by prose.

### Postures

| Posture | Default? | Risk | Consent | Two-person |
|---|---|---|---|---|
| `posture:permissive_in_scope` | **yes** | medium | operator | no |
| `posture:strict_readonly` | opt-in narrowing | low | operator | for anything not read-only |
| `posture:ctf_aggressive` | opt-in | high | operator | no |

A posture decides **how much asking happens**, never **what is reachable**. The
engagement's allowlist, signed RoE window, DNS pinning, cloud-metadata denial and
argv refusal floor apply to every posture, including `ctf_aggressive`. This is
asserted in `tests/test_offensive_surface.py::test_posture_never_widens_the_allowlist`
and `::test_ctf_posture_still_refuses_destructive_flags`.

### The only actions that need two people

```yaml
exploitation:proof_of_concept   # state-changing exploitation
credential:post_exploitation    # credential material
mass_scan:expanded_budget       # scanning outside the mission budget
tool:hydra                      # online auth attempts against real accounts
```

Everything else — nmap, nuclei, ffuf, gobuster, TLS audits, content discovery,
rewrites of your own posture by an approver — runs on the operator's single
acknowledgement. That is the difference between a governance platform and a
permission maze.

`HIGH_IMPACT_POLICIES` in `gateway/offensive_policy.py` is the category floor the
API reports; `tool:hydra` is a tool row that raises itself on top of it.

### Consent is bound to text, not to a click

A consent record stores the SHA-256 of the **exact declaration** the operator
accepted. Editing a policy's declaration therefore invalidates old consent, and
a consent granted for one policy does not silently satisfy a stricter one. The
join rule is in `OffensivePolicyEngine.has_consent`.

---

## 2. What a session must state (Session Start Protocol)

`GET /api/v1/offensive/brief?engagement_id=…` returns the five required items,
read from the ledger rather than from memory:

1. **Mission** — id, type (mode), status, remaining action budget and deadline.
2. **Scope** — engagement, validity window, allowlist size and sample targets,
   pending expansion requests.
3. **RoE** — active posture, who must consent, whether consent is met, which
   actions need two people, remaining budget.
4. **SSL/TLS status** — mandatory (`true` always), completed, last audit id and
   risk.
5. **Capability layers + restrictions** — tool execution (with the number of
   actually installed binaries), agents, pwntools availability, and the standing
   restrictions.

A brief is a statement of fact, not a plan: if TLS has not been audited it says
`pending: true`, and if pwntools is not installed it says so.

### 2a. Modes, composition and the decision engine

Six modes are declared in `config/capabilities.yaml`: `vulnerability_discovery`,
`bug_bounty`, `pentest`, `ctf`, `assessment` and `ssl_tls_analysis`. Modes with a
transport surface (all but `ctf`) make `tls_deep_analysis` mandatory.

**Composition.** A mission may name more than one mode, either through a declared
shorthand (`"mode_id": "pentest_plus_tls"`) or explicitly
(`"mode_id": "pentest+ssl_tls_analysis"`). Composition widens the permitted
capability set and nothing else:

| Rule | Effect |
|---|---|
| capabilities | union of the parts (minus an explicit `remove`, which can never drop a mandatory capability) |
| mandatory | union — an obligation cannot be composed away |
| ceiling | the **minimum** of `max_hosts` / `max_actions` / `max_seconds` / `concurrent_missions` |
| expansion clauses | **intersection** — composition cannot manufacture a widening clause |
| size | at most 3 parts, each a declared mode; every part must also be on the admin allow-list |

`POST /api/v1/capabilities/compose` resolves a combination without declaring it.
A composed mission stores the resolved ceiling plus the composition audit under
`mode_ceiling.composition`, so the ledger shows which parts merged and which one
shrank the ceiling.

**Decision engine.** `POST /api/v1/decide/approach` maps observations (TLS, web
surface, leaked paths, input surface, injection hints, directory services, cloud
naming) onto a prioritised list of governed next steps. Each step names the
`tool:` policy row that governs it, anything already in the audit history is
reported as `skipped_as_already_run`, and the whole response is marked
`advisory_only: true` with `basis: "deterministic rules over supplied
observations; no model call"`. The endpoint never executes anything; the step
still has to pass scope, argv, consent and policy through `/offensive/tools/run`.

---

## 3. Tool execution — 183 tools, deny-by-default argv

`mcp_server/catalog.py` registers 183 tools in 15 categories:

| dns | network | web | injection | tls | cloud | ad | password | osint | binary | web_search | reporting | mobile | wireless | forensics |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 14 | 18 | 41 | 5 | 5 | 10 | 12 | 7 | 12 | 13 | 4 | 3 | 9 | 14 | 16 |

The last three families were added in 2.3.1 for the surfaces the brief names:
authorised **mobile** app assessment (`adb frida objection apktool jadx mobsf
drozer aapt class-dump`), **wireless** survey and WPS/EAP testing (`airmon-ng
airodump-ng aireplay-ng aircrack-ng wifite bettercap kismet reaver bully
hostapd-wpe mdk4 wash eaphammer pixiewps`) and **forensics** image/firmware work
(`volatility volatility3 binwalk bulk_extractor foremost scalpel sleuthkit fls
icat autopsy photorec testdisk dc3dd guymager regripper usn-journal-parser`).
They are ordinary governed entries, with three extra refusals seeded for the
families where misuse hurts bystanders: `aireplay-ng --deauth/-0`, `mdk4`'s
flood verbs, `eaphammer`'s hostile-portal/capture flags, `adb install/push/root`
and `frida --spawn/-U`. Wireless tools are marked `requires_root`; forensics and
offline mobile tools take an **artifact**, never a host.

Each tool's flag surface is a **policy row** (`config/policies.yaml`, `tools:`),
not a hardcoded list. `build_argv()` refuses anything not explicitly allowed, and
the always-refused floor lives in `BASELINE_REFUSED_FLAGS`:

| tool | always refused |
|---|---|
| `sqlmap` | `--os-shell --os-pwn --os-cmd --os-smbrelay --file-write --file-read --priv-esc` |
| `nmap` | `--script --script-args --datadir -iL -iR --interactive --resume -D -S --spoof-mac --data --data-string` |
| `nuclei` | `-interactsh-url -headless -fuzz` |
| `hping3` | `--flood --rand-source --spoof -a` |
| `masscan` | `--adapter-ip --adapter-mac --router-mac --source-ip` |

**`-T4` is not on that list.** Timing is a noise question, not a capability
question: `tool:nmap` allows `-T1/-T2`, and `tool:nmap_aggressive` adds
`-T3/-T4` for an engagement that accepted the extra noise. `--os-shell` stays
refused in every posture, because it converts a finding into a compromise event
without adding evidence.

### Two kinds of target

A **network tool** takes a scoped host: the allowlist is checked, the name is
pinned to a validated IP, and a refused host is reported as *out of scope*.

A **binary tool** (`readelf`, `objdump`, `strings`, `nm`, `checksec`, …) takes an
**artifact name inside `REDGATE_ARTIFACT_DIR`**. It is not a network target and is
never scope-checked: `takes_artifact()` draws the line, `build_argv()` refuses any
path separator, and the executor resolves the name against an explicit root
(`resolve()` then parent comparison — not a string prefix), returning exit 127 if
the file is absent. Reading "the hardening flags of 127.0.0.1" is a category
error, and the API refuses it as one rather than pretending a host is a file.

Execution order (`gateway/scan_runner.py`), each step able to refuse:

1. **Catalog membership** — an unknown tool is never resolved on `PATH`.
2. **Scope (network tools only)** — allowlist, RoE window, DNS pin, metadata
   guard. Reported as *out of scope*, not as *needs consent*.
3. **argv** — built **before** the consent question, so a refused flag is never
   misreported as a permission problem that consent could fix.
4. **Consent/posture** — if the row is high-impact, the call returns
   `pending_approval` with an approval id instead of executing.
5. **Binary resolution** — the resolved path must be the catalogued binary, so a
   planted `nmap` earlier in `PATH` cannot shadow it.
6. **Pinned execution** — the operator's target string is replaced with the
   scope-validated IP, so DNS rebinding cannot redirect an in-flight run.

### Honest availability

`GET /api/v1/offensive/tools` separates the catalogue from reality:

```json
{
  "count": 183,
  "installed_on_this_image": {"readelf": "/usr/bin/readelf", "objdump": "…"}
}
```

On the reference image four catalogued binaries are present (`readelf`,
`objdump`, `strings`, `nm`). A run against a missing binary returns
`status: "unavailable"` with the validated argv and exit code 127 — it never
fabricates output. A tool service that is down or rejects a call is reported the
same way (`status: "unavailable"`, bridge error quoted), not as a 500. That is
deliberate: a tool list is a claim about what the platform *can do*, and the
installed list is the claim about what it *does here*.

---

## 4. Evidence is king — the exploitation lifecycle

```
drafted ──(own two-person approval granted)──► validated
validated ──(gateway records the run)────────► executed
executed ──(second operator reproduces)───────► verified
         └─ mismatch ────────────────────────► unverified  (kept, never deleted)
```

Guarantees, each covered by a test:

- **The PoC body is immutable.** A database trigger aborts any update that
  changes `poc_sha256`.
- **An unapproved PoC cannot run.** The evidence row and the approval queue are
  both consulted; either one refusing is enough.
- **A finding cannot be self-verified.** Verification requires a different
  operator id, and the reproduced output's digest must match the recorded one.
- **A mismatch demotes.** The finding becomes `unverified` — it is recorded, not
  quietly dropped, and it can no longer be reported externally.
- **Destructive PoCs are refused at draft time**, with the matching pattern
  quoted back (`rm -rf /`, `dd` to a block device, `DROP TABLE`,
  pipe-to-shell). A finding needs the smallest demonstrative proof.
- **Only `verified` findings are externally claimable.** `confirmed_findings()`
  returns nothing less.

Attack chains can only reference verified findings and name their weakest link by
severity. A chain with an unverified step is refused by id.

---

## 5. Recursive discovery and secondary targets

When the RoE declares a related-asset clause, discovery goes further than the
literal allowlist — but never *past* it:

- an in-scope hit becomes a testable node;
- an out-of-scope hit becomes a **proposal**, which still needs an expansion
  request and a different approver;
- something that is neither (a malformed host string, a shell-metacharacter
  candidate) is rejected with a reason.

`propose: true` on `POST /explore/discover` queues the expansion request in the
same call, so "we found more" and "may we touch it" are one auditable step.

Secondary targets come only from **existing** asset rows, and an asset that is no
longer in scope is listed under `no_longer_in_scope` rather than silently dropped.

### Mass scanning has a real budget

"No unbounded scanning" is only meaningful if the budget is checkable. A
`scan_authorizations` row (approved by two people, expiring) carries
`max_hosts`/`max_requests`; `check_scan_budget()` refuses beyond the row and
depletes as requests are consumed. Without a live row, *any* expansion beyond the
mission default is refused with a reason naming the two-person policy.

---

## 6. Bug bounty — synced when it can be, manual when it cannot

| Step | Needs network/credentials | Behaviour without them |
|---|---|---|
| register program | no | scope recorded as `source: manual` |
| `sync_program` | yes | `status: unavailable`, names the missing env vars, **no** sync timestamp, scope stays `manual` |
| `check_duplicates` | yes (for a real answer) | local heuristics; outcome `unverified`, never `no_match` |
| `draft_report` | no | copies PoC/output digests, steps, impact, remediation |
| `mark_ready` | no | refuses while a finding or duplicate check is unresolved |

Two honesty rules are worth naming because they are easy to get wrong:

1. **A locally typed scope is never called "synced".** The `source` column
   distinguishes `manual` from `synced`, and a `synced` row cannot be hand-edited
   (trigger), so the provenance cannot be rewritten after the fact.
2. **"No duplicates found" is not a claim this deployment can make.** Without a
   platform query the strongest true statement is "no overlap with our own
   history", so the outcome is `unverified` and `mark_ready` blocks on it.

A bounty scope is permission from the **platform**; the allowlist is permission
from the **client**. `GET /bounty/programs/{id}/drift?engagement_id=…` shows both
directions instead of merging them, and the platform scope never widens the
engagement allowlist.

---

## 7. Agents, hunt loops, and the brain

**49 advisory roles** across 14 phases (recon, transport, web, discovery, ad,
network, password, validation, binary, ctf, bug_bounty, reporting, correlation,
governance). Roles plan; they cannot execute, approve, widen scope or confirm.
The count is asserted in the test suite so a future edit cannot quietly shrink
the roster.

**Hunt loops** make a role's work falsifiable. A loop opens with a *testable
hypothesis*, iterates a bounded number of times, and can end as:

- `advanced` — survived the gate;
- `blocked` — the gate refused;
- `killed` — with a required reason.

`killed` is a first-class outcome on purpose. A roster that only ever produces
findings is not testing anything.

**The 7-Question Gate** must be answered `yes` seven times before a hypothesis
can be promoted:

| # | Question | Blocks |
|---|---|---|
| 1 | Can a second person reproduce this from the stored PoC and steps alone? | promotion to a candidate |
| 2 | Is the affected asset inside the signed scope at the time of testing? | any external claim |
| 3 | What can an attacker actually do that they could not do before? | severity above informational |
| 4 | Is this behaviour intended, documented, or an accepted risk? | reporting as a vulnerability |
| 5 | Did someone other than the author confirm it independently? | the "Confirmed" label |
| 6 | What is the strongest argument that this is not a real finding? | promotion past candidate |
| 7 | What is the blast radius of proving it, and is that proportional? | execution of the PoC |

`unknown` blocks exactly like `no`. An unanswered question is a blocking
question — that is the difference between a gate and a form.

**The brain is append-only.** Triggers reject both `UPDATE` and `DELETE`; a
corrected belief is a new entry. A returning operator can read what was already
tried and killed, which is what stops the same dead end from being funded twice.
`GET /brain` returns `entries_by_kind`, `loops_by_status` and the most recent
lessons.

---

## 8. pwntools layer

Enabled by default for CTF and binary missions, executed in a child process with
a scrubbed environment, a private temporary working directory, no network, and
the script body pinned by SHA-256. Supported actions: `elf_analyze`, `checksec`,
`rop_search`, `asm`, `disasm`, `cyclic`, `shellcode`, `run_script`.

**This deployment does not have pwntools installed.** The layer therefore returns

```json
{
  "status": "unavailable",
  "detail": "pwntools is not installed in this runtime (ModuleNotFoundError: No module named 'pwn')…"
}
```

and records the job in `pwntools_jobs` with that status. Nothing is emulated:
there is no fake checksec and no synthesised ROP chain. The read-only ELF facts
the Gateway parses itself (`binary_triage.py`) are reported separately, and the
API says so, so a consumer can always tell which layer produced a fact.

To enable it, install `pwntools` in the image (`pip install pwntools`) — the
probe is `import pwn` inside the child interpreter, never in the Gateway process.

---

## 9. API surface

```
GET  /api/v1/offensive/policy            postures, high-impact rows, control model
GET  /api/v1/offensive/posture           active posture + consent status
POST /api/v1/offensive/posture           approver-only
POST /api/v1/offensive/consent           accept a declaration (hashed)
GET  /api/v1/offensive/consent
POST /api/v1/offensive/decide            "may I run this?" without running it
GET  /api/v1/offensive/tools             catalogue + installed subset
POST /api/v1/offensive/tools/run         governed execution
POST /api/v1/offensive/findings          draft a PoC
GET  /api/v1/offensive/findings
POST /api/v1/offensive/findings/{id}/execution
POST /api/v1/offensive/findings/{id}/verify
POST /api/v1/offensive/chains            propose from verified findings only
POST /api/v1/offensive/chains/validate
POST /api/v1/offensive/explore/discover
GET  /api/v1/offensive/explore/secondary
POST /api/v1/offensive/explore/mass-scan
GET  /api/v1/offensive/explore/budget
POST /api/v1/offensive/bounty/programs
POST /api/v1/offensive/bounty/programs/{id}/sync
GET  /api/v1/offensive/bounty/programs/{id}/drift
POST /api/v1/offensive/bounty/duplicates
POST /api/v1/offensive/bounty/reports
POST /api/v1/offensive/bounty/reports/{id}/ready
GET  /api/v1/offensive/pwntools/status
POST /api/v1/offensive/pwntools/run
GET  /api/v1/offensive/agents
POST /api/v1/offensive/loops
POST /api/v1/offensive/loops/{id}/iterate | /kill | /gate
GET  /api/v1/offensive/brain       POST /api/v1/offensive/brain
GET  /api/v1/offensive/brief             Session Start Protocol

POST /api/v1/intel/classes                rank vulnerability classes (weights visible)
POST /api/v1/intel/surface                bucket endpoints P1/P2/P3/Kill
POST /api/v1/intel/budget                 split minutes/tokens by rank score
POST /api/v1/intel/exhaustion             may this class be closed?
POST /api/v1/intel/chain                  next bug from proven capabilities
POST /api/v1/intel/evidence-score         pre-submission report gate
POST /api/v1/intel/cvss                   CVSS v3.1 base score (v4 refused)
POST /api/v1/intel/outcomes   GET ...      append-only hunt outcomes
POST /api/v1/coverage  GET  DELETE         coverage ledger (unrecorded = uncovered)
POST /api/v1/responses/observe             store a response fingerprint
GET  /api/v1/responses/diff   /history     what changed between observations

GET  /api/v1/capabilities                 modes, layers, composition, gate, TLS profile
POST /api/v1/capabilities/compose         resolve "a+b" without declaring it
POST /api/v1/capabilities/resolve         per-capability decision for a mode (or composed mode)
POST /api/v1/decide/approach              deterministic next steps (advisory only)
POST /api/v1/session/start                declare a session against a (composed) mode
```

Every refusal is written to `audit_log` before the HTTP error is returned, so an
attempted widening is visible even when it is denied. `/api/v1/audit/verify`
checks the hash chain independently.

---

## 9a. Intel engine, coverage ledger and response diffing

Three pieces that turn "we tested it" into something a reviewer can check. They
do not execute tools and cannot promote a finding; see
[AUTHORITY_AUDIT.md](AUTHORITY_AUDIT.md) for the full mapping and provenance.

**Ranking (`POST /api/v1/intel/{classes,surface,budget,chain,evidence-score,cvss}`)**

* `classes` scores 17 vulnerability classes from fixed, published weights over
  the caller's signals, program ROI, brain verdicts and recorded outcomes. Every
  response carries the per-term contribution, so a ranking can be argued with.
* `surface` buckets endpoints `P1/P2/P3/Kill` from declared traits.
* `budget` splits minutes/tokens proportionally to rank score; a class at zero
  receives nothing.
* `exhaustion` refuses to close a class without `attempts >= 3`,
  `evidence_items >= 2`, `variants_tried >= 2` and no open anomaly.
* `chain` walks a **capability** graph (`db_read → auth_bypass → …`), so the next
  hypothesis is an escalation rather than another scan.
* `evidence-score` is the pre-submission gate (reproduction, request/response,
  impact, remediation, scope attestation, redaction, independent reproduction)
  and returns named gaps plus `do_not_submit` / `submit_with_gaps` / `submit`.
* `cvss` computes a **v3.1** base score with the Appendix-A round-up and
  **refuses** v2, v3.0 and v4.0 vectors instead of approximating them.

The only adaptive input is the append-only `intel_outcomes` table
(`POST /api/v1/intel/outcomes`); a ranking is otherwise a pure function of the
request. Brain entries count only when the row carries both a class and a
`supported`/`refuted` verdict.

**Coverage (`POST/GET/DELETE /api/v1/coverage`)**

`coverage_records` is keyed `(engagement, surface)` and upserts. Two rules are
enforced in code: a `covered` record **must** name at least one check performed,
and a `skipped` record **must** state why. `summary()` takes the declared surface
list and returns every surface with no record as `uncovered`; the ratio is
computed against `expected ∪ recorded`, so silence is never coverage.

**Response diffing (`POST /api/v1/responses/observe`, `GET /responses/{diff,history}`)**

A fingerprint stores the *shape* of a response — digits collapsed, whitespace
collapsed, volatile headers (`Date`, `Set-Cookie`, `ETag`, `CF-Ray`, …) dropped —
plus the raw title hash. `diff` compares the two most recent observations and
names the changed fields and headers, ending with who has to re-verify.

---

## 10. Data model

Migration `004_offensive_surface.sql` and `005_agent_brain.sql` add:

| Table | Append-only | Purpose |
|---|---|---|
| `policies` | — | declarative rows, runtime-editable by admins (audited) |
| `engagement_postures` | — | one posture per engagement |
| `consent_records` | no DELETE | hashed acknowledgements |
| `exploitation_evidence` | PoC body immutable | PoC lifecycle + evidence |
| `attack_chains` | — | ordered verified findings |
| `bounty_programs` | synced scope immutable | platform binding |
| `bounty_duplicate_checks` | no UPDATE | duplicate-check history |
| `bounty_reports` | — | drafts |
| `pwntools_jobs` | — | layer execution records |
| `scan_authorizations` | — | mass-scan budgets |
| `hunt_loops` | — | hypotheses and outcomes |
| `brain_entries` | no UPDATE, no DELETE | reasoning trail |

---

## 11. Reproducing the verification

```bash
cd redgate
.venv/bin/python -m pytest tests/test_offensive_surface.py -q      # 71 tests
.venv/bin/python -m pytest tests/ -q \
  --ignore=tests/test_e2e.py --ignore=tests/test_agent_v2.py \
  --ignore=tests/test_collector.py                                  # 232 passed
.venv/bin/python -m ruff check .
```

The live checks in `docs/VERIFICATION_2.3.md` used a loopback Gateway with three
operators (`alice`, `sara` as operators, `kaveh` as admin) against the RFC 5737
engagement in `config/allowlist.yaml`; no external host was contacted.

---

## 12. What this release still does not do

- **Destructive exploitation.** `--os-shell`, file writes through sqlmap, and
  payloads with a blast radius wider than the finding stay refused in every
  posture. Two-person approval lifts the *gate*, not the *capability floor*.
- **Autonomous action.** Agents plan; the Gateway executes; approvals are human.
- **Unbounded scanning.** Budgets are checkable and deplete.
- **Credential theft.** `credential:post_exploitation` governs handling of
  material obtained elsewhere; nothing here harvests credentials.
- **A licence-clean HexStrike/pentest-agents merge.** Those forks carry no
  licence we can inherit, so this is a protocol-boundary reimplementation of the
  shape, not a copy. See `LIMITATIONS.md`.
