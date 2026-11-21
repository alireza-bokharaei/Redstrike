# Limitations and Operational Boundaries — 2.3.1

## 2.3 offensive surface limits

- **The default posture is permissive inside the declared scope; it is not permission to go outside it.** `posture:permissive_in_scope` removes repeated *asking* for ordinary active testing. It does not add an allowlist entry, extend the RoE window, disable DNS pinning, unblock cloud-metadata addresses, or reach past the argv refusal floor. Those are scope and capability controls and they apply to every posture, including `posture:ctf_aggressive`.
- **Two people are required for four things, not everything:** a state-changing PoC (`exploitation:proof_of_concept`), handling credential material (`credential:post_exploitation`), scanning outside the mission budget (`mass_scan:expanded_budget`), and online authentication attempts (`tool:hydra`). If an operator expects every action to be double-signed, the `posture:strict_readonly` posture exists for that; it is a narrowing choice, not the default.
- **Consent is not approval.** An operator's acknowledgement of a declaration lets an ordinary action proceed. A high-impact action still queues its own request and needs a second person for *that specific request*.
- **The tool catalogue is 144 entries; the image ships four of the binaries.** `GET /api/v1/offensive/tools` reports `installed_on_this_image` separately, and a run against a missing binary returns `status: unavailable` with exit code 127 and the validated argv. It never fabricates output, and a large catalogue is not a claim that every tool runs here.
- **`pwntools` is not installed in this deployment.** The binary layer, ROP/asm/disasm/cyclic/shellcode actions and `run_script` all return `status: unavailable` with the underlying `ModuleNotFoundError`, and the job is recorded as such. `binary_triage` reports ELF hardening facts computed by the Gateway itself; it is a separate layer and not a substitute. Installing `pwntools` in the image enables the layer without a code change.
- **Bug-bounty sync needs platform credentials and this deployment has none.** Scope entered by hand is stored as `source: manual` and is never relabelled `synced`. `sync_program` returns `status: unavailable` naming the missing environment variables. The duplicate checker is a *local* heuristic: without a platform query its honest outcome is `unverified`, never `no_match`, and a report whose duplicate check is `unverified` cannot be marked ready. Real HackerOne/Bugcrowd submission is not implemented.
- **A bounty scope is not client authorisation.** The platform's scope and the engagement allowlist must both permit an asset; `GET /bounty/programs/{id}/drift` shows the difference instead of merging them.
- **Discovery proposes, it does not widen.** Related assets found during enumeration become expansion requests that need a declared RoE clause, a different approver and a TTL. Malformed candidates are rejected with a reason rather than silently ignored.
- **Mass-scan budgets are per authorisation and expire.** An authorisation does not widen the allowlist; it raises a request-count ceiling that depletes. Rate limiting on the network path is still the deployment's responsibility.
- **Verification means reproduction, not truth.** A finding is `verified` when a *different* operator reproduces the exact recorded output. That proves reproducibility, not business impact, and it says nothing about compensating controls or asset criticality.
- **`--os-shell`, sqlmap file writes and similar flags stay refused in every posture.** This is a deliberate product decision: they convert a finding into a compromise event without adding evidence, and they are not needed to prove an injection. Two-person approval lifts a gate; it does not lift this floor.
- **Agents remain advisory.** 49 roles plan, hypothesise and apply the 7-Question Gate. They cannot execute a tool, approve a request, widen scope or confirm a finding. A roster count is not evidence of coverage.
- **The brain and the gate are only as good as the answers written into them.** An operator who answers the seven questions carelessly gets a deterministic gate applied to careless input. `unknown` blocks, but `yes` cannot be audited for sincerity.
- **HexStrike and pentest-agents were reimplemented, not vendored.** Neither upstream fork carries a licence this repository can inherit, so the tool-execution shape and the agent workflow were rebuilt behind a protocol boundary. No source was copied. See `docs/OFFENSIVE_SURFACE.md` §12 and `docs/ARTEX_SCOPE.md`.
- **New tables are additive.** Migration `004`/`005` create 12 new tables; no 2.1/2.2 table is altered, and old databases upgrade in place.

## Scope of this release

This is an independent addition of mission/graph/evidence/retest workflows (2.1) and operational modes, deep TLS analysis, governed expansion, an evidence gate and read-only ELF triage (2.2) to Redstrike. It is not a full ARTEX source merge, feature clone or compatibility layer; see [ARTEX_SCOPE.md](docs/ARTEX_SCOPE.md), [CAPABILITY_MODES.md](docs/CAPABILITY_MODES.md) and [OFFENSIVE_SURFACE.md](docs/OFFENSIVE_SURFACE.md). 2.3 adds a governed offensive surface: 144 catalogued tools, a PoC lifecycle with independent verification, attack chains, recursive discovery with budgeted mass scanning, a bug-bounty workflow, a pwntools layer (unavailable until installed) and 49 advisory agents with hunt loops and an append-only brain. Destructive payloads, weaponised exploit chains, credential harvesting, stealth/persistence, browser interception, unrestricted proxy/replay and autonomous offensive action are still not added.

## 2.2 capability layer limits

- A mode is a ceiling, not a permission. Every action still passes the engagement's signed RoE window, allowlist, DNS pinning and cloud-metadata guard. An admin toggle can disable a mode; no toggle can re-enable a permanently banned flag.
- Deep TLS analysis performs bounded handshakes against a pinned IP only. It does **not** check revocation (OCSP/CRL), does not measure application-protocol behaviour, and external adapters (testssl.sh, sslyze, sslscan) are approval-gated and reported as `not_invoked` unless explicitly run. Certificate facts come from a minimal in-tree DER parser; an unparseable certificate is reported as such rather than guessed.
- A deprecated-protocol or weak-cipher result depends on the Python/OpenSSL build used by the container. The report names the observed negotiation; it is not a claim about every client population.
- Expansion requests change nothing until a different approver decides them, must cite a declared RoE clause, and expire after the configured TTL. Target expansion re-checks allowlist syntax and the metadata/CIDR guards before review, so a permanently prohibited destination can never even be proposed.
- A budget expansion extends the deadline by the approved delta; it does not reset a paused mission's lost time, cannot revive a terminal mission, and cannot exceed the mode ceiling.
- The seven-question gate is deterministic over stored evidence. It can reject a true positive whose provenance is model-only, and it does not verify business impact, compensating controls or asset criticality.
- Agent roles are advisory text. They cannot execute tools, approve requests, widen scope or confirm findings; a role listing is not evidence of coverage.
- Binary triage parses ELF metadata inside the configured artifact directory only. It performs no disassembly, no execution, no exploitation and no remote interaction, and reports `exploit_generation: not_supported`.
- 2.2 numbers a wider boundary; it is not a measured performance or detection-capability improvement and makes no such claim.

## Authorization and traffic

- Application scope checks do not replace legal authorization, SOC deconfliction, external egress controls or careful engagement scheduling.
- DNS resolution, TLS, TCP checks and even HEAD requests are observable and can trigger alerts. Read-only HTTP can still have server-side effects on poorly designed targets. No stealth or zero-impact guarantee is made.
- HTTP evidence fails closed without a safe DNS pin, even if legacy strict-DNS mode has been relaxed. Metadata, link-local, multicast and unspecified destinations are not valid evidence targets. Explicitly allowlisted loopback is for private labs; inside Docker, `127.0.0.1` denotes the worker container, not the host gateway.
- Domain scope does not mean that an entire shared-hosting IP is authorized. Do not broaden egress scopes merely to make a tool run.

## Mission lifecycle and reliability

- A single gateway process owns the in-memory workers; SQLite stores their durable state. Do not run multiple Uvicorn workers, replicas or a shared network filesystem database. There is no distributed lease, external job broker or horizontally scaled scheduler.
- At most 8 target hosts, 64 actions and 1800 seconds per mission; at most two active missions globally and one per owner. A pause does not extend the absolute deadline. A terminal/budget-exhausted mission needs a new plan.
- Pause drains the current intent. Cancel gates later actions, not an already-sent network request. Shutdown can leave a remote collector finishing its bounded in-flight request.
- Completed/checkpointed runs are not silently replayed. After a hard crash, an action that performed I/O but did not persist its checkpoint may be retried on explicit resume. There is no exactly-once network execution guarantee. Reserved/failed attempts are not refunded.
- A mission can complete with failed/skipped checks or unavailable evidence; inspect intent warnings and step results. `completed` describes orchestration, not a clean bill of security.
- Plans snapshot a Skill; live target and tool permissions still apply. Gated follow-ups enter the existing approval workflow rather than executing autonomously.

## Graphs, coverage and exports

- Asset graph: up to 200 server-projected nodes. Exploration graph: up to 500 nodes. Console SVG: up to 120 nodes. Use paginated inventory APIs for larger datasets.
- The workspace displays the latest 30 missions and 20 evidence records. JSON mission export caps evidence at 100 and retest history at 100 per finding; inspect the export's limit/truncation metadata. It is not an unlimited archive of an engagement.
- Discovery is not a tested finding. Coverage counts recorded checks/evidence for known assets, not every path, port, vulnerability class or business workflow.
- No automatic importer/backfill of old recon runs or ARTEX databases is provided. Existing Redstrike records are preserved; workspace inventory is built by new activity.

## Evidence and retests

- Only anonymous HEAD/GET with verified HTTPS or explicit plaintext HTTP. No authenticated-session replay, custom headers, request body, query/fragment, redirect following, browser DOM/network capture, HAR import or raw packet store.
- Native collector limits: four concurrent captures; two requests/second per logical host/port; timeout up to 15 seconds; response headers up to 32 KiB; explicit body preview up to 8192 bytes. These are collector limits, not a universal rate limit covering every legacy MCP/adaptor action.
- Headers are allowlisted; Set-Cookie and arbitrary application headers are discarded. Bodies are omitted by default and only eligible text previews may be retained. Secret filtering is heuristic: custom secrets, URL path identifiers and PII can survive. `redacted: true` means filtering was applied, not guaranteed absence of sensitive data.
- SHA-256 validates the stored redacted representation, not raw-wire authenticity or the honesty of a compromised worker. SQLite is not encrypted by this application; backups/exports need independent protection.
- Automatic retests cover supported `missing:<security-header>` findings from the original completed HTTP endpoint only. They preserve scheme, port, path and method. Non-2xx responses and HSTS over plaintext are inconclusive. Header presence does not establish its effectiveness. Other findings require manual review. Original analyst verdicts are never auto-updated.

## Script isolation and deployment

- Static analysis cannot prove arbitrary scripts safe. Timeouts, prlimit, environment scrubbing, digest verification and process-group cleanup are defense in depth—not an OS sandbox, VM, filesystem jail or network namespace.
- The runner only renders proposed IPv4 firewall commands; it does not apply them or prove IPv6/default-deny enforcement. `REDGATE_ENFORCE_IPTABLES=true` is unsupported and refuses script execution rather than falsely claiming protection. Use an independently verified external firewall and stronger per-job containment for hostile code.
- Compose provides non-root/read-only service containers, not per-script isolation. Jobs within a runner share a UID and persistent tool caches; a hostile adapter could interfere with that state. Avoid multi-tenant hostile workloads. Native evidence invokes no user-supplied code.
- `lite` omits Go/Node adapters and their validators. `full` includes all four languages but first-use Go compilation under finite memory/time may fail closed until caches are warm. The evidence-only runner target refuses scripts regardless of installed base utilities.
- PostgreSQL's optional Compose profile is provisioning only: the application still uses SQLite. There is no supported PostgreSQL driver, automatic database conversion or multi-node deployment.
- No Docker daemon was available in the implementation sandbox. [GitHub CI](https://github.com/alireza-bokharaei/Redstrike/actions/runs/44288999257) subsequently passed full/lite build/startup/readiness/capability checks and built the evidence-only target. Intended-host resource enforcement, in-container script/collector behavior, image-size comparisons, performance benchmarks and real external inference still require separate validation. CI/local test timings are not production capacity or speedup measurements.

## Local models and human judgment

Offline inference requires previously downloaded model weights, correct model licenses and an actually local endpoint. Download/setup initially needs network access and storage. Local compute is not cost-free, quantization sizing is an estimate, and remote inference/proxies can send prompts off-host.

Model output, summaries, confidence and dual verification can be wrong or affected by prompt injection. They do not replace analyst assessment of authorization/business logic, IDOR/BOLA, compensating controls, asset criticality, privacy or impact. A model cannot enlarge scope, bypass policy or approve its own work.
