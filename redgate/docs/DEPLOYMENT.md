# Deployment, Upgrade and Operations — 2.3.1

## 1. Prerequisites and trust boundary

Use Linux with Docker Engine, Compose v2.20+ and BuildKit. Build/pull access to image registries, Debian packages, PyPI and npm is needed initially. No model files are bundled. Approve/pin upstream image digests in your deployment process; the checked-in base tags are not immutable.

The default stack runs **one** gateway, MCP and runner. Only gateway port 8000 is published, on `127.0.0.1`. `control_net` is internal; `target_egress_net` and `llm_egress_net` provide routing, **not destination filtering**. Before live work, enforce and test default-deny IPv4/IPv6 egress outside the containers for both MCP and runner, permitting only signed targets and explicitly required control/inference connections. Use a stronger per-job isolation boundary for hostile scripts. Do not use host networking, privileged containers, a Docker socket mount or multiple gateway workers.

Docker is not available in the implementation sandbox. Subsequent [GitHub CI](https://github.com/alireza-bokharaei/Redstrike/actions/runs/44288999257) passed full/lite builds, startup/readiness and capability checks, and built the evidence-only target. This controlled run does not establish intended-host resource enforcement or hostile-code containment. Perform staged adapter, native-collector, scope/egress-denial and restore checks on your deployment before production; see the [verification record](VERIFICATION_2.1.0.md).

## 2. First deployment

Run from `redgate/`:

```bash
./scripts/bootstrap_env.sh
./scripts/redgate.sh doctor
./scripts/redgate.sh up --full
./scripts/redgate.sh status
```

Bootstrap prints distinct operator tokens **once**; store/distribute them privately. `.env` contains their SHA-256 hashes and an internal-service token, mode 0600. It is read by Compose, never sourced as shell. `--force` rotates **all** operator/service tokens and rewrites deployment defaults; do not use it as a routine upgrade step.

The gateway user is UID/GID 10000; runner 10001; MCP 10002. Bootstrap creates `secrets/` 0750 and `llm_api_key` 0640 with a restricted host group (`REDGATE_SECRETS_GID`, default your current group). Compose adds that supplementary group only to gateway. Ensure the chosen group has no unintended members. Bind-mounted config/skills must be readable by their service users; database volume ownership must allow UID 10000 to write. Don't solve permission problems by making secrets world-readable.

Open `http://127.0.0.1:8000`; use **Token** to authenticate. Compose forces `REDGATE_DEMO_MODE=false`, even if `.env` says otherwise. Deploy TLS and access control through a reverse proxy before explicitly setting `REDGATE_BIND_ADDR=0.0.0.0` for remote access. Browser code uses relative URLs; never direct a remote user's browser to internal localhost services.

### Image flavors

| Target | Gateway | Runner | Use |
|---|---|---|---|
| `full` (default) | Python/Bash/Go/JS validators | All four script runtimes + native evidence | Existing polyglot skills |
| `lite` | Python/Bash validators | Python/Bash + native evidence | Workspace without Go/JS adapters |
| runner `evidence` build target | Not a complete stack flavor | Native HTTP evidence; `/execute` returns 403 | Custom deployment minimizing script execution |

```bash
./scripts/redgate.sh up --lite
# Standalone build target, not REDGATE_IMAGE_FLAVOR=evidence:
docker build --target evidence -f sandbox_runner/Dockerfile -t redgate/runner:2.3.1-evidence .
```

`lite` does not disable policy checks to make unsupported languages pass. Go dual-verification skills may have failed/unavailable adapter steps. Check `/api/v1/health` validator booleans and `sandbox_runner.languages`; readiness alone does not establish complete skill/tool support. First-use Go compilation has finite time/memory and may fail closed on a cold/restricted host. Plan capacity based on measurements, not an assumed speedup.

## 3. Scope, policy and mission operation

1. Replace samples in `config/allowlist.yaml` with authorized engagement IDs, UTC RoE dates and exact IP/CIDR/domain rules. Assign matching engagement IDs to identities in `config/operators.yaml`.
1a. **Decide the 2.3 posture per engagement.** `config/policies.yaml` declares three postures; the default is `posture:permissive_in_scope` (permissive inside the signed scope, operator acknowledgement, two-person approval reserved for four high-impact actions). Bind a different posture per engagement with `POST /api/v1/offensive/posture` (approver/admin only) or accept the default. Postures narrow; none of them widens the allowlist, the RoE window, DNS pinning or the cloud-metadata block.
1b. **Review the tool flag policy.** Each `tools:` row carries `allowed_flags`/`refused_flags`. `BASELINE_REFUSED_FLAGS` in `mcp_server/catalog.py` is a code-level floor that config cannot lift (e.g. `sqlmap --os-shell`). Moving a flag between allowed and refused is a deliberate review, not a tuning knob. Only the binaries actually installed in your image can run; `GET /api/v1/offensive/tools` reports the installed subset.
1c. **Mount the artifact root for binary tooling.** `readelf`, `objdump`, `strings` and `nm` take an *artifact name* inside `REDGATE_ARTIFACT_DIR` (gateway default `data/artifacts`; the mcp-server service must see the same directory). Without it those tools refuse rather than resolving against the process cwd, and a path separator in the target is rejected before execution.
1d. **Optional layers are opt-in by installation.** Install `pwntools` in the gateway/mcp image to enable the binary layer; without it the layer reports `status: unavailable` and journals that fact. Export `HACKERONE_API_USERNAME`/`HACKERONE_API_TOKEN` (or the Bugcrowd/Intigriti/YesWeHack equivalents) only if you want scope sync; otherwise hand-entered scopes stay `source: manual`.
2. Review `tool_policy.yaml`/`script_policy.yaml`. Mission HTTP ports must be in `http_headers.allowed_params.allowed_ports`; approval-gated tools are not made autonomous.
3. Keep YAML baselines synchronized with approved runtime changes: startup seeds engagements, tool/script policies and built-in Skills. A restart can overwrite corresponding API edits. Removing a target from YAML is **not a deletion API**; explicitly deactivate obsolete records and verify effective scope.
4. Create a mission in the console, inspect its finite budget and endpoint, then **Start** explicitly. Pause drains the current intent; cancel gates later actions. A gateway restart pauses interrupted work and requires explicit resume. Pausing does not reset the deadline or return spent reservations.
5. Read step/intent warnings even if a mission says `completed`. Retests append observations, never auto-close findings. Reports and exports require analyst review and sensitive-data handling.

The loopback lab applies to **direct host development**. Within Compose, the runner's `127.0.0.1` is the runner, not the gateway/host. For a container smoke target use an explicitly authorized, disposable service and matching scope/port configuration; do not broaden a production scope to work around container networking.

## 4. Local inference and secret rotation

Default `mock` mode needs no external model service.

```bash
# No model download; configures .env for container networking:
./scripts/setup_local_llm.sh --compose ollama
# Explicit large download + model profile build:
./scripts/setup_local_llm.sh --compose --pull ollama Qwen/Qwen2.5-Coder-14B-Instruct-GGUF Q4_K_M
# Host-run gateway/runtime:
./scripts/setup_local_llm.sh --local ollama
```

Bundled Ollama is addressed **from gateway** as `http://ollama:11434/v1`, not `127.0.0.1`. Its model cache is a persistent volume. The helper's `--pull` path needs a working Docker/Ollama service and external model download access; it was not exercised against a real model here.

LM Studio on a host needs an address reachable from the gateway container, an explicitly bound inference server, host routing and firewall controls. For Linux `host.docker.internal` requires an operator-managed Compose override such as:

```yaml
services:
  gateway:
    extra_hosts:
      - "host.docker.internal:host-gateway"
```

Then configure, for example, `setup_local_llm.sh --compose --base-url http://host.docker.internal:1234/v1 lm_studio`. Do not expose the inference server unrestrictedly. Confirm its actual loaded model ID in `/v1/models`; a Hugging Face repository name is not necessarily that ID.

**Saved SQLite runtime configuration takes precedence over initial environment defaults.** The setup helper only edits `.env`; for an existing database update **Local AI → Runtime** using an assigned admin, or `PUT /api/v1/models/runtime`. Merely recreating gateway is not a reliable way to change saved model settings. A remote/cloud/proxied endpoint is not offline or automatically private.

```bash
./scripts/rotate_llm_key.sh
```

Rotation prompts without echo, writes a restricted temporary file, then atomically replaces `secrets/llm_api_key`. The **directory** is mounted, so subsequent requests see the new inode. The configured key file takes precedence over the environment fallback when it exists. No restart is required for new requests; already-dispatched requests may still use the old key. Revoke the old provider credential separately after checking service health. Do not print tokens in logs or command arguments.

## 5. Upgrade from the existing Redstrike v2 schema

1. Stop accepting new mission work and pause/cancel ongoing activity. Record the current deployment artifacts/config and verify the existing audit chain.
2. Make a **consistent backup** and protect it off-host:

   ```bash
   ./scripts/backup_db.sh backups/pre-2.1.sqlite.gz
   # Direct local database instead of Compose:
   ./scripts/backup_db.sh --local data/redgate.db backups/pre-2.1-local.sqlite.gz
   ```

   The helper uses SQLite's backup API (WAL-aware), checks `quick_check`, writes gzip/0600 and refuses overwrites. Do **not** copy a live `.db` alone or discard its WAL. Retain config, skills and secrets separately under appropriate access control.
3. Stop/recreate the old single gateway with the new image/source and matching configuration. Never use `docker compose down --volumes` during an upgrade.
4. First startup applies the additive migrations under a transaction: `002_workspace.sql`, `003_capability_modes.sql`, `004_offensive_surface.sql` (policies, postures, consent, exploitation evidence, chains, bounty, pwntools jobs, scan authorisations) and `005_agent_brain.sql` (hunt loops, append-only brain). `schema_migrations` records each filename/digest; subsequent boots verify them and do not reapply. Existing runs, findings and audit records are preserved; no 2.1/2.2 table is altered. No automatic old-run inventory backfill or ARTEX database import occurs.
4a. After upgrade, the 2.3 control model is present but **inactive for high-impact work** until an approver grants approver-level consent for the relevant policy. That is intentional: an upgraded deployment must not inherit standing permission for exploitation. Verify with `GET /api/v1/offensive/policy` and `GET /api/v1/offensive/brief`.

5. Check `/healthz` (cheap liveness), `/readyz` (MCP/runner readiness), `/api/v1/health` (tool availability), then authenticated `/api/v1/audit/verify`. Verify preserved records, a disposable local mission/evidence/retest, cross-engagement denial, external egress denial and a backup/restore rehearsal before live work.

Do not edit an already-applied migration. Digest drift deliberately prevents startup. Diagnose deployment/source mismatch; do not delete the ledger merely to bypass it.

### Rollback

There is no destructive down migration. Stop **all** writers/services; preserve a consistent copy of the post-upgrade data for investigation; restore the checked pre-upgrade SQLite backup into the stopped data volume using your tested restore process. Ensure UID/GID 10000 ownership and that no stale `-wal`/`-shm` files from a different database remain. Start the previous approved images with their matching config/secrets. Verify SQLite integrity, original records and the audit chain before reopening access. Restore the backup only after confirming which new evidence would be lost; restoring a backup intentionally discards subsequent writes.

## 6. Monitoring and measurement

```bash
./scripts/redgate.sh logs gateway
./scripts/redgate.sh status
docker compose images
docker stats --no-stream
```

Monitor restarts, memory/pids, disk/WAL growth, task warnings, audit integrity and backup age. Audit verification scans the ledger and is more expensive than `/healthz`. Retention/export encryption and independent audit anchoring are operator-managed.

For a fair `full` vs `lite` comparison record image IDs/digests, architecture, cold/warm cache state, build times, image sizes, readiness latency and idle/loaded RSS/CPU on the **same** host and workload. No such benchmark is claimed for this release. The optional `postgres` profile only provisions a database container; Redstrike still persists to SQLite and has no PostgreSQL migration/driver support.
