#!/usr/bin/env bash
# Development/lab launcher, NOT an OS isolation boundary. Use Docker + an external
# egress policy for untrusted adapters. Demo login is explicit and off by default.
set -euo pipefail
umask 077
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
if [[ "${1:-}" == --help || "${1:-}" == -h ]]; then
  printf 'Usage: %s\nUse REDGATE_DEMO_MODE=true only in an explicit, private lab.\n' "$0"
  exit 0
fi
[[ $# -eq 0 ]] || { printf 'ERROR: Configure the launcher through REDGATE_* environment variables.\n' >&2; exit 2; }
PYTHON_BIN="${REDGATE_PYTHON:-python3}"
command -v "$PYTHON_BIN" >/dev/null 2>&1 || { printf 'ERROR: Python 3.11+ is required.\n' >&2; exit 1; }
"$PYTHON_BIN" -c 'import fastapi, uvicorn, httpx, yaml' || {
  printf 'ERROR: Activate your virtualenv and install requirements.lock.\n' >&2; exit 1;
}
export REDGATE_GATEWAY_PORT="${REDGATE_GATEWAY_PORT:-8000}"
export REDGATE_MCP_PORT="${REDGATE_MCP_PORT:-8001}"
export REDGATE_SANDBOX_PORT="${REDGATE_SANDBOX_PORT:-8002}"
export REDGATE_GATEWAY_HOST="${REDGATE_GATEWAY_HOST:-127.0.0.1}"
for port in "$REDGATE_GATEWAY_PORT" "$REDGATE_MCP_PORT" "$REDGATE_SANDBOX_PORT"; do
  [[ "$port" =~ ^[0-9]{2,5}$ && "$port" -ge 1024 && "$port" -le 65535 ]] || {
    printf 'ERROR: Use unprivileged TCP ports from 1024 to 65535.\n' >&2; exit 2;
  }
done
"$PYTHON_BIN" - "$REDGATE_GATEWAY_PORT" "$REDGATE_MCP_PORT" "$REDGATE_SANDBOX_PORT" <<'PY'
import socket, sys
ports = [int(p) for p in sys.argv[1:]]
if len(set(ports)) != 3:
    raise SystemExit('ERROR: Gateway, MCP and sandbox ports must differ.')
for port in ports:
    with socket.socket() as listener:
        try:
            listener.bind(('0.0.0.0', port))
        except OSError as exc:
            raise SystemExit(f'ERROR: Port {port} is unavailable: {exc}') from exc
PY
mkdir -p "$ROOT_DIR/bin" "$ROOT_DIR/data"
# Rebuild after source changes too; never silently use a stale pre-2.1 binary.
needs_build=false
if [[ ! -x bin/sandbox-runner ]]; then needs_build=true
else
  for source in sandbox_runner/*.go sandbox_runner/go.mod; do
    if [[ "$source" -nt bin/sandbox-runner ]]; then needs_build=true; break; fi
  done
fi
if [[ "$needs_build" == true ]]; then
  command -v go >/dev/null 2>&1 || { printf 'ERROR: Install Go to build sandbox-runner.\n' >&2; exit 1; }
  printf '[start] Building Go sandbox runner...\n'
  (cd sandbox_runner && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o ../bin/sandbox-runner .)
fi
RUNTIME_DIR="$(mktemp -d /tmp/redgate-local.XXXXXX)"
SANDBOX_DIR="$(mktemp -d /tmp/redgate-sandbox.XXXXXX)"
cleanup() {
  trap - EXIT INT TERM
  for pid in "${GW_PID:-}" "${MCP_PID:-}" "${SB_PID:-}"; do
    if [[ -n "$pid" ]]; then kill "$pid" 2>/dev/null || true; fi
  done
  for pid in "${GW_PID:-}" "${MCP_PID:-}" "${SB_PID:-}"; do
    if [[ -n "$pid" ]]; then wait "$pid" 2>/dev/null || true; fi
  done
  rm -rf -- "$RUNTIME_DIR" "$SANDBOX_DIR"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Generate secrets and hashes inside Python, not command-line arguments. Only the
# parent launcher/Gateway receive the private manifest, never adapter workspaces.
eval "$("$PYTHON_BIN" - "$RUNTIME_DIR/tokens.json" <<'PY'
import hashlib, json, secrets, sys
internal = secrets.token_hex(32)
print('export REDGATE_INTERNAL_TOKEN=' + internal)
profiles = []
for op, label, role, env in [
    ('op-alice', 'Alice', 'operator', 'REDGATE_TOKEN_HASH_OP_ALICE'),
    ('lead-sara', 'Sara', 'approver', 'REDGATE_TOKEN_HASH_LEAD_SARA'),
    ('admin-kaveh', 'Kaveh', 'admin', 'REDGATE_TOKEN_HASH_ADMIN_KAVEH'),
]:
    token = 'rg_local_' + secrets.token_hex(24)
    profiles.append(dict(operator_id=op, label=f'{label} · {role}', role=role, token=token))
    print(f'export {env}=' + hashlib.sha256(token.encode()).hexdigest())
with open(sys.argv[1], 'w', encoding='utf-8') as output:
    json.dump(dict(notice='Explicit local-lab demo only. Never deploy publicly.', profiles=profiles), output)
PY
)"
export REDGATE_CONFIG_DIR="${REDGATE_CONFIG_DIR:-$ROOT_DIR/config}"
export REDGATE_SKILLS_DIR="${REDGATE_SKILLS_DIR:-$ROOT_DIR/skills}"
export REDGATE_DB_PATH="${REDGATE_DB_PATH:-$ROOT_DIR/data/redgate.db}"
export REDGATE_SANDBOX_ADDR="127.0.0.1:$REDGATE_SANDBOX_PORT"
export REDGATE_SANDBOX_URL="http://127.0.0.1:$REDGATE_SANDBOX_PORT"
export REDGATE_SANDBOX_ROOT="$SANDBOX_DIR"
export REDGATE_MCP_URL="http://127.0.0.1:$REDGATE_MCP_PORT"
export REDGATE_LLM_MODE="${REDGATE_LLM_MODE:-mock}"
export REDGATE_STRICT_DNS_RESOLVE="${REDGATE_STRICT_DNS_RESOLVE:-true}"
export REDGATE_DEMO_MODE="${REDGATE_DEMO_MODE:-false}"
export REDGATE_DEMO_TOKENS_FILE="$RUNTIME_DIR/tokens.json"
if [[ "$REDGATE_DEMO_MODE" == true ]]; then
  printf '[WARNING] Explicit lab demo: anyone reaching this gateway can obtain a demo login.\n' >&2
else
  printf '[LOCAL ONLY] Private operator tokens are in %s (0600); demo bootstrap is disabled.\n' "$REDGATE_DEMO_TOKENS_FILE"
fi
"$ROOT_DIR/bin/sandbox-runner" &
SB_PID=$!
"$PYTHON_BIN" -m uvicorn mcp_server.http_server:app --host 127.0.0.1 --port "$REDGATE_MCP_PORT" --log-level warning &
MCP_PID=$!
# Bounded startup checks, not a fixed sleep that can hide a crashed service.
"$PYTHON_BIN" - "$REDGATE_MCP_PORT" "$REDGATE_SANDBOX_PORT" <<'PY'
import json, sys, time, urllib.request
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
deadline = time.monotonic() + 15
pending = set(sys.argv[1:])
while pending and time.monotonic() < deadline:
    for port in list(pending):
        try:
            with opener.open(f'http://127.0.0.1:{port}/health', timeout=0.5) as response:
                if json.load(response).get('status') == 'ok':
                    pending.remove(port)
        except (OSError, ValueError):
            pass
    if pending:
        time.sleep(0.1)
if pending:
    raise SystemExit('ERROR: Internal services did not become healthy: ' + ','.join(sorted(pending)))
PY
kill -0 "$SB_PID" "$MCP_PID"
printf '[ready] Redstrike 2.3.1 at http://%s:%s (development mode, no host isolation guarantee)\n' "$REDGATE_GATEWAY_HOST" "$REDGATE_GATEWAY_PORT"
"$PYTHON_BIN" -m uvicorn gateway.main:app --host "$REDGATE_GATEWAY_HOST" --port "$REDGATE_GATEWAY_PORT" --workers 1 --log-level info &
GW_PID=$!
# If any layer exits unexpectedly, clean up the other two instead of orphaning them.
wait -n "$GW_PID" "$MCP_PID" "$SB_PID"
