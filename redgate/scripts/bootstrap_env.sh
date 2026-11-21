#!/usr/bin/env bash
# Create deployment credentials; print operator tokens ONCE, store only hashes.
# .env remains 0600. The LLM key directory/file use 0750/0640 so the non-root
# gateway can read them through the host's restricted supplementary group.
set -euo pipefail
umask 077
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$ROOT_DIR/.env"
SECRET_DIR="$ROOT_DIR/secrets"
LLM_KEY_FILE="$SECRET_DIR/llm_api_key"
if [[ "${1:-}" == --help || "${1:-}" == -h ]]; then
  printf 'Usage: %s [--force]\n--force rotates all operator/service tokens; keep your existing .env backed up privately.\n' "$0"
  exit 0
fi
[[ $# -le 1 && ( $# -eq 0 || "$1" == --force ) ]] || { printf 'ERROR: Expected --force or no arguments.\n' >&2; exit 2; }
if [[ -e "$ENV_FILE" && "${1:-}" != --force ]]; then
  printf 'ERROR: %s exists. Use --force only if you intend to rotate all tokens.\n' "$ENV_FILE" >&2
  exit 1
fi

gen_hex() {
  if command -v openssl >/dev/null 2>&1; then openssl rand -hex "$1"
  else python3 -c 'import secrets, sys; print(secrets.token_hex(int(sys.argv[1])))' "$1"; fi
}
sha256_of() { printf '%s' "$1" | sha256sum | awk '{print $1}'; }
INTERNAL_TOKEN="$(gen_hex 32)"
TOK_ALICE="rg_op_$(gen_hex 20)"
TOK_SARA="rg_lead_$(gen_hex 20)"
TOK_KAVEH="rg_adm_$(gen_hex 20)"
HASH_ALICE="$(sha256_of "$TOK_ALICE")"
HASH_SARA="$(sha256_of "$TOK_SARA")"
HASH_KAVEH="$(sha256_of "$TOK_KAVEH")"
SECRETS_GID="${REDGATE_SECRETS_GID:-$(id -g)}"
[[ "$SECRETS_GID" =~ ^[0-9]+$ ]] || { printf 'ERROR: REDGATE_SECRETS_GID must be numeric.\n' >&2; exit 2; }
mkdir -p "$SECRET_DIR" "$ROOT_DIR/data"
[[ -e "$LLM_KEY_FILE" ]] || : > "$LLM_KEY_FILE"
chgrp -- "$SECRETS_GID" "$SECRET_DIR" "$LLM_KEY_FILE"
chmod 750 "$SECRET_DIR"
chmod 640 "$LLM_KEY_FILE"
TMP_ENV="$(mktemp "$ROOT_DIR/.env.new.XXXXXX")"
trap 'rm -f -- "$TMP_ENV"' EXIT
cat > "$TMP_ENV" <<EOF
# Generated on $(date -u +%Y-%m-%dT%H:%M:%SZ). Never commit this file.
REDGATE_BIND_ADDR=127.0.0.1
REDGATE_VERSION=2.3.1
REDGATE_IMAGE_FLAVOR=full
REDGATE_SECRETS_GID=${SECRETS_GID}
REDGATE_INTERNAL_TOKEN=${INTERNAL_TOKEN}
REDGATE_TOKEN_HASH_OP_ALICE=${HASH_ALICE}
REDGATE_TOKEN_HASH_LEAD_SARA=${HASH_SARA}
REDGATE_TOKEN_HASH_ADMIN_KAVEH=${HASH_KAVEH}
REDGATE_LLM_MODE=mock
REDGATE_LLM_BASE_URL=http://ollama:11434/v1
REDGATE_LLM_MODEL=qwen2.5-coder:14b
REDGATE_STRICT_DNS_RESOLVE=true
REDGATE_DEMO_MODE=false
EOF
chmod 600 "$TMP_ENV"
if [[ "${1:-}" == --force ]]; then mv -f -- "$TMP_ENV" "$ENV_FILE"
else ln -- "$TMP_ENV" "$ENV_FILE"; rm -f -- "$TMP_ENV"; fi
trap - EXIT
cat <<EOF
=====================================================================
 Redstrike 2.3.1 initialized. SAVE THESE PRIVATE BEARER TOKENS NOW.
 Only their SHA-256 hashes are stored in .env (0600).
=====================================================================
  op-alice    (operator) : ${TOK_ALICE}
  lead-sara   (approver) : ${TOK_SARA}
  admin-kaveh (admin)    : ${TOK_KAVEH}
=====================================================================
LLM key: secrets/llm_api_key (0640); restricted host group: ${SECRETS_GID}
Run ./scripts/redgate.sh doctor, then ./scripts/redgate.sh up.
Open http://127.0.0.1:8000 and paste an operator token.
Review signed scope and external egress isolation before live work.
EOF
