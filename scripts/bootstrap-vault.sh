#!/bin/sh
# bootstrap-vault.sh — enable Vault Transit and create the issuer ed25519
# signing key (TASK-001-14). Idempotent: safe to re-run against a live stack.
# Uses the Vault HTTP API via curl+jq only, so it runs in any small image with
# those tools (no Vault CLI required).
#
# Also exports the issuer public key (base64url, unpadded) to
# $SECRETS_DIR/issuer.pub so `chainbind open`/`verify` on the host can check the
# Vault-produced signature without talking to Vault.
set -eu

VAULT_ADDR="${VAULT_ADDR:-http://vault:8200}"
VAULT_TOKEN="${VAULT_TOKEN:-root}"
KEY="${CHAINBIND_VAULT_TRANSIT_KEY:-issuer-signing-key}"
SECRETS_DIR="${SECRETS_DIR:-/secrets}"
HDR="X-Vault-Token: ${VAULT_TOKEN}"

echo "bootstrap-vault: waiting for Vault at ${VAULT_ADDR}"
until curl -sf "${VAULT_ADDR}/v1/sys/health" >/dev/null 2>&1; do
  sleep 1
done

# Enable Transit. Already-enabled returns 400 ("path is already in use"); that
# is the idempotent no-op, not a failure.
curl -s -o /dev/null -X POST -H "${HDR}" \
  -d '{"type":"transit"}' "${VAULT_ADDR}/v1/sys/mounts/transit" || true
echo "bootstrap-vault: transit engine ready"

# Create the ed25519 key. POST to an existing key is a no-op, so this is
# idempotent (the vault signer adapter requires type=ed25519).
curl -s -o /dev/null -X POST -H "${HDR}" \
  -d '{"type":"ed25519"}' "${VAULT_ADDR}/v1/transit/keys/${KEY}"
echo "bootstrap-vault: transit key '${KEY}' present"

# Export the issuer public key for the host-side open/verify. Vault returns the
# ed25519 public key as standard base64; the CLI/library expect base64url
# unpadded, so translate the alphabet and strip padding (same 32 bytes).
mkdir -p "${SECRETS_DIR}"
PUB_STD="$(curl -sf -H "${HDR}" "${VAULT_ADDR}/v1/transit/keys/${KEY}" \
  | jq -r '.data.keys | to_entries | max_by(.key | tonumber) | .value.public_key')"
if [ -z "${PUB_STD}" ] || [ "${PUB_STD}" = "null" ]; then
  echo "bootstrap-vault: could not read public key for '${KEY}'" >&2
  exit 1
fi
printf '%s' "${PUB_STD}" | tr '+/' '-_' | tr -d '=' > "${SECRETS_DIR}/issuer.pub"
echo "bootstrap-vault: wrote ${SECRETS_DIR}/issuer.pub"
