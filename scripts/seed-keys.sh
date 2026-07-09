#!/bin/sh
# seed-keys.sh — provision the three recipient X25519 keypairs (user, merchant,
# gateway) as static seed data (TECHSPEC-001 §10 Q1: static seeding, no key
# registry). Writes:
#   $SECRETS_DIR/keys/<name>.key   private half, base64url unpadded (32 bytes)
#   $SECRETS_DIR/keys/<name>.pub   public  half, base64url unpadded (32 bytes)
#   $SECRETS_DIR/audiences.json    the roster the shell loads (public halves)
#
# The public halves in audiences.json and the private halves in keys/ come from
# the same keypair, so `open` with a keys/<name>.key recovers exactly the
# segment sealed to that audience. Idempotent: existing keypairs are kept, only
# audiences.json is rewritten from them.
set -eu

SECRETS_DIR="${SECRETS_DIR:-/secrets}"
KEYS_DIR="${SECRETS_DIR}/keys"
AUD_FILE="${SECRETS_DIR}/audiences.json"
mkdir -p "${KEYS_DIR}"

# b64url reads raw bytes on stdin and prints base64url unpadded.
b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }

# gen writes keys/<name>.{key,pub} if the private key is not already present.
# Raw X25519 keys are the last 32 bytes of the PKCS8 (private) / SPKI (public)
# DER encodings.
gen() {
  name="$1"
  if [ -f "${KEYS_DIR}/${name}.key" ] && [ -f "${KEYS_DIR}/${name}.pub" ]; then
    return 0
  fi
  priv_pem="$(openssl genpkey -algorithm X25519)"
  printf '%s\n' "${priv_pem}" | openssl pkey -outform DER 2>/dev/null \
    | tail -c 32 | b64url > "${KEYS_DIR}/${name}.key"
  printf '%s\n' "${priv_pem}" | openssl pkey -pubout -outform DER 2>/dev/null \
    | tail -c 32 | b64url > "${KEYS_DIR}/${name}.pub"
  echo "seed-keys: generated ${name} keypair"
}

gen user
gen merchant
gen gateway

USER_PUB="$(cat "${KEYS_DIR}/user.pub")"
MERCHANT_PUB="$(cat "${KEYS_DIR}/merchant.pub")"
GATEWAY_PUB="$(cat "${KEYS_DIR}/gateway.pub")"

cat > "${AUD_FILE}" <<EOF
[
  {"name":"user","kid":"user-key-1","public_key":"${USER_PUB}"},
  {"name":"merchant","kid":"merchant-key-1","public_key":"${MERCHANT_PUB}"},
  {"name":"gateway","kid":"gateway-key-1","public_key":"${GATEWAY_PUB}"}
]
EOF
echo "seed-keys: wrote ${AUD_FILE}"
