#!/usr/bin/env bash
# bootstrap-keycloak.sh — provision the realm the shell's auth check requires
# (TASK-001-14). Creates:
#   - realm `chainbind` (issuer URL matches CHAINBIND_KEYCLOAK_ISSUER)
#   - public client `chainbind-api` with direct access grants
#   - an audience mapper so tokens carry aud=chainbind-api
#   - realm role `role_issuer_admin`
#   - user `issuer`/`issuer` carrying that role
#
# The shell (internal/adapters/auth/keycloak) accepts a token only if iss ==
# CHAINBIND_KEYCLOAK_ISSUER AND aud contains chainbind-api AND realm_access.roles
# contains role_issuer_admin — all three are provisioned here.
#
# Obtain a token (used by `make demo` and the integration test):
#   curl -s -d grant_type=password -d client_id=chainbind-api \
#        -d username=issuer -d password=issuer \
#        http://localhost:8080/realms/chainbind/protocol/openid-connect/token
#
# Idempotent: safe to re-run. Uses kcadm.sh from the Keycloak image.
set -euo pipefail

KC=/opt/keycloak/bin/kcadm.sh
SERVER="${KC_URL:-http://keycloak:8080}"
ADMIN="${KEYCLOAK_ADMIN:-admin}"
ADMIN_PW="${KEYCLOAK_ADMIN_PASSWORD:-admin}"

REALM=chainbind
CLIENT=chainbind-api
ROLE=role_issuer_admin
USER=issuer
USER_PW=issuer

echo "bootstrap-keycloak: waiting for ${SERVER}"
until "${KC}" config credentials --server "${SERVER}" --realm master \
  --user "${ADMIN}" --password "${ADMIN_PW}" >/dev/null 2>&1; do
  sleep 2
done
echo "bootstrap-keycloak: authenticated to master"

# Realm.
if ! "${KC}" get "realms/${REALM}" >/dev/null 2>&1; then
  "${KC}" create realms -s realm="${REALM}" -s enabled=true
  echo "bootstrap-keycloak: created realm ${REALM}"
fi

# Realm role.
if ! "${KC}" get "roles/${ROLE}" -r "${REALM}" >/dev/null 2>&1; then
  "${KC}" create roles -r "${REALM}" -s name="${ROLE}"
  echo "bootstrap-keycloak: created realm role ${ROLE}"
fi

# Public client with direct access grants (password grant, no client secret).
CID="$("${KC}" get clients -r "${REALM}" -q clientId="${CLIENT}" \
  --fields id --format csv --noquotes 2>/dev/null | head -n1 || true)"
if [ -z "${CID}" ]; then
  "${KC}" create clients -r "${REALM}" \
    -s clientId="${CLIENT}" -s enabled=true -s publicClient=true \
    -s directAccessGrantsEnabled=true -s standardFlowEnabled=false
  CID="$("${KC}" get clients -r "${REALM}" -q clientId="${CLIENT}" \
    --fields id --format csv --noquotes | head -n1)"
  echo "bootstrap-keycloak: created client ${CLIENT} (${CID})"
fi

# Audience mapper so access tokens carry aud=chainbind-api (Keycloak does not
# add the client id to aud by default).
if ! "${KC}" get "clients/${CID}/protocol-mappers/models" -r "${REALM}" \
  --fields name --format csv --noquotes 2>/dev/null | grep -q 'aud-chainbind-api'; then
  "${KC}" create "clients/${CID}/protocol-mappers/models" -r "${REALM}" \
    -s name=aud-chainbind-api -s protocol=openid-connect \
    -s protocolMapper=oidc-audience-mapper \
    -s 'config."included.client.audience"=chainbind-api' \
    -s 'config."access.token.claim"=true' \
    -s 'config."id.token.claim"=false'
  echo "bootstrap-keycloak: added audience mapper"
fi

# Test user. email/firstName/lastName/emailVerified are set because the realm's
# default user profile treats them as required: without them the direct-grant
# token request fails with "Account is not fully set up".
USER_ATTRS='-s enabled=true -s emailVerified=true -s email=issuer@example.com -s firstName=Issuer -s lastName=Admin'
UID_VAL="$("${KC}" get users -r "${REALM}" -q username="${USER}" \
  --fields id --format csv --noquotes 2>/dev/null | head -n1 || true)"
if [ -z "${UID_VAL}" ]; then
  # shellcheck disable=SC2086
  "${KC}" create users -r "${REALM}" -s username="${USER}" ${USER_ATTRS}
  UID_VAL="$("${KC}" get users -r "${REALM}" -q username="${USER}" \
    --fields id --format csv --noquotes | head -n1)"
  echo "bootstrap-keycloak: created user ${USER}"
else
  # shellcheck disable=SC2086
  "${KC}" update "users/${UID_VAL}" -r "${REALM}" ${USER_ATTRS}
fi
# Permanent password (no UPDATE_PASSWORD required action).
"${KC}" set-password -r "${REALM}" --username "${USER}" --new-password "${USER_PW}" --temporary=false

# Assign the realm role (add-roles is safe to repeat).
"${KC}" add-roles -r "${REALM}" --uusername "${USER}" --rolename "${ROLE}"

echo "bootstrap-keycloak: done"
echo "bootstrap-keycloak: token endpoint -> ${SERVER}/realms/${REALM}/protocol/openid-connect/token (client=${CLIENT} user=${USER} pw=${USER_PW})"
