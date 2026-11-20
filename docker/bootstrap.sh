#!/bin/sh
# One-off bootstrap: enables the engines, creates the signing key, the least-privilege policy
# and an AppRole, then hands the credentials to the API container through a shared volume.
set -eu

export VAULT_ADDR="${VAULT_ADDR:-http://vault:8200}"
export VAULT_TOKEN="${VAULT_TOKEN:-root}"

echo "waiting for Vault at ${VAULT_ADDR}"
until vault status >/dev/null 2>&1; do
  sleep 1
done

if ! vault secrets list | grep -q '^secret/'; then
  vault secrets enable -path=secret -version=2 kv
fi

if ! vault secrets list | grep -q '^transit/'; then
  vault secrets enable transit
fi

if ! vault read transit/keys/audit-signer >/dev/null 2>&1; then
  vault write -f transit/keys/audit-signer type=ecdsa-p256
fi

vault policy write audit-api - <<'EOF'
# The API appends checkpoints, updates the head pointer, and reads both back for verification.
path "secret/data/audit-ledger/checkpoints/*" {
  capabilities = ["create", "update", "read"]
}
path "secret/data/audit-ledger/heads/*" {
  capabilities = ["create", "read", "update"]
}
path "secret/metadata/audit-ledger/*" {
  capabilities = ["read", "list"]
}
path "transit/sign/audit-signer" {
  capabilities = ["update"]
}
path "transit/keys/audit-signer" {
  capabilities = ["read"]
}
EOF

vault auth list | grep -q '^approle/' || vault auth enable approle

vault write auth/approle/role/audit-api \
  token_policies=audit-api \
  token_ttl=1h \
  token_max_ttl=4h \
  secret_id_ttl=0 >/dev/null

role_id=$(vault read -field=role_id auth/approle/role/audit-api/role-id)
secret_id=$(vault write -f -field=secret_id auth/approle/role/audit-api/secret-id)

mkdir -p /vault/agent/approle
printf '%s' "$role_id" >/vault/agent/approle/role_id
printf '%s' "$secret_id" >/vault/agent/approle/secret_id
chmod 644 /vault/agent/approle/role_id /vault/agent/approle/secret_id

echo "bootstrap complete: kv-v2, transit key 'audit-signer', policy and AppRole are ready"
