#!/usr/bin/env bash
# End-to-end smoke test against `docker compose up`: business writes, a green verification,
# a direct SQL tamper by a "DBA", and the verification that catches it.
set -euo pipefail

API="${API:-http://localhost:8080}"
COMPOSE="${COMPOSE:-docker compose}"
PSQL=($COMPOSE exec -T postgres psql -U audit -d audit -tA -c)
JSON=(-H "Content-Type: application/json" -H "X-Actor: smoke")

step() { printf '\n\033[1m%s\033[0m\n' "$*"; }

step "1. health"
curl -sf "$API/healthz"
echo

step "2. create, confirm and ship an order"
order=$(curl -sf "${JSON[@]}" -X POST "$API/orders" -d '{"customer":"acme","amount":99.90}')
order_id=$(printf '%s' "$order" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')
echo "order: $order_id"
curl -sf -X POST "${JSON[@]}" "$API/orders/$order_id/confirm" >/dev/null
curl -sf -X POST "${JSON[@]}" "$API/orders/$order_id/ship" >/dev/null
echo "status: $(curl -sf "$API/orders/$order_id" | python3 -c 'import json,sys; print(json.load(sys.stdin)["status"])')"

step "3. journal state"
curl -sf "$API/audit/verify" | python3 -m json.tool
curl -sf "$API/audit/checkpoints" | python3 -c 'import json,sys
for c in json.load(sys.stdin):
    print("checkpoint {}: tree_size={} root={}… key=v{}".format(c["seq"], c["treeSize"], c["root"][:16], c["keyVersion"]))'

step "4. anchor that lives outside the database (Vault)"
$COMPOSE exec -T -e VAULT_ADDR=http://127.0.0.1:8200 -e VAULT_TOKEN=root vault \
  vault kv get -field=tree_size secret/audit-ledger/heads/orders \
  | sed 's/^/heads.tree_size = /'

step "5. inclusion proof for leaf 1"
curl -sf "$API/audit/proof/1" | python3 -c 'import json,sys
p = json.load(sys.stdin)
print("leaf {} of {}: path length {}".format(p["leafIndex"], p["treeSize"], len(p["auditPath"])))'

step "6. the DBA edits a row directly in PostgreSQL"
"${PSQL[@]}" "UPDATE audit_log SET actor = 'mallory' WHERE leaf_index = 0;" >/dev/null
echo "UPDATE audit_log SET actor = 'mallory' WHERE leaf_index = 0;  -- done"

step "7. verification now fails"
report=$(curl -sf "$API/audit/verify")
printf '%s' "$report" | python3 -m json.tool
ok=$(printf '%s' "$report" | python3 -c 'import json,sys; print(str(json.load(sys.stdin)["ok"]).lower())')

if [ "$ok" = "true" ]; then
  echo "FAILED: tampering was not detected" >&2
  exit 1
fi

step "OK: the journal detected the tampering"
