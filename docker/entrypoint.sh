#!/bin/sh
# Starts Vault Agent in front of the API when AppRole credentials are mounted.
set -eu

if [ -f /vault/agent/approle/role_id ] && [ -f /vault/agent/approle/secret_id ]; then
  echo "starting Vault Agent (AppRole -> cache proxy on 127.0.0.1:8200)"
  vault agent -config=/etc/vault-agent.hcl >/tmp/vault-agent.log 2>&1 &
  agent_pid=$!

  for _ in $(seq 1 60); do
    if curl -sf http://127.0.0.1:8200/v1/sys/health >/dev/null 2>&1; then
      break
    fi
    sleep 1
  done

  if ! kill -0 "$agent_pid" 2>/dev/null; then
    echo "Vault Agent failed to start:" >&2
    cat /tmp/vault-agent.log >&2
    exit 1
  fi
else
  echo "no AppRole credentials mounted; starting without Vault Agent"
fi

exec dotnet Orders.Api.dll
