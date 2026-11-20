# Vault Agent in proxy mode: it authenticates with AppRole and injects the token,
# so the API never sees or manages a Vault token itself.
pid_file = "/tmp/vault-agent.pid"

vault {
  address = "http://vault:8200"
}

auto_auth {
  method "approle" {
    mount_path = "auth/approle"
    config = {
      role_id_file_path                   = "/vault/agent/approle/role_id"
      secret_id_file_path                 = "/vault/agent/approle/secret_id"
      remove_secret_id_file_after_reading = false
    }
  }
}

cache {
  use_auto_auth_token = true
}

listener "tcp" {
  address     = "127.0.0.1:8200"
  tls_disable = true
}
