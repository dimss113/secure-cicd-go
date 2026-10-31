# No vault { address } stanza: HCL does not expand env vars, so the agent reads VAULT_ADDR itself.

auto_auth {
  method "approle" {
    mount_path = "auth/approle"
    config = {
      role_id_file_path                   = "/vault/auth/.role-id"
      secret_id_file_path                 = "/vault/auth/.secret-id"
      remove_secret_id_file_after_reading = false
    }
  }
}

# Give up instead of serving a stale or partial config when Vault keeps refusing.
template_config {
  exit_on_retry_failure = true
}

template {
  source               = "/vault/config/config.json.ctmpl"
  destination          = "/vault/out/config.json"
  perms                = "0400"
  error_on_missing_key = true
}
