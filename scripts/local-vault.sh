#!/usr/bin/env bash
# Local Vault dev server seeded like vault.axen.software, for testing the sidecar without the real Vault.
# Usage: scripts/local-vault.sh up | down
# Writes AppRole credentials to .local/{development,production}.env (git-ignored). Dev only: in-memory, throwaway values.
set -euo pipefail

cd "$(dirname "$0")/.."
NAME=scg-vault-dev
NET=scg-local
IMAGE=hashicorp/vault:2.2.1@sha256:962a92876e168d68eaaa24b0b8b49bbce1cb63024060a67bba95cd158a366fc2

vexec() { docker exec -i -e VAULT_ADDR=http://127.0.0.1:8200 -e VAULT_TOKEN="$(cat .local/root-token)" "$NAME" vault "$@"; }

up() {
  mkdir -p .local && chmod 700 .local
  openssl rand -hex 16 > .local/root-token
  docker network inspect "$NET" >/dev/null 2>&1 || docker network create "$NET" >/dev/null
  docker run -d --name "$NAME" --network "$NET" -p 127.0.0.1:8200:8200 --cap-add IPC_LOCK \
    -e VAULT_DEV_ROOT_TOKEN_ID="$(cat .local/root-token)" "$IMAGE" \
    server -dev -dev-listen-address=0.0.0.0:8200 >/dev/null
  until vexec status >/dev/null 2>&1; do sleep 1; done

  vexec secrets enable -path=static-secret kv-v2 >/dev/null
  vexec auth enable approle >/dev/null
  for env in development production; do
    # The development JWT secret holds a quote and a backslash on purpose: the template must still emit valid JSON.
    jwt="$(openssl rand -hex 24)"
    [ "$env" = development ] && jwt="q\"b\\s-$jwt"
    vexec kv put -mount=static-secret "secure-cicd-go/$env/secrets/jwt" secret_key="$jwt" >/dev/null
    vexec kv put -mount=static-secret "secure-cicd-go/$env/secrets/aes" secret_key="$(openssl rand -hex 32)" >/dev/null
    vexec policy write "secure-cicd-go-$env" - < "vault/policies/secure-cicd-go-$env.hcl" >/dev/null
    vexec write "auth/approle/role/secure-cicd-go-$env" token_policies="secure-cicd-go-$env" \
      token_ttl=1h token_max_ttl=4h secret_id_ttl=0 secret_id_num_uses=0 >/dev/null
    {
      echo "VAULT_ADDR=http://$NAME:8200"
      echo "VAULT_ROLE_ID=$(vexec read -field=role_id "auth/approle/role/secure-cicd-go-$env/role-id")"
      echo "VAULT_SECRET_ID=$(vexec write -f -field=secret_id "auth/approle/role/secure-cicd-go-$env/secret-id")"
    } > ".local/$env.env"
    chmod 600 ".local/$env.env"
  done
  echo "local vault up: $NAME on network $NET; credentials in .local/development.env and .local/production.env"
}

down() {
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  rm -rf .local
  echo "local vault removed"
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  kv) shift; vexec kv "$@" ;;
  *) echo "usage: $0 up|down|kv <args>" >&2; exit 2 ;;
esac
