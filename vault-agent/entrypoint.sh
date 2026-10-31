#!/bin/sh
# Writes the AppRole credentials from the environment to the tmpfs auth volume, then runs the agent.
set -eu

: "${VAULT_ADDR:?VAULT_ADDR is not set}"
: "${APP_ENV:?APP_ENV is not set}"
: "${VAULT_ROLE_ID:?VAULT_ROLE_ID is not set}"
: "${VAULT_SECRET_ID:?VAULT_SECRET_ID is not set}"

umask 077
printf '%s' "$VAULT_ROLE_ID" > /vault/auth/.role-id
printf '%s' "$VAULT_SECRET_ID" > /vault/auth/.secret-id

exec vault agent -config=/vault/config/agent.hcl
