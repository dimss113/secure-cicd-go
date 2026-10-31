#!/usr/bin/env bash
# Asks Dokploy to deploy one compose service, then waits until the app reports the expected commit.
# A deploy only counts once /version proves the scanned commit is the one running.
# Env: DOKPLOY_URL DOKPLOY_API_KEY DOKPLOY_COMPOSE_ID APP_URL EXPECTED_COMMIT [TIMEOUT_SECONDS] [POLL_SECONDS]
set -euo pipefail

: "${DOKPLOY_URL:?DOKPLOY_URL is not set}"
: "${DOKPLOY_API_KEY:?DOKPLOY_API_KEY is not set}"
: "${DOKPLOY_COMPOSE_ID:?DOKPLOY_COMPOSE_ID is not set}"
: "${APP_URL:?APP_URL is not set}"
: "${EXPECTED_COMMIT:?EXPECTED_COMMIT is not set}"
timeout="${TIMEOUT_SECONDS:-300}"
poll="${POLL_SECONDS:-10}"

body="$(jq -n --arg id "$DOKPLOY_COMPOSE_ID" --arg sha "$EXPECTED_COMMIT" \
  '{composeId: $id, title: ("CI deploy " + $sha[0:7])}')"

# The key is read from a file descriptor, not passed as an argument, so it never shows up in the process list.
curl -sS --fail-with-body --max-time 30 -X POST "$DOKPLOY_URL/api/compose.deploy" \
  -H "Content-Type: application/json" \
  -H @<(printf 'x-api-key: %s\n' "$DOKPLOY_API_KEY") \
  --data "$body"
echo

deadline=$((SECONDS + timeout))
while :; do
  got="$(curl -sS --max-time 5 "$APP_URL/version" 2>/dev/null | jq -r '.commit // empty' 2>/dev/null || true)"
  if [ "$got" = "$EXPECTED_COMMIT" ]; then
    curl -sS --fail --max-time 5 "$APP_URL/health"
    echo "running commit $EXPECTED_COMMIT"
    exit 0
  fi
  if [ "$SECONDS" -ge "$deadline" ]; then
    echo "::error::$APP_URL still reports '${got:-unreachable}' after ${timeout}s, expected $EXPECTED_COMMIT"
    exit 1
  fi
  echo "waiting: app reports '${got:-unreachable}'"
  sleep "$poll"
done
