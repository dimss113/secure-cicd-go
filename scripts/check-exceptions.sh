#!/usr/bin/env bash
# Enforces docs/exception-process.md: every scanner suppression carries an owner, a reason and an expiry
# no more than MAX_DAYS away. Run from the repo root. Exits 1 on any violation.
set -euo pipefail

MAX_DAYS="${MAX_DAYS:-90}"
WARN_DAYS="${WARN_DAYS:-14}"
TODAY="${TODAY:-$(date -u +%F)}"
META_RE='exception: owner=@[A-Za-z0-9-]+ exp=([0-9]{4}-[0-9]{2}-[0-9]{2}) reason="[^"]{10,}"'
NOSEM_RE='nosemgrep: ?[A-Za-z0-9_.-]+'
errors=0

fail() { echo "::error file=$1,line=$2::$3"; errors=$((errors + 1)); }

# GNU date on the runner, BSD date on macOS. valid_date prints nothing for an impossible date.
valid_date() { date -u -d "$1" +%F 2>/dev/null || date -u -j -f %F "$1" +%F 2>/dev/null || true; }
add_days() { date -u -d "$1 + $2 days" +%F 2>/dev/null || date -u -j -v+"$2"d -f %F "$1" +%F; }

LIMIT="$(add_days "$TODAY" "$MAX_DAYS")"
WARN_FROM="$(add_days "$TODAY" "$WARN_DAYS")"

# check_meta FILE LINE TEXT: TEXT is the line directly above the suppression. Sets $exp when it is valid.
check_meta() {
  exp=""
  if [[ ! "$3" =~ $META_RE ]]; then
    fail "$1" "$2" "suppression needs 'exception: owner=@user exp=YYYY-MM-DD reason=\"...\"' on the line directly above"
    return 1
  fi
  exp="${BASH_REMATCH[1]}"
  if [ "$(valid_date "$exp")" != "$exp" ]; then
    fail "$1" "$2" "exp=$exp is not a real date"
    return 1
  elif [[ "$exp" < "$TODAY" ]]; then
    fail "$1" "$2" "exception expired on $exp: fix the finding or renew it in a new PR"
    return 1
  elif [[ "$exp" > "$LIMIT" ]]; then
    fail "$1" "$2" "exp=$exp is more than $MAX_DAYS days away (latest allowed $LIMIT)"
    return 1
  elif [[ "$exp" < "$WARN_FROM" ]]; then
    echo "::warning file=$1,line=$2::exception expires on $exp"
  fi
}

# Plain ignore files: every entry needs the exception line directly above it.
# shellcheck disable=SC2094 # fail only prints the file name, it never writes to the file
check_ignore_file() {
  local file="$1" n=0 prev="" line
  [ -f "$file" ] || return 0
  while IFS= read -r line || [ -n "$line" ]; do
    n=$((n + 1))
    case "$line" in
      '' | '#'*) prev="$line"; continue ;;
    esac
    # Trivy only re-reports a finding after its own exp: date, so it must match the exception line.
    if check_meta "$file" "$n" "$prev" && [ "$file" = .trivyignore ] && [[ "$line" != *" exp:$exp" ]]; then
      fail "$file" "$n" "Trivy entry must end with ' exp:$exp'"
    fi
    prev="$line"
  done < "$file"
}

# These files suppress findings silently, with no owner or expiry, so they are not allowed at all.
for f in .semgrepignore .gitleaks.toml .trivyignore.yaml trivy.yaml; do
  if [ -e "$f" ]; then
    fail "$f" 1 "not allowed: use the exception process in docs/exception-process.md"
  fi
done

check_ignore_file .trivyignore
check_ignore_file .gitleaksignore

# Inline suppressions. gitleaks:allow is banned because a .gitleaksignore fingerprint pins one finding, not a whole line.
while IFS=: read -r file n text; do
  if [[ "$text" == *gitleaks:allow* ]]; then
    fail "$file" "$n" "gitleaks:allow is not allowed: add the finding's fingerprint to .gitleaksignore"
    continue
  fi
  if [[ ! "$text" =~ $NOSEM_RE ]]; then
    fail "$file" "$n" "nosemgrep must name the rule id (nosemgrep: <rule-id>)"
    continue
  fi
  prev=""
  [ "$n" -gt 1 ] && prev="$(sed -n "$((n - 1))p" "$file")"
  check_meta "$file" "$n" "$prev" || true
done < <(git grep -n -I -E 'nosemgrep|gitleaks:allow' -- . ':!*.md' ':!scripts/check-exceptions.sh' || true)

if [ "$errors" -gt 0 ]; then
  echo "$errors exception problem(s). See docs/exception-process.md" >&2
  exit 1
fi
echo "exceptions OK (today $TODAY, latest allowed exp $LIMIT)"
