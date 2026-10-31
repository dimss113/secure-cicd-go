# Security finding exceptions

The PR gates block a merge on any finding. Sometimes a finding has to be accepted for a while: a CVE
with no fixed version yet, or a scanner false positive. This is the only allowed way to do that.

## Rules

1. **Fix first.** An exception is for a finding that cannot be fixed now, not one that is inconvenient.
2. **Through a PR.** Exceptions live in the repo, so Git history records who added one, when and why.
   The PR description links an issue with the details.
3. **One finding per entry.** One CVE ID, one Gitleaks fingerprint, or one `nosemgrep` with a rule id.
   Never a whole rule, a whole severity, or a whole path.
4. **Owner, reason and expiry.** Every entry has this line directly above it:

   ```
   exception: owner=@github-user exp=YYYY-MM-DD reason="at least 10 characters, link to the issue"
   ```

   `exp` is at most **90 days** away. To keep an exception longer, renew it in a new PR with a fresh reason.
5. **Real secrets are never excepted.** A Gitleaks finding that is a real credential is revoked and
   rotated. Gitleaks exceptions are for false positives only.

`scripts/check-exceptions.sh` enforces rules 3 and 4 in the `exceptions` PR check, and every Monday
in the `exception-expiry` workflow. It warns 14 days before an exception expires.

## Per scanner

| Scanner | Where | Entry |
| --- | --- | --- |
| Trivy (image, config) | `.trivyignore` | `CVE-2026-12345 exp:2026-12-31` or `DS-0002 exp:2026-12-31`. Trivy itself reports the finding again after `exp:`, which must equal the date on the exception line |
| Gitleaks | `.gitleaksignore` | Fingerprint `<commit>:<file>:<rule-id>:<line>`, printed in the Gitleaks report |
| Semgrep | the source line | `// nosemgrep: <rule-id>` (or `# nosemgrep: <rule-id>`), with the exception line directly above |
| govulncheck | none | No suppression. It only reports vulnerable code that is actually called: upgrade, or stop calling it |
| dependency-review | none | No suppression. It only checks dependencies the PR adds: pick a version without the advisory |

Not allowed, because they suppress findings without an owner or expiry: `.semgrepignore`, `.gitleaks.toml`,
`.trivyignore.yaml`, `trivy.yaml`, a bare `nosemgrep`, and `gitleaks:allow`.

## Examples

`.trivyignore`:

```
# exception: owner=@dimss113 exp=2026-12-31 reason="no fixed version upstream yet, tracked in #20"
CVE-2026-12345 exp:2026-12-31
```

Go source:

```go
// exception: owner=@dimss113 exp=2026-12-31 reason="fixed test vector from RFC, not a credential, #21"
const vector = "..." // nosemgrep: generic.secrets.security.detected-generic-api-key.detected-generic-api-key
```

## Limits

- Gitleaks has no expiry of its own. After `exp`, the check fails until the entry is removed, but the
  fingerprint keeps hiding that one old finding. That is acceptable: it only ever matches a single commit.
- A repo writer can change the workflow or this script in a PR. Review of those files is what stops that.
