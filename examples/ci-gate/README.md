# CI Gate Examples

Drop-in workflows for running Stave as a CI security gate.

## Files

| File | Platform | What It Does |
|---|---|---|
| [github-actions.yml](github-actions.yml) | GitHub Actions | Imports snapshot, evaluates, uploads SARIF to Code Scanning |
| [gitlab-ci.yml](gitlab-ci.yml) | GitLab CI | Imports snapshot, evaluates, stores JSON artifact |
| [scheduled-scan.sh](scheduled-scan.sh) | cron / any CI | Captures snapshot, evaluates, diffs against previous run |

## Setup

1. Create a read-only IAM role for the collector
   ([policy and SMT proof](../../docs/trust/collector-policy.md))
2. Store credentials as CI secrets
3. Copy the workflow file into your repo
4. Push to main

## Exit codes

| Code | Meaning | CI result |
|---|---|---|
| 0 | Clean — all controls pass | Pass |
| 3 | Violations found | Fail (gate blocks) |
| 2 | Input error (bad flags, missing files) | Fail (config issue) |
| 4 | Internal error | Fail (bug) |

Exit code 3 is not a failure — it means Stave found real
misconfigurations. The gate is working.

## SARIF integration

The GitHub Actions workflow uploads findings as SARIF. They appear
in Security > Code Scanning alongside any other scanning tools.
See [SARIF integration guide](../../docs/integrations/sarif/sarif-code-scanning.md).
