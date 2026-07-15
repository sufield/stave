# SARIF Integration: GitHub Code Scanning

Stave findings appear directly in GitHub's Security tab
alongside code scanning alerts.

## Setup

1. Copy [`examples/ci-gate/github-actions.yml`](../../../examples/ci-gate/github-actions.yml)
   into your repo's `.github/workflows/` directory
2. Configure AWS credentials as repository secrets:
   - `STAVE_AWS_ACCESS_KEY_ID` — read-only collector key
   - `STAVE_AWS_SECRET_ACCESS_KEY` — read-only collector secret
   - `CONFIG_BUCKET` — S3 bucket with AWS Config snapshots
3. Push to main

## What you'll see

Findings appear in **Security > Code Scanning**:

- Compound chain findings (EXPLOITABLE) as **error** severity
- Near-miss chain findings (ONE AWAY) as **warning** severity
- Standard control violations as **warning** or **note**

Each finding includes:
- The control ID and description
- The resource identifier
- Exploitability classification and chain membership
- Remediation guidance

## Severity mapping

| Stave severity | SARIF level | Code Scanning display |
|---|---|---|
| critical | error | Error (red) |
| high | error | Error (red) |
| medium | warning | Warning (yellow) |
| low | note | Note (blue) |
| info | note | Note (blue) |

## Filtering

In the Code Scanning UI, filter by:

- **Tool**: `stave` in the tool dropdown
- **Severity**: error, warning, note
- **Rule**: control ID (e.g., `CTL.S3.PUBLIC.001`)

## Scheduled scans

The example workflow runs weekly (Monday 6 AM UTC). For
continuous monitoring, change the cron schedule or add a
`push` trigger.

## Exit codes and gating

`stave apply` exits 3 when violations are found. In the
workflow, this fails the job — the security gate blocks.
The SARIF upload step uses `if: always()` so findings are
uploaded even when the gate fails.

Exit 3 is not an error. It means Stave found real
misconfigurations. The gate is working as designed.
