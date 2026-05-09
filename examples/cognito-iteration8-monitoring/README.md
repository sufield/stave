# Cognito Iteration 8 — Monitoring and Alarms

End-to-end fixtures for the Iteration 8 CloudWatch alarm /
metric controls. New asset type: `aws_cognito_account`
(account-scoped Cognito monitoring posture). No compound chain
defined for this iteration.

```
10 individual controls   (writeup → all fire ; remediated → 0)
 0 compound chains
```

## Controls covered

All 10 evaluate on a single `aws_cognito_account` asset with
`kind: cognito_account` — an account-region-scoped aggregation
the collector synthesises by joining `aws_cloudwatch_alarm`,
`aws_cloudwatch_log_metric_filter`, and `aws_cloudtrail_trail`
queries together. Stave never sees the per-alarm assets; it
sees one aggregated boolean per question on the account asset.

| Control | Predicate signal |
|---|---|
| `CTL.COGNITO.ALARM.ADMINCREATE.001`  | `alarm_admin_create_user == false` |
| `CTL.COGNITO.ALARM.UPDATEPOOL.001`   | `alarm_update_user_pool == false` |
| `CTL.COGNITO.ALARM.DELETEPOOL.001`   | `alarm_delete_user_pool == false` |
| `CTL.COGNITO.ALARM.CREATEIDPOOL.001` | `alarm_create_identity_pool_unauth == false` |
| `CTL.COGNITO.ALARM.RISKCONFIG.001`   | `alarm_set_risk_config == false` |
| `CTL.COGNITO.ALARM.ADMINPWD.001`     | `alarm_admin_set_user_password == false` |
| `CTL.COGNITO.ALARM.FAILEDAUTH.001`   | `alarm_failed_auth_spike == false` |
| `CTL.COGNITO.ALARM.REGSPIKE.001`     | `alarm_registration_spike == false` |
| `CTL.COGNITO.ALARM.MFAFAIL.001`      | `alarm_mfa_failure_spike == false` |
| `CTL.COGNITO.METRICS.LOGINS.001`     | `metrics_logins_tracked == false` |

## Run

```bash
cd <repo-root>/stave
make build

./stave apply \
    --observations examples/cognito-iteration8-monitoring/fixtures/writeup-config/observations \
    --now 2026-05-09T12:00:00Z --allow-unknown-input --format json \
  | jq '{ctls: ([.findings[] | select(.control_id | test("CTL.COGNITO.(ALARM|METRICS)"))] | map(.control_id) | sort | unique), chains: (.chain_findings // [] | map(.chain))}'

./stave apply \
    --observations examples/cognito-iteration8-monitoring/fixtures/remediated-config/observations \
    --now 2026-05-09T12:00:00Z --allow-unknown-input --format json \
  | jq '{ctls: ([.findings[] | select(.control_id | test("CTL.COGNITO.(ALARM|METRICS)"))] | length), chains: (.chain_findings // [] | length)}'
```

Expected:

```
writeup     → 10 ctls, 0 chains
remediated  → 0, 0
```

## Architecture observation: the account-aggregation pattern

This iteration introduces an asset type whose semantics
differ from the per-resource Cognito assets used by
Iterations 1-7:

- **Per-resource assets** (`aws_cognito_user_pool`,
  `aws_cognito_identity_pool`, `aws_cognito_user_pool_client`)
  fire one finding per actual AWS resource.
- **Account-aggregation asset** (`aws_cognito_account`) fires
  one finding for an account-region's whole monitoring
  posture, regardless of how many user pools exist in that
  account.

This is the right shape for monitoring controls — "no alarm
for `AdminCreateUser` API calls" is a property of the
account, not of any individual user pool. If three user pools
exist in the same account, you don't want three findings
reminding you to wire one alarm.

The aggregation lives in the collector. The collector queries
CloudWatch metric filters for the API operation, joins to
CloudWatch alarms, joins to CloudTrail to confirm the trail
captures the management events, and stamps the joined-up
boolean on the account asset. Same denormalisation pattern as
every prior iteration; the join is just three-table instead
of one-property.

## Why no compound chain

The plan listed 0 compound chains for Iteration 8 and the
catalog ships none. Each missing alarm is independently
actionable; "alarm X missing AND alarm Y missing" doesn't
escalate to a worse outcome than the sum. Future "monitoring
blindspot" compounds (similar to the existing
`cloudwatch_false_monitoring` chain at the broader
CloudWatch / CloudTrail layer) could compose this iteration's
findings with CloudTrail-side findings via `scope_field` on
account_id — but that's an integration with broader account-
posture iterations, not a Cognito-internal compound.

## What this iteration shipped

- **10 individual controls** for Cognito-management-event
  monitoring posture fire end-to-end on a single
  `aws_cognito_account` asset.
- **No compound chain** by design.
- **New asset type** (`aws_cognito_account`) introduces the
  account-aggregation pattern for monitoring controls.

No Stave engine changes required. Same trajectory as
Iterations 3-7 — catalog content + fixtures only.
