# Lab 08 — Remediation

The control tells you what to change. `stave check` proves you changed it.

## The Remediation Block

From CTL.IAM.TRUST.MFA.AUTHAGE.001:

```yaml
remediation:
  description: >
    Trust policy requires MFA but uses only aws:MultiFactorAuthPresent
    (boolean). The MFA has no time-bound — a single TOTP code grants
    a session for the full MaxSessionDuration with no re-authentication.
  action: >
    Add an aws:MultiFactorAuthAge condition to the trust policy.
    Example: "Condition": {"NumericLessThan":
    {"aws:MultiFactorAuthAge": "3600"}}.
```

Not "figure it out." An exact condition to add, with the recommended value
(3600 seconds = 1 hour).

## The Fix

Compare the bad fixture with the clean fixture:

```bash
diff <(jq '.assets[0].properties' internal/fixtures/labs/mfa-authage/bad/2026-08-19T120000Z.json) \
     <(jq '.assets[0].properties' internal/fixtures/labs/mfa-authage/clean/2026-08-19T120000Z.json)
```

```diff
<           "has_multifactor_auth_age": false,
---
>           "has_multifactor_auth_age": true,
```

One field changed. `false` to `true`. In AWS terms: you added
`aws:MultiFactorAuthAge` to the trust policy Condition block.

## Verify the Fix

```bash
stave check \
  --before internal/fixtures/labs/mfa-authage/bad/ \
  --after internal/fixtures/labs/mfa-authage/clean/ \
  --controls internal/controls \
  --eval-time 2026-08-19T14:00:00Z \
  2>/dev/null | jq '.summary'
```

```json
{
  "previous_violations": 1,
  "current_violations": 0,
  "remediated": 1,
  "open": 0,
  "regressions": 0
}
```

`remediated: 1, regressions: 0`. The fix resolved the finding without
introducing new violations. This is proof, not hope.

## The Loop

1. `stave apply` — find the violation
2. Read `remediation.action` — know what to change
3. Make the change
4. `stave check --before bad/ --after fixed/` — prove it worked

## Verify

Run `stave check` yourself with the before/after paths above. Confirm
`regressions: 0`.

Next: [Lab 09 — Drift Detection](09-drift-detection.md)
