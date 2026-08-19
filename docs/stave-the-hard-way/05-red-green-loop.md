# Lab 05 — Red-Green Loop

A control is not trusted because someone wrote it. It is trusted because
fixtures prove it catches the bad state and passes the good state.

## RED — The Bad Fixture Fires

```bash
stave apply \
  --observations internal/fixtures/labs/mfa-authage/bad/ \
  --eval-time 2026-08-19T14:00:00Z \
  --format json | jq '.summary'
```

```json
{
  "total_assets": 1,
  "exposed_resources": 1,
  "violations": 1,
  "indeterminate": 11
}
```

One violation. Filter to confirm it is AUTHAGE.001:

```bash
stave apply \
  --observations internal/fixtures/labs/mfa-authage/bad/ \
  --eval-time 2026-08-19T14:00:00Z \
  --format json | jq '[.findings[] | select(.control_id == "CTL.IAM.TRUST.MFA.AUTHAGE.001") | .control_id]'
```

```json
["CTL.IAM.TRUST.MFA.AUTHAGE.001"]
```

The control fires on the bad fixture. RED confirmed.

## GREEN — The Clean Fixture Passes

```bash
stave apply \
  --observations internal/fixtures/labs/mfa-authage/clean/ \
  --eval-time 2026-08-19T14:00:00Z \
  --format json | jq '[(.findings // [])[] | select(.control_id == "CTL.IAM.TRUST.MFA.AUTHAGE.001")]'
```

```json
[]
```

Zero AUTHAGE findings. The clean fixture has `has_multifactor_auth_age: true`
— the MFA has a time-bound, so the control passes. GREEN confirmed.

## BOUNDARY — No MFA At All

```bash
stave apply \
  --observations internal/fixtures/labs/mfa-authage/no-mfa/ \
  --eval-time 2026-08-19T14:00:00Z \
  --format json | jq '[(.findings // [])[] | select(.control_id == "CTL.IAM.TRUST.MFA.AUTHAGE.001")]'
```

```json
[]
```

Zero findings. Why? The fixture has `has_mfa_condition: false`. The predicate
requires `has_mfa_condition eq true` — that clause fails, so the control does
not fire. A role with no MFA at all is caught by a different control
(CTL.IAM.TRUST.MFA.001), not this one. Each control owns its slice.

## Verify

Explain in one sentence why the boundary fixture passes AUTHAGE.001 but
would fail TRUST.MFA.001.

Next: [Lab 06 — Findings](06-findings.md)
