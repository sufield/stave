# Lab 06 — Findings

A finding is not an alert. It is a proof that a specific property does not
hold for a specific asset at a specific time.

## Anatomy of a Finding

Run the RED fixture and examine the full AUTHAGE finding:

```bash
stave apply \
  --observations internal/fixtures/labs/mfa-authage/bad/ \
  --eval-time 2026-08-19T14:00:00Z \
  --format json | jq '.findings[] | select(.control_id == "CTL.IAM.TRUST.MFA.AUTHAGE.001") | {control_id, asset_id, control_severity, evidence: {first_unsafe_at: .evidence.first_unsafe_at, unsafe_duration_hours: .evidence.unsafe_duration_hours}}'
```

```json
{
  "control_id": "CTL.IAM.TRUST.MFA.AUTHAGE.001",
  "asset_id": "arn:aws:iam::111122223333:role/MfaPresentOnly",
  "control_severity": "medium",
  "evidence": {
    "first_unsafe_at": "2026-08-19T12:00:00Z",
    "unsafe_duration_hours": 2
  }
}
```

Every finding includes: which control, which asset, how severe, when first
seen, and how long it has been unsafe.

## The Reasoning Trace

Each finding includes the predicate evaluation trace:

```bash
stave apply \
  --observations internal/fixtures/labs/mfa-authage/bad/ \
  --eval-time 2026-08-19T14:00:00Z \
  --format json | jq '.findings[] | select(.control_id == "CTL.IAM.TRUST.MFA.AUTHAGE.001") | .reasoning_trace'
```

```json
[
  {"predicate_expr": "identity.kind eq \"role\"", "observed_value": "role"},
  {"predicate_expr": "identity.trust_policy.has_mfa_condition eq true", "observed_value": true},
  {"predicate_expr": "identity.trust_policy.has_mfa_condition present", "observed_value": true},
  {"predicate_expr": "identity.trust_policy.has_multifactor_auth_age ne true", "observed_value": false}
]
```

The trace shows exactly which values were observed and how each predicate
clause evaluated. This is the proof — not a heuristic, not a score.

## Output Categories

The `stave apply` output has four arrays:

| Array | Meaning |
|-------|---------|
| `findings` | Breached threshold — property violated |
| `risk_signals` | Approaching threshold — not yet violated |
| `chain_findings` | Compound findings from chains (Lab 07) |
| `indeterminate` | Controls that could not evaluate (missing data) |

## Verify

Run the RED fixture and find the `remediation.action` field in the AUTHAGE
finding. It tells you exactly what to change.

Next: [Lab 07 — Chains](07-chains.md)
