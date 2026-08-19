# Lab 07 — Chains

Individual properties compose into compound findings. This is where the
"aha" happens.

## The Setup

You know that AUTHAGE.001 fires when MFA has no time-bounding. You know
that SESSION.DURATION.001 fires when session duration exceeds 4 hours. What
happens when both are true on the same role?

## The Chain

```bash
cat internal/chains/iam_mfa_theater.yaml
```

```yaml
id: iam_mfa_theater
description: >
  MFA theater — role requires MFA but the MFA provides no effective
  security. The trust policy uses MultiFactorAuthPresent without
  MultiFactorAuthAge (no time-bound re-authentication) AND the role
  allows a long MaxSessionDuration.
controls:
  - CTL.IAM.TRUST.MFA.AUTHAGE.001
  - CTL.IAM.SESSION.DURATION.001
escalation_threshold: 2
compound_severity: high
```

Two controls, threshold 2 — both must fire on the same asset for the chain
to produce a compound finding. Individual severity is medium. Compound
severity escalates to high.

## Run the MFA Theater Fixture

```bash
stave apply \
  --observations internal/fixtures/labs/mfa-theater/bad/ \
  --eval-time 2026-08-19T14:00:00Z \
  --format json | jq '{chain_findings: [.chain_findings[] | {chain, asset_id, severity, controls_failing}]}'
```

```json
{
  "chain_findings": [
    {
      "chain": "iam_mfa_theater",
      "asset_id": "arn:aws:iam::111122223333:role/MfaTheaterRole",
      "severity": "high",
      "controls_failing": [
        "CTL.IAM.TRUST.MFA.AUTHAGE.001",
        "CTL.IAM.SESSION.DURATION.001"
      ]
    }
  ]
}
```

Both controls fired. The chain composed them into a high-severity compound
finding. The role requires MFA, uses the weak form, and allows 12-hour
sessions. MFA theater.

## The Partial — One Leg Missing

```bash
stave apply \
  --observations internal/fixtures/labs/mfa-theater/partial/ \
  --eval-time 2026-08-19T14:00:00Z \
  --format json | jq '{chain_count: (.chain_findings | length), authage_count: [(.findings // [])[] | select(.control_id | test("AUTHAGE"))] | length}'
```

```json
{
  "chain_count": 0,
  "authage_count": 1
}
```

AUTHAGE.001 fires (no AuthAge), but SESSION.DURATION.001 does not (session
is 1 hour). Only one leg met — below the threshold. The chain does not fire.

The individual finding still reports the weak MFA. But the compound — the
MFA theater pattern — requires both: weak MFA AND long session.

## Verify

Explain why the chain catches something no individual control can: what
compound property does `iam_mfa_theater` prove that neither AUTHAGE.001
nor SESSION.DURATION.001 proves alone?

Next: [Lab 08 — Remediation](08-remediation.md)
