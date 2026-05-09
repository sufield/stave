# Cognito Iteration 5 — Identity Pool Authenticated Role

End-to-end fixtures for the Iteration 5 authenticated-role
over-privilege controls plus the `cognito_authrole_escalation`
compound chain. Single asset type (`aws_cognito_identity_pool`),
single-asset chain composition — same simple shape as
Iterations 3 and 4.

```
7 individual controls   (writeup → all fire ; remediated → 0)
1 compound chain        (cognito_authrole_escalation)
```

## Controls covered

All 7 evaluate on a single `cognito_identity_pool` asset.
Each predicate reduces to a pre-computed boolean stamped by
the collector after evaluating the auth role's IAM policy
shape.

| Control | Predicate signal |
|---|---|
| `CTL.COGNITO.IDPOOL.AUTHROLE.BROAD.001`        | `auth_role_broad == true` (>20 actions or wildcard) |
| `CTL.COGNITO.IDPOOL.AUTHROLE.PASSROLE.001`     | `auth_role_has_passrole == true` |
| `CTL.COGNITO.IDPOOL.AUTHROLE.ASSUMEROLE.001`   | `auth_role_can_escalate_via_assume == true` |
| `CTL.COGNITO.IDPOOL.AUTHROLE.CROSSACCT.001`    | `auth_role_has_cross_account == true` |
| `CTL.COGNITO.IDPOOL.ROLEMAPPING.NONE.001`      | `has_role_mapping == false` |
| `CTL.COGNITO.IDPOOL.CLASSICFLOW.001`           | `allow_classic_flow == true` |
| `CTL.COGNITO.IDPOOL.PROVIDER.NOVALIDATION.001` | `provider_validates_audience == false` |

## Compound chain

| Chain | Members | Threshold | Compound severity |
|---|---|---|---|
| `cognito_authrole_escalation` | PASSROLE, ASSUMEROLE, BROAD, ROLEMAPPING.NONE | 2 | critical |

The chain is the marketing-grade headline: "any signed-in user
is one or two API calls away from arbitrary privileges." Fires
on the writeup fixture (4 of 4 members hit, threshold 2 met).

## Run

```bash
cd <repo-root>/stave
make build

./stave apply \
    --observations examples/cognito-iteration5-authrole/fixtures/writeup-config/observations \
    --now 2026-05-09T12:00:00Z --allow-unknown-input --format json \
  | jq '{ctls: ([.findings[] | select(.control_id | test("CTL.COGNITO.IDPOOL.(AUTHROLE|ROLEMAPPING|CLASSICFLOW|PROVIDER)"))] | map(.control_id) | sort | unique), chains: (.chain_findings // [] | map(.chain) | sort | unique)}'

./stave apply \
    --observations examples/cognito-iteration5-authrole/fixtures/remediated-config/observations \
    --now 2026-05-09T12:00:00Z --allow-unknown-input --format json \
  | jq '{ctls: ([.findings[] | select(.control_id | test("CTL.COGNITO.IDPOOL.(AUTHROLE|ROLEMAPPING|CLASSICFLOW|PROVIDER)"))] | length), chains: (.chain_findings // [] | length)}'
```

Expected:

```
writeup     → 7 ctls, 1 chain
remediated  → 0, 0
```

## Catalog observation: SAMEROLE collapsed into ROLEMAPPING.NONE

The Iteration 5 plan called for 8 controls; the catalog ships
7 because `CTL.COGNITO.IDPOOL.SAMEROLE.001` ("same role for
all authenticated users") was folded into
`CTL.COGNITO.IDPOOL.ROLEMAPPING.NONE.001`. The semantics
overlap: when no role mapping is configured, every authenticated
user receives the default `auth_role`, which IS the
"same-role-for-all" condition.

This is a clean simplification — one boolean covers both
checks. The plan's 5.2.5 / 5.2.6 split is more useful as a
remediation distinction than as two separate detection
controls. Out of scope to add SAMEROLE.001 here; flag for
catalog content review only if operators surface a need to
distinguish the two states (e.g. for a future "near-miss"
narrative where role mapping IS configured but mapped to one
role for everyone).

## What this iteration shipped

- **7 individual controls** for authenticated-role
  over-privilege fire end-to-end on a single identity-pool
  asset.
- **`cognito_authrole_escalation` compound** composes the four
  escalation primitives via legacy `asset.ID` grouping (no
  scope_field needed). On the writeup fixture all 4 members
  hit; on remediated none do.

No Stave engine changes required. Same trajectory as
Iterations 3 and 4 — catalog content + fixtures only.
