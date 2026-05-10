# Cognito Iteration 6 — Advanced Security Features

End-to-end fixtures for the Iteration 6 advanced-security /
verification / custom-domain controls. No compound chain defined
for this iteration — each control stands alone as a baseline-
hygiene check.

```
6 individual controls   (writeup → all fire ; remediated → 0)
0 compound chains       (none defined for this iteration)
```

## Controls covered

The plan called for 8 controls; the catalog ships 6.
ADVSEC.AUDITONLY (audit-only mode, distinct from off) and
ADVSEC.COMPCREDS (compromised-credentials specifically) are
folded into the on/off check `ADVANCED.SECURITY.001`.

| Control | Predicate signal |
|---|---|
| `CTL.COGNITO.ADVANCED.SECURITY.001` | `advanced_security.enabled == false` |
| `CTL.COGNITO.ADVSEC.DEVICETRACK.001`| `cognito.device_tracking_enabled == false` |
| `CTL.COGNITO.VERIFY.EMAIL.001`      | `cognito.email_auto_verified == false` |
| `CTL.COGNITO.VERIFY.PHONE.001`      | `cognito.mfa_sms_enabled == true AND cognito.phone_auto_verified == false` |
| `CTL.COGNITO.DOMAIN.HTTPS.001`      | `cognito.domain_enforces_https == false` |
| `CTL.COGNITO.DOMAIN.CERTEXPIRY.001` | `cognito.custom_domain_cert_expired == true` |

## Run

```bash
cd <repo-root>/stave
make build

./stave apply \
    --observations examples/cognito-iteration6-advsec/fixtures/writeup-config/observations \
    --now 2026-05-09T12:00:00Z --allow-unknown-input --format json \
  | jq '{ctls: ([.findings[] | select(.control_id | test("CTL.COGNITO.(ADVANCED|ADVSEC|VERIFY|DOMAIN)"))] | map(.control_id) | sort | unique), chains: (.chain_findings // [] | map(.chain))}'

./stave apply \
    --observations examples/cognito-iteration6-advsec/fixtures/remediated-config/observations \
    --now 2026-05-09T12:00:00Z --allow-unknown-input --format json \
  | jq '{ctls: ([.findings[] | select(.control_id | test("CTL.COGNITO.(ADVANCED|ADVSEC|VERIFY|DOMAIN)"))] | length), chains: (.chain_findings // [] | length)}'
```

Expected:

```
writeup     → 6 ctls, 0 chains
remediated  → 0, 0
```

## Catalog observation: `kind` discriminator inconsistency

The fixture splits its observation across **two user-pool
asset entries** because the catalog uses two different `kind`
discriminators on `aws_cognito_user_pool` properties:

- `kind: user_pool` — used by ADVANCED.SECURITY, DEVICETRACK,
  VERIFY.EMAIL, VERIFY.PHONE, MFA.001 (Iteration 3),
  PASSWORD.001 (Iteration 3), LOCKOUT.NONE.001, SELFREG.001.
- `kind: cognito_user_pool` — used by DOMAIN.HTTPS,
  DOMAIN.CERTEXPIRY, the Iteration 1 ghost-trigger family
  (PRESIGNUP, PREAUTH, …), SAMLMETA, DOMAINCERT, DOMAINDNS.

A single user-pool asset can only declare one `kind` value, so
fixtures that need to fire controls from both groups need
two asset entries. In production this means the collector
emits two observation entries per user pool — one with each
`kind` value — which is wasteful but works.

This is the same kind of catalog-content gap that was closed
in the Iteration 3 dedup pass (`PASSWORD.001` ↔
`PASSWORD.POLICY.001` and `MFA.001` ↔ `MFA.ENFORCE.001` —
each pair retired the duplicate, kept the canonical path).
The `kind` split here would be fixed the same way: pick ONE
canonical value and migrate the predicates. Out of scope for
the Iteration 6 fixture build; flagged for the broader
auth-baseline / catalog-content review.

## Catalog observation: ADVSEC subdivisions

The plan's three advanced-security states (OFF / AUDIT /
ENFORCED) collapse into one `enabled == false` check. The
catalog cannot distinguish "audit-mode-only" (advanced security
runs but doesn't block — a real misconfiguration) from "fully
off" (worse). To restore granularity, add:

- `CTL.COGNITO.ADVSEC.AUDITONLY.001` reading
  `advanced_security.mode == "AUDIT"`
- `CTL.COGNITO.ADVSEC.COMPCREDS.001` reading
  `advanced_security.compromised_credentials_action == "NONE"`

Both fit the per-asset boolean pattern of the existing
controls. Out of scope here; flagged for the auth-baseline
content review (same review queue as Iteration 3's gap).

## What this iteration shipped

- **6 individual controls** for advanced-security /
  verification / custom-domain configuration fire end-to-end.
- **No compound chain** is needed for this set — each finding
  represents a baseline-hygiene check that's independently
  actionable.

No Stave engine changes required. Same trajectory as
Iterations 3, 4, 5 — catalog content + fixtures only.
