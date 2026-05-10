# Cognito Iteration 3 — Password Policy and MFA (Auth Baseline)

End-to-end fixtures for the Iteration 3 authentication-baseline
controls plus the two compound chains. Single asset type
(`aws_cognito_user_pool`), single-asset chain composition — no
`scope_field` needed, no marker controls needed. The simplest
iteration in the gap-closure plan.

```
6 individual controls   (4 fire on writeup, 2 fire on recovery-bypass; remediated = 0)
2 compound chains       (cognito_weakauth, cognito_recoverybypass)
```

## Controls covered

All 6 fire on a single `aws_cognito_user_pool` asset. Compound
chains compose them via legacy `asset.ID` grouping.

| Control | Predicate signal |
|---|---|
| `CTL.COGNITO.PASSWORD.001`         | `password_policy.is_weak == true` |
| `CTL.COGNITO.MFA.001`              | `auth.mfa_enforced == false` |
| `CTL.COGNITO.MFA.SMSONLY.001`      | `cognito.mfa_sms_only == true` |
| `CTL.COGNITO.RECOVERY.NOMFA.001`   | `auth.mfa_enforced == true AND cognito.recovery_bypasses_mfa == true` |
| `CTL.COGNITO.LOCKOUT.NONE.001`     | `cognito.has_brute_force_protection == false` |
| `CTL.COGNITO.SELFREG.001`          | `governance.self_registration_restricted == false` |

## Compound chains

| Chain | Members | Threshold | Fires on |
|---|---|---|---|
| `cognito_weakauth`        | PASSWORD.001, MFA.001, LOCKOUT.NONE.001 | 2 | writeup-config (3 of 3) |
| `cognito_recoverybypass`  | RECOVERY.NOMFA.001, MFA.SMSONLY.001, MFA.001 | 2 | recovery-bypass-config (2 of 3) |

`cognito_recoverybypass` lists `MFA.001` as a member, but
`MFA.001` (`mfa_enforced == false`) and `RECOVERY.NOMFA.001`
(`mfa_enforced == true AND recovery_bypasses_mfa == true`) make
opposite assertions about `mfa_enforced` — they cannot fire on
the same asset. The chain practically composes
`RECOVERY.NOMFA.001 + MFA.SMSONLY.001` (both fire when MFA is
enforced + SMS-only + recovery bypass enabled).

## Run

```bash
cd <repo-root>/stave
make build

# Writeup: weak password + MFA disabled + no lockout + open self-reg
./stave apply \
    --observations examples/cognito-iteration3-authbaseline/fixtures/writeup-config/observations \
    --now 2026-05-09T12:00:00Z --allow-unknown-input --format json \
  | jq '{ctls: ([.findings[] | select(.control_id | test("CTL.COGNITO.(PASSWORD|MFA|LOCKOUT|SELFREG|RECOVERY)"))] | map(.control_id) | sort | unique), chains: (.chain_findings // [] | map(.chain) | sort)}'

# Recovery bypass: MFA enforced but SMS-only + recovery bypasses
./stave apply \
    --observations examples/cognito-iteration3-authbaseline/fixtures/recovery-bypass-config/observations \
    --now 2026-05-09T12:00:00Z --allow-unknown-input --format json \
  | jq '{ctls: ([.findings[] | select(.control_id | test("CTL.COGNITO.(PASSWORD|MFA|LOCKOUT|SELFREG|RECOVERY)"))] | map(.control_id) | sort | unique), chains: (.chain_findings // [] | map(.chain) | sort)}'

# Remediated: strong everything
./stave apply \
    --observations examples/cognito-iteration3-authbaseline/fixtures/remediated-config/observations \
    --now 2026-05-09T12:00:00Z --allow-unknown-input --format json \
  | jq '{ctls: ([.findings[] | select(.control_id | test("CTL.COGNITO.(PASSWORD|MFA|LOCKOUT|SELFREG|RECOVERY)"))] | length), chains: (.chain_findings // [] | length)}'
```

Expected:

```
writeup           → ctls: [PASSWORD.001, MFA.001, LOCKOUT.NONE.001, SELFREG.001], chains: [cognito_weakauth]
recovery-bypass   → ctls: [MFA.SMSONLY.001, RECOVERY.NOMFA.001], chains: [cognito_recoverybypass]
remediated        → ctls: 0, chains: 0
```

## Catalog observations

### Rolled-up booleans (intentional)

The original Iteration 3 plan called for 12 controls; the
catalog ships 6 because password and MFA properties are
pre-computed boolean rollups by design:

| Plan asked for | Catalog ships |
|---|---|
| PASSWORD.MINLENGTH, PASSWORD.UPPERCASE, PASSWORD.LOWERCASE, PASSWORD.NUMBERS, PASSWORD.SYMBOLS | `PASSWORD.001` (single `is_weak` rollup) |
| MFA.DISABLED, MFA.OPTIONAL | `MFA.001` (single `mfa_enforced == false`) — does not distinguish OFF vs OPTIONAL |
| PASSWORD.TEMPEXPIRY | `TEMPPASSWORD.001` (`temp_password_valid_days_exceeded`) |

This is the same denormalisation pattern Iteration 2's
`unauth_role_has_s3` boolean uses. The collector evaluates the
specific conditions and stamps a rollup; Stave reads the
rollup. **The tradeoff is intentional:** simpler catalog (one
control fires on weak-password configs of any shape), at the
cost of triage granularity (the finding doesn't say *which*
char-class is missing — operators inspect the observation's
`password_policy` object directly). The decision is documented
in `CTL.COGNITO.PASSWORD.001`'s description.

## What this iteration shipped

- **6 individual controls** fire end-to-end on realistic
  observation data, no engine changes required. Compound
  chains use legacy asset.ID grouping (no scope_field).
- **WEAKAUTH compound** is the marketing-grade headline: "MFA
  off + 6-character passwords + no lockout = brute-forceable
  in minutes." Fires on the writeup fixture as severity:
  critical, score: 100.
- **RECOVERYBYPASS compound** demonstrates that "MFA enforced"
  on its own is theatre when the recovery flow bypasses it —
  the second-most-reported authentication misconfiguration in
  identity audits.

No Stave engine changes needed. Iteration 3 closes purely on
catalog content + fixtures. The originally-flagged duplicates
(`PASSWORD.POLICY.001`, `MFA.ENFORCE.001`) were retired in a
follow-up; canonical paths are `password_policy.is_weak` and
`auth.mfa_enforced`.
