# E2E Test: Non-narrow bucket policy grants without a scoping Condition

## Case summary

- **Pattern**: S3 bucket policy with at least one Allow statement whose Principal is
  non-narrow (`Principal: "*"`, `Principal: {"AWS": "*"}`, or an Allow with no Principal
  block) and no scoping Condition (`aws:PrincipalOrgID`, `aws:SourceVpc`, `aws:SourceIp`
  with a fixed CIDR, or `aws:SourceArn`). Posture hardening gap — the effective
  principal set is the whole internet (or every AWS account) until a Condition narrows
  it.
- **Modeled assets**: 4 synthetic buckets covering the one fail case and the three pass
  cases documented in the control.
- **Regression guard**: `CTL.S3.POLICY.SCOPING.001` fires only on the unscoped bucket
  and stays silent on the scoped bucket, the bucket with no policy (field absent), and
  the bucket with only narrow-principal Allows (field `null`).

## Buckets

| ID | `access.policy_has_scoping_condition` | Fires |
|----|:---:|:---:|
| `unscoped-wildcard` | `false` | ✅ POLICY.SCOPING.001 |
| `org-scoped-wildcard` | `true` | — |
| `no-policy` | absent | — |
| `narrow-principals-only` | `null` | — |

## Controls asserted

| Control | Severity | Fires on | Count |
|---------|:---:|---|:---:|
| `CTL.S3.POLICY.SCOPING.001` | medium | `policy_has_scoping_condition=false` (posture) | 1 |

## Expected result

- Exit code: 3
- Findings: 1
- Buckets evaluated: 4, unsafe: 1

## Notes

The predicate uses `op: present, value: true` before `op: eq, value: false`. Present
treats both omitted keys and explicit `null` values as missing, so the control stays
cleanly silent on the "nothing to scope" states without producing the inconclusive
warn-log that a bare `eq false` would emit against an explicit `null`.
