# E2E Test: Bucket policy evaluates as effectively public (PAB-independent)

## Case summary

- **Pattern**: S3 bucket policy evaluates as public under AWS `PolicyStatus.IsPublic`
  semantics — a wildcard principal Allow statement with no scoping Condition. The
  control (`CTL.S3.ACCESS.004`) fires on the policy in isolation, regardless of Public
  Access Block state. PAB does not silence the finding; it only separates the *active*
  case (PAB off — confirmed exposure) from the *latent* case (PAB on — one toggle away
  from exposure). Severity compounding between the two cases is the RiskEngine's job.
- **Modeled assets**: 3 synthetic buckets — one active-public (policy public, PAB off),
  one latent-public (policy public, PAB fully enforcing), and one scoped-policy
  (policy not public).
- **Regression guard**: `CTL.S3.ACCESS.004` fires on both public-policy buckets and
  stays silent on the scoped bucket. PAB state must not gate the control.

## Buckets

| ID | `access.policy_is_effectively_public` | `controls.public_access_fully_blocked` | Fires |
|----|:---:|:---:|:---:|
| `active-public` | `true` | `false` | ✅ ACCESS.004 (active — RiskEngine compounds to Critical) |
| `latent-public` | `true` | `true` | ✅ ACCESS.004 (latent — RiskEngine stays at High) |
| `scoped-policy` | `false` | — | — |

## Controls asserted

| Control | Severity | Fires on | Count |
|---------|:---:|---|:---:|
| `CTL.S3.ACCESS.004` | high | `policy_is_effectively_public=true` | 2 |

## Expected result

- Exit code: 3
- Findings: 2
- Buckets evaluated: 3, unsafe: 2

## Notes

This control is the verified-public counterpart to `CTL.S3.ACCESS.002`. ACCESS.002
answers "is there a wildcard principal whose Conditions still need verification?"
ACCESS.004 answers "has the verification already concluded that the policy is
public?". Both firing on the same bucket is expected and meaningful: the wildcard is
present AND it is not scoped. Only ACCESS.002 firing means "wildcard exists, scoping
Conditions make it not-public". Only ACCESS.004 firing is not possible under the
evaluator contract — effective-public requires a wildcard principal as a
precondition.
