# E2E Test: Access Point bypass — clean bucket, public AP

## Case summary

- **Pattern**: A bucket whose own controls evaluate clean (Block Public Access fully
  enforcing, policy not effectively public) can still be publicly reachable through
  a single-region S3 Access Point attached to it. The Access Point carries its own
  PAB and its own policy, evaluated independently of the parent bucket. This is a
  cross-resource compound pattern, not a single-resource misconfiguration.
- **Derivation-driven**: The `storage.exposure.has_public_access_point` field on the
  bucket is **not set in the observation JSON** — it's populated by the
  `EnrichBucketAPExposure` derivation in `internal/core/evaluation/derive/` from
  `aws_s3_access_point` observations in the same snapshot. The fixture exercises the
  full pipeline: raw observations → derivation → control evaluation.
- **Suppression rule**: `CTL.S3.AP.BYPASS.001` only fires when the bucket's own
  controls are clean. If the bucket is already publicly accessible via its own policy
  or PAB state, the bucket-level controls already caught it and the bypass finding
  would be noise. The fixture's `already-public-bucket` scenario verifies this
  suppression explicitly.

## Assets

| ID | Kind | `controls.public_access_fully_blocked` | `access.public_read` | `policy_is_public` (AP) | Fires |
|---|:---:|:---:|:---:|:---:|---|
| `clean-bucket-leaky-ap` | bucket | true | false | — | ✅ `AP.BYPASS.001` |
| `already-public-bucket` | bucket | false | true | — | ✅ `CONTROLS.001`, `PUBLIC.001` |
| `fully-clean-bucket` | bucket | true | false | — | — |
| `leaky-ap` → `clean-bucket-leaky-ap` | access_point | — | — | true | ✅ `AP.POLICY.001` |
| `already-public-ap` → `already-public-bucket` | access_point | — | — | true | ✅ `AP.POLICY.001` |
| `clean-ap` → `fully-clean-bucket` | access_point | — | — | false | — |

## Controls asserted

| Control | Severity | Fires on | Count |
|---------|:---:|---|:---:|
| `CTL.S3.AP.BYPASS.001` | critical | clean bucket + derived `has_public_access_point=true` | 1 |
| `CTL.S3.AP.POLICY.001` | critical | AP with public policy | 2 |
| `CTL.S3.CONTROLS.001` | high | bucket with PAB off | 1 |
| `CTL.S3.PUBLIC.001` | — | bucket with public_read | 1 |
| **Total** | | | **5** |

## Expected result

- Exit code: 3
- Findings: 5
- Assets evaluated: 6, unsafe: 4 (two buckets + two APs)

## Trace — the point of the fixture

The AP.BYPASS.001 finding on `clean-bucket-leaky-ap` is a compound finding that
does not exist in the raw observation data. Reconstructing how it was produced:

```
CTL.S3.AP.BYPASS.001 on bucket clean-bucket-leaky-ap
  ├─ storage.controls.public_access_fully_blocked == true   (raw observation)
  ├─ storage.access.policy_is_effectively_public == false   (raw observation)
  ├─ storage.exposure.has_public_access_point == true       (derived via
  │    derive.EnrichBucketAPExposure)
  │    └─ access_point leaky-ap: policy_is_public == true   (raw observation)
```

Every step is inspectable: the raw bucket observation, the raw AP observation,
the documented join rule, and the single predicate that ties them together. That
separation is what makes a "passing" bucket receiving a Critical finding
auditable rather than mysterious.

## Out of scope

- Cross-account AP → bucket joins. Access Points can target buckets in other
  accounts, and the current observation contract does not carry account
  identifiers on either side of the join. The derivation deliberately matches
  only within a single snapshot. When the multi-account story lands, the
  derivation gains an account-id condition on the match.
