# E2E Test: Single-region S3 Access Points

## Case summary

- **Resource kind**: `aws_s3_access_point` — a new resource kind with discriminator
  `storage.kind = "access_point"`. Mirrors MRAP's field semantics (`public_access_block.*`,
  `public_access_fully_blocked`, `policy_is_public`) but sits as a top-level asset
  rather than as a sub-field on the parent bucket.
- **Pattern**: Access Points carry their own PAB and their own resource policy,
  both evaluated independently of the parent bucket's controls. A bucket that
  is hardened at the bucket level can still be reached through a
  misconfigured Access Point attached to it.
- **Regression guard**: `CTL.S3.AP.PAB.001` and `CTL.S3.AP.POLICY.001` mirror
  the MRAP control family for single-region APs. Both at Critical severity.

## Access Points

| ID | `public_access_fully_blocked` | `policy_is_public` | `network_origin` | Fires |
|----|:---:|:---:|:---:|:---:|
| `pass-pab-enabled` | true | false | internet | — |
| `pass-scoped-policy` | true | false | internet | — |
| `pass-vpc-only` | true | false | vpc | — |
| `fail-pab-disabled` | false | false | internet | ✅ AP.PAB.001 |
| `fail-wildcard-policy` | true | true | internet | ✅ AP.POLICY.001 |
| `fail-internet-broad` | false | true | internet | ✅ AP.PAB.001 + AP.POLICY.001 |

## Controls asserted

| Control | Severity | Fires on | Count |
|---------|:---:|---|:---:|
| `CTL.S3.AP.PAB.001` | critical | `kind=access_point AND public_access_fully_blocked=false` | 2 |
| `CTL.S3.AP.POLICY.001` | critical | `kind=access_point AND policy_is_public=true` | 2 |
| **Total** | | | **4** |

## Expected result

- Exit code: 3
- Findings: 4
- Assets evaluated: 6, unsafe: 3

## Notes

`aws_s3_access_point` is a new asset type whose `source_type` is not in the
extractor allowlist; Stave accepts custom or unknown source types by default,
so no extra flag is needed. This matches CLAUDE.md's guidance on custom
observation source types.

The bucket-side namespace for MRAP remains intact (`storage.mrap_*` on the bucket
asset); single-region Access Points are modeled as their own asset because each
bucket can have many of them with independent configurations. The per-resource
shape makes the compound finding that Gap 2 motivated —
**AP.POLICY.001 fires on an AP while the parent bucket's own controls are clean** —
expressible in a future iteration.
