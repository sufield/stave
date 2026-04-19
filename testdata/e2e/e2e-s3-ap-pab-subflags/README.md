# E2E Test: S3 Access Point Public Access Block per-sub-flag predicates

## Case summary

- **Pattern**: symmetric to the bucket-level `e2e-s3-pab-subflags` fixture.
  The umbrella `CTL.S3.AP.PAB.001` fires when any of the four flags under
  `storage.public_access_block.*` is `false`, but does not tell the
  operator which one. Prowler and ScoutSuite report each flag
  independently so the remediation is a one-command fix targeted at the
  specific flag. This fixture exercises four new per-flag controls that
  sit alongside the umbrella — both layers fire, giving operators who
  want the aggregate signal the umbrella and operators who want specific
  remediation guidance the per-flag finding.
- **Controls exercised**: the four per-flag controls plus the umbrella,
  loaded together so the fixture verifies both layers light up on the
  intended Access Points.

## Access Points

| ID | block_public_acls | ignore_public_acls | block_public_policy | restrict_public_buckets | `public_access_fully_blocked` | Fires |
|---|:---:|:---:|:---:|:---:|:---:|---|
| `fully-blocked-ap` | true | true | true | true | true | — |
| `missing-block-public-acls-ap` | **false** | true | true | true | false | umbrella + `BLOCKPUBLICACLS` |
| `missing-ignore-public-acls-ap` | true | **false** | true | true | false | umbrella + `IGNOREPUBLICACLS` |
| `missing-block-public-policy-ap` | true | true | **false** | true | false | umbrella + `BLOCKPUBLICPOLICY` |
| `missing-restrict-public-buckets-ap` | true | true | true | **false** | false | umbrella + `RESTRICTPUBLICBUCKETS` |
| `all-flags-off-ap` | **false** | **false** | **false** | **false** | false | umbrella + all four sub-flag controls |

## Controls asserted

| Control | Severity | Fires on | Count |
|---------|:---:|---|:---:|
| `CTL.S3.AP.PAB.001` (umbrella) | critical | `public_access_fully_blocked=false` | 5 |
| `CTL.S3.AP.PAB.BLOCKPUBLICACLS.001` | high | `public_access_block.block_public_acls=false` | 2 |
| `CTL.S3.AP.PAB.IGNOREPUBLICACLS.001` | high | `public_access_block.ignore_public_acls=false` | 2 |
| `CTL.S3.AP.PAB.BLOCKPUBLICPOLICY.001` | high | `public_access_block.block_public_policy=false` | 2 |
| `CTL.S3.AP.PAB.RESTRICTPUBLICBUCKETS.001` | high | `public_access_block.restrict_public_buckets=false` | 2 |
| **Total** | | | **13** |

## Expected result

- Exit code: 3 (violations present)
- Findings: 13
- Exposed Access Points: 5 (only `fully-blocked-ap` stays clean)
