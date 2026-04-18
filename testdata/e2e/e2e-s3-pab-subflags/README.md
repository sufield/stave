# E2E Test: S3 Public Access Block per-sub-flag predicates

## Case summary

- **Pattern**: the existing umbrella PAB control (`CTL.S3.CONTROLS.001`) fires
  when any of the four sub-flags under `storage.controls.public_access_block.*`
  is `false`, but does not tell the operator which one. Prowler and ScoutSuite
  report each flag independently so the remediation is a one-command fix
  targeted at the specific flag. This fixture exercises four new per-flag
  controls that sit alongside the umbrella — both layers fire, giving
  operators who want the aggregate signal the umbrella and operators who
  want specific remediation guidance the per-flag finding.
- **Controls exercised**: the four per-flag controls plus the umbrella,
  loaded together so the fixture verifies both layers light up on the
  intended buckets.

## Buckets

| ID | block_public_acls | ignore_public_acls | block_public_policy | restrict_public_buckets | `public_access_fully_blocked` | Fires |
|---|:---:|:---:|:---:|:---:|:---:|---|
| `fully-blocked-bucket` | true | true | true | true | true | — |
| `missing-block-public-acls` | **false** | true | true | true | false | umbrella + `BLOCKPUBLICACLS` |
| `missing-ignore-public-acls` | true | **false** | true | true | false | umbrella + `IGNOREPUBLICACLS` |
| `missing-block-public-policy` | true | true | **false** | true | false | umbrella + `BLOCKPUBLICPOLICY` |
| `missing-restrict-public-buckets` | true | true | true | **false** | false | umbrella + `RESTRICTPUBLICBUCKETS` |
| `all-flags-off-bucket` | **false** | **false** | **false** | **false** | false | umbrella + all four sub-flag controls |

## Controls asserted

| Control | Severity | Fires on | Count |
|---------|:---:|---|:---:|
| `CTL.S3.CONTROLS.001` (umbrella) | high | `public_access_fully_blocked=false` | 5 |
| `CTL.S3.PAB.BLOCKPUBLICACLS.001` | high | `public_access_block.block_public_acls=false` | 2 |
| `CTL.S3.PAB.IGNOREPUBLICACLS.001` | high | `public_access_block.ignore_public_acls=false` | 2 |
| `CTL.S3.PAB.BLOCKPUBLICPOLICY.001` | high | `public_access_block.block_public_policy=false` | 2 |
| `CTL.S3.PAB.RESTRICTPUBLICBUCKETS.001` | high | `public_access_block.restrict_public_buckets=false` | 2 |
| **Total** | | | **13** |

## Expected result

- Exit code: 3
- Findings: 13
- Assets evaluated: 6, unsafe: 5

## Notes

Control ID spelling: the task suggested underscored ids like
`CTL.S3.PAB.BLOCK_PUBLIC_ACLS.001`. Stave's control ID validator requires
dot-separated uppercase segments with no underscores (see the error
message from the loader), so the ids collapse to
`CTL.S3.PAB.BLOCKPUBLICACLS.001` etc. This matches existing precedent
like `CTL.IAM.ESCALATE.ATTACHUSERPOLICY.001`,
`CTL.IAM.ESCALATE.CREATEACCESSKEY.001`, and
`CTL.IAM.ESCALATE.UPDATELOGINPROFILE.001` — all concatenated caps, no
underscores. The contract field names (`block_public_acls` etc.) keep
snake case, as is convention for observation-field paths.

Two-layer coverage is intentional. Operators who want the aggregate PAB
signal keep using `CTL.S3.CONTROLS.001`; operators who want the specific
flag to remediate get the corresponding `CTL.S3.PAB.*` finding. Neither
supersedes the other — the overlap is the point.

The all-four-off bucket fires five controls (umbrella + four sub-flag),
generating the densest finding cluster. This is a common state on
freshly-created buckets that predate an organization's PAB adoption, and
the fixture documents that this state produces the full set of findings
so operators can plan bulk remediation accordingly.
