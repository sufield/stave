# E2E Test: Object-scoped public grant discrimination (Reju Kole Gap B)

## Case summary

- **Pattern**: bucket policy grants public read to one or more **specific object
  keys** (e.g. `arn:aws:s3:::bucket/backup.xlsx`) rather than a bucket-wide
  pattern. This is the configuration Reju Kole disclosed in January 2026 —
  an object-scoped grant on `backup.xlsx` that surfaced in a publicly
  readable bucket policy, leading to offline password crack and credential
  leak. Prowler and Pacu both treat object-scoped grants as a distinct
  finding class from bucket-wide public access.
- **Control**: `CTL.S3.POLICY.OBJECTSCOPED.001` — medium severity, posture-
  level. Fires on `storage.access.public_read_scope in ["object", "mixed"]`.
- **Contract extension**: `storage.access.public_read_scope` added as a
  string/null enum with values `"bucket"`, `"prefix"`, `"object"`, `"mixed"`.
  Null/absent when `public_read = false`.

## Buckets

| ID | `public_read` | `public_read_scope` | Fires |
|---|:---:|:---:|:---:|
| `reju-kole-backup-bucket` | true | `object` | ✅ `POLICY.OBJECTSCOPED.001` (Reju Kole configuration) |
| `mixed-scope-bucket` | true | `mixed` | ✅ `POLICY.OBJECTSCOPED.001` (one statement names both bucket/* and specific keys) |
| `bucket-wide-public` | true | `bucket` | — (caught by `CTL.S3.PUBLIC.001` on `public_read`, not by this control) |
| `public-assets-prefix` | true | `prefix` | — (published-assets prefix is the intended pattern; this control stays silent) |
| `fully-private-bucket` | false | — | — |

## Controls asserted

| Control | Severity | Fires on | Count |
|---------|:---:|---|:---:|
| `CTL.S3.POLICY.OBJECTSCOPED.001` | medium | `kind=bucket AND public_read_scope in ["object", "mixed"]` | 2 |

## Expected result

- Exit code: 3
- Findings: 2
- Assets evaluated: 5, unsafe: 2

## Notes

The fixture's `reju-kole-backup-bucket` carries `public_read_scope = "object"`
as the upstream-computed value. Upstream derivation inspects each Allow
statement with a non-narrow principal: if every such statement's Resource
enumerates specific object keys (no `bucket/*` patterns), scope is
`"object"`. A single statement mixing bucket-wide and object-specific
Resources collapses to `"mixed"`.

Why medium and not high: object-scoped public grants are a legitimate
pattern for individually-published documents. PDFs, binaries, and static
files pinned to specific keys are valid use cases. Firing at high severity
would produce false positives at scale. When the target bucket carries
`storage.tags.data-classification in [phi, pii, confidential]`,
`CTL.S3.PUBLIC.002` already fires at high severity on the composite
signal — this control covers the untagged case.

This fixture loads `CTL.S3.POLICY.OBJECTSCOPED.001` in isolation to
keep the finding set focused. In a full catalog run, the bucket-wide
and prefix buckets would also fire `CTL.S3.PUBLIC.001` / `.004` on
`public_read = true`, which is correct — the object-scoped control
does not duplicate or replace those findings, it adds a distinct
posture signal about scope shape.

## Deferred

- **File-extension sensitivity signal** (e.g. `.xlsx`, `.sql`, `.mdb`, `.db`)
  is not in the contract. If it were, a compound high-severity control
  could fire on object-scoped public grants that target likely-data file
  extensions — matching Reju Kole's exact attack profile. This would need
  a contract field (something like
  `storage.access.public_object_extensions: string[]`) and is a follow-up
  iteration, not part of this one.
- Structured `public_read_grants[]` (Shape A in the design discussion).
  Not chosen here because the `storage.access.*` namespace is uniformly
  derived scalars with zero structured-object-array precedents. If a
  future iteration needs per-grant principal/action/resource querying,
  the structured shape can coexist with the scope enum; the enum
  continues to serve as the aggregate signal.
