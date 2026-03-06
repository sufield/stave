# Justification: CTL.S3.WRITE.SCOPE.001 and Deviations from case-studies/11-prompt.md

## Why this control is needed

No existing control covers signed upload policy scope. The closest are:

| Control | What it checks | Gap |
|-----------|---------------|-----|
| **CTL.S3.PUBLIC.003** | `public_write == true` on a bucket | Flags *who* can write, not *how broad* the write scope is. A private bucket passes this. |
| **CTL.S3.ACCESS.003** | `has_external_write == true` | Flags external account write access. Does not inspect upload policy scope. |
| **CTL.S3.TENANT.ISOLATION.001** | Identity-level prefix enforcement on presigned URLs via `any_match` | Checks for path traversal / `enforce_prefix=false` on *identity* objects, not policy resources. |

CTL.S3.WRITE.SCOPE.001 covers a distinct attack surface: whether a signed upload
policy binds writes to an exact object key vs. a prefix wildcard. A private bucket
with no public write flags would pass all existing controls while still being
vulnerable to the HackerOne #93691 pattern (broad `starts-with` scope in the
upload policy).

## Deviations from case-studies/11-prompt.md

## 1. `field: type` predicate does not access top-level resource fields

**Prompt specified:**
```yaml
- field: type
  op: eq
  value: "s3_upload_policy"
```

**Problem:** The predicate engine resolves all field paths against `resource.Properties`, not the top-level resource struct. The code in `internal/domain/unsafe_predicate_fields.go` strips a `properties.` prefix if present, then looks up the remaining path in `Properties`. So `field: type` resolves to `Properties["type"]`, not `Resource.Type`.

The top-level `Resource.Type` field is only accessible in identity contexts (via `identityToMap()` in `unsafe_predicate_eval.go`), not in resource evaluation contexts (`NewResourceEvalContext` in `unsafe_predicate_eval_context.go` passes only `r.Properties`).

**Fix:** Added `"type": "s3_upload_policy"` inside the resource's `properties` map so the predicate resolves correctly. The `properties` map is free-form in obs.v0.1, so no schema change is needed.

## 2. Observation dates changed from 2015 to 2026

**Prompt specified:**
- T1: `2015-10-13T00:00:00Z`
- T2: `2015-10-20T00:00:00Z`

**Problem:** The e2e.sh test harness passes `--now 2026-01-11T00:00:00Z` (hardcoded). Stave clamps `now` to the latest observation timestamp when `--now` exceeds it. With a latest observation at 2015-10-20, `now` becomes 2015-10-20. The unsafe duration from T1 to T2 is exactly 168 hours, which does not exceed the 168h threshold (the comparison is strictly greater than).

**Fix:** Used `2026-01-01T00:00:00Z` and `2026-01-11T00:00:00Z` to match the e2e.sh `--now` value. This gives 240h unsafe duration, exceeding the 168h threshold.

## 3. Both snapshots show unsafe state (no T2 fix)

**Prompt specified:** T2 should show the fix (`allowed_key_mode: "exact"`).

**Problem:** Stave only reports violations for resources that are attack surface at the latest snapshot. If the resource is safe at T2, `attack_surface = 0` and `violations = 0` regardless of T1 state. This was confirmed empirically during the earlier e2e-h1-shopify-57505 implementation — a resource safe at T2 with unsafe T1 produced exit code 0 and empty findings.

**Fix:** Both snapshots show the unsafe prefix-mode policy. The README notes that the real-world remediation (binding to exact key) occurred after the observation window.
