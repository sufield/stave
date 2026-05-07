# Example — S3 Tenant Prefix Isolation

Demonstrates the `s3-tenant-prefix-isolation` pattern using
both **CEL** (`pkg/stave`) and **Z3** (the
`aclements/go-z3` binding). Pattern P5 in
[`examples-plan.md`](../../../examples-plan.md), grounded in
**2** of the 35 H1/disclosure fixtures in
[`h1-stages.md`](../../../h1-stages.md): Shopify report 94087
(path traversal in signed S3 object keys) and Unikrn 254200
(cross-tenant write).

The bug: a multi-tenant SaaS uses a shared S3 bucket with a
per-tenant prefix scheme — `tenants/{tenant_id}/...` — but
the application's presigned-URL signer doesn't enforce the
tenant prefix at signing time. Tenant A's session can request
a signed URL for `tenants/B/...`, the signer mints it, S3
honours it, the cross-tenant read or write happens at the
*sign* layer, not at S3's request-evaluation layer.

This is the second iteration that uses Z3. Iter-4 modelled
prefix-mode upload policies; iter-5 models the multi-tenant
case where **a missing tag-enforcement condition** lets one
tenant reach another's data.

## Two binaries, two questions

```
examples/s3-tenant-prefix-isolation/
├── README.md
├── main.go              # CEL: does the signer's purpose admit unsafe operations?
├── controls/
│   └── CTL.S3.TENANT.ISOLATION.001.yaml
├── fixtures/
│   ├── before/observations/{T1,T2}.json   # enforce_prefix=false, allow_traversal=true
│   └── after/observations/{T1,T2}.json    # enforce_prefix=true, allow_traversal=false
├── z3prove/
│   ├── go.mod           # separate module — CGO/libz3 stays out of stave/
│   └── main.go          # Z3: which cross-tenant request does the signer admit?
└── expected/
    ├── before-output.txt
    ├── after-output.txt
    ├── z3-before-output.txt
    └── z3-after-output.txt
```

`z3prove/` is a separate Go module so its libz3 link does not
infect Stave's vendored tree (same architecture as iter-4).

## CEL side

From the repo's `stave/` directory:

```bash
go run ./examples/s3-tenant-prefix-isolation           # both phases
go run ./examples/s3-tenant-prefix-isolation before    # permissive signer
go run ./examples/s3-tenant-prefix-isolation after     # enforced signer
```

Captured output:

```
=== before (signer permissive) ===
  status: NON_COMPLIANT   total_assets=1   violations=1
  CTL.S3.TENANT.ISOLATION.001 fired on 1 asset(s):
    - acme-tenant-data   severity=high   exposure_score=76.64
  assertion: fires=true (expected) ✓

=== after  (signer enforced) ===
  status: COMPLIANT   total_assets=1   violations=0
  CTL.S3.TENANT.ISOLATION.001: no findings
  assertion: fires=false (expected) ✓
```

The control's predicate folds across two assets: the bucket
(tagged `tenant_mode=shared` with a `tenant_prefix`) and the
top-level `identities` list (an `app_signer` whose `purpose`
contains `enforce_prefix=false` or `allow_traversal=true`).
Both have to be present for the control to fire — a shared
bucket alone is fine, a permissive signer alone is fine; the
combination is what matters.

## Z3 side

Prerequisites (Ubuntu): `sudo apt install libz3-dev pkg-config`.

```bash
cd stave/examples/s3-tenant-prefix-isolation/z3prove
go mod tidy
CGO_ENABLED=1 go run . before
CGO_ENABLED=1 go run . after
```

Captured output for `before`:

```
=== before (signer permissive) ===
  signer purpose: signs_uploads;enforce_prefix=false;allow_traversal=true
  flags: enforce_prefix=false   allow_traversal=true
  admitted set: [tenant=A → tenants/A/photo.png tenant=A → tenants/B/photo.png tenant=A → tenants/A/../B/secret.json]
  intended set: ["tenant=A → tenants/A/photo.png"]
  verdict: SAT — witness request: tenant=A → tenants/B/photo.png
```

Z3 returns SAT with a witness — `tenant=A → tenants/B/photo.png`
— a request the signer admits but the application never
intended.

For `after`:

```
=== after  (signer enforced) ===
  signer purpose: signs_uploads;enforce_prefix=true;allow_traversal=false
  flags: enforce_prefix=true   allow_traversal=false
  admitted set: [tenant=A → tenants/A/photo.png]
  intended set: ["tenant=A → tenants/A/photo.png"]
  verdict: UNSAT — every admitted request is intended
```

UNSAT. With `enforce_prefix=true` and `allow_traversal=false`,
the signer's admitted set collapses to exactly the requesting
tenant's own prefix.

## Modelling note

Same pattern as iter-4. Each candidate request is a
`(requesting_tenant, target_key)` pair encoded as an integer:

```
0 = (tenant=A, target="tenants/A/photo.png")        intended
1 = (tenant=A, target="tenants/B/photo.png")        cross-tenant
2 = (tenant=A, target="tenants/A/../B/secret.json") path traversal
```

The constraint set is parameterised by the signer's flags:

```
enforce_prefix=false              → admitted = {0, 1, 2}     (anything)
enforce_prefix=true, traversal=on → admitted = {0, 2}        (own + ..)
enforce_prefix=true, traversal=no → admitted = {0}           (own only)
```

`unsafe = admitted ∧ ¬intended` (with `intended = (request == 0)`).
SAT proves a cross-tenant or traversal request is reachable;
UNSAT proves the signer's settings collapse the admitted set
to the intended set.

## What this iteration adds

Iter-4 demonstrated Z3 over a *single-tenant* prefix policy.
Iter-5 generalises to **multi-tenant** prefix isolation —
the same shape, but the failure mode is one tenant reaching
another, not one user reaching their own admin path. Together
they cover both halves of the prefix-quantification class:

| Iter 4 | Iter 5 |
|---|---|
| One tenant, key namespace | Many tenants, prefix per tenant |
| Witness: file path the user can write outside the intended pattern | Witness: cross-tenant request the signer admits |
| Severity: high | Severity: high |

No new `pkg/stave` API was needed for iter-5. The CEL side
reuses `FindingsForControl` from iter-1 unchanged. The Z3
side reuses the iter-4 encoder template (int-enum search
space, parameterised admitted set, `unsafe = admitted ∧
¬intended`).

## Where this fits

This is **Iteration 5, Phase B** of the examples roadmap.
Phase C is the article in `channels/devto/`, which uses the
SAT model output as the demonstrated cross-tenant request
and the UNSAT verdict as proof that the signer remediation
closes the *class* of attack across all tenants.
