# Example — S3 Broad Write Scope

Demonstrates the `s3-broad-write-scope` pattern using both
**CEL** (state assertion via `pkg/stave`) and **Z3** (witness
extraction via the `aclements/go-z3` binding). Pattern P3 in
[`examples-plan.md`](../../../examples-plan.md), grounded in
**4** of the 35 H1/disclosure fixtures in
[`h1-stages.md`](../../../h1-stages.md): Shopify reports 93691
and 98819, BCM 764243, and Shopify 94502.

The bug: a signed S3 upload policy uses a **prefix** rule
(`starts-with $key files/`) instead of binding each upload to a
single exact key. Anyone with a signed POST URL can write to
*any* object key under the prefix — including paths the
application never expected.

This is the first iteration where Z3 actually does something
CEL alone cannot. CEL detects the unsafe state ("the policy is
in prefix mode"). Z3 enumerates a concrete key the policy
admits but the application's intended-key pattern excludes —
the *witness* that turns "your policy is too permissive" into
"here is the specific filename a tester can write."

## Prerequisites

This example's `z3prove/` binary links against libz3 via CGO.
Install the development headers before running:

| OS | Command |
|---|---|
| Ubuntu 22.04 / 24.04 | `sudo apt-get install -y libz3-dev pkg-config` |
| macOS (Homebrew) | `brew install z3 pkg-config` |

Then build with `CGO_ENABLED=1 go run .` from inside `z3prove/`.
The Stave binary itself has no libz3 dependency; only the
per-example Z3 prover does. See [`../PREREQUISITES.md`](../PREREQUISITES.md)
for other platforms (Fedora, Arch, nix, Debian) and for the
prerequisites of the SMT CLI / Soufflé / Prolog / Python-venv
examples.

## Two binaries, two questions

```
examples/s3-broad-write-scope/
├── README.md
├── main.go              # CEL: does the unsafe predicate hold?
├── controls/
│   └── CTL.S3.WRITE.SCOPE.001.yaml
├── fixtures/
│   ├── before/observations/{T1,T2}.json   # allowed_key_mode=prefix
│   └── after/observations/{T1,T2}.json    # allowed_key_mode=exact
├── z3prove/
│   ├── go.mod           # separate module — CGO/libz3 stays out of stave/
│   └── main.go          # Z3: is there an admitted key outside the intended set?
└── expected/
    ├── before-output.txt
    ├── after-output.txt
    ├── z3-before-output.txt
    └── z3-after-output.txt
```

`z3prove/` is a **separate Go module** so its libz3 link does
not infect Stave's vendored tree. Stave's main binary stays
`CGO_ENABLED=0`. The Z3 program reads observation JSON
directly — no Stave dependency at all — illustrating that
the obs.v0.1 schema is consumable by any reasoner.

## CEL side — `main.go`

From the repo's `stave/` directory:

```bash
go run ./examples/s3-broad-write-scope           # both phases
go run ./examples/s3-broad-write-scope before    # vulnerable only
go run ./examples/s3-broad-write-scope after     # remediated only
```

Captured output:

```
=== before (prefix-mode) ===
  status: NON_COMPLIANT   total_assets=2   violations=1
  CTL.S3.WRITE.SCOPE.001 fired on 1 asset(s):
    - acme-uploads-signed-policy   severity=high   exposure_score=100.00
  assertion: fires=true (expected) ✓

=== after  (exact-mode) ===
  status: COMPLIANT   total_assets=2   violations=0
  CTL.S3.WRITE.SCOPE.001: no findings
  assertion: fires=false (expected) ✓
```

`total_assets=2` because the fixture carries both the bucket
asset and the upload-policy asset (`s3_upload_policy` is
modelled as a separate asset because the vulnerability lives
in the policy contract, not in the bucket).

## Z3 side — `z3prove/`

Prerequisites (Ubuntu): `sudo apt install libz3-dev pkg-config`.

```bash
cd stave/examples/s3-broad-write-scope/z3prove
go mod tidy
CGO_ENABLED=1 go run . before
CGO_ENABLED=1 go run . after
```

Captured output for `before`:

```
=== before (prefix-mode) ===
  policy mode: prefix   exemplar: files/*
  admitted set: [files/abc-uuid/photo.png files/admin.html files/../etc/passwd]
  intended set: ["files/abc-uuid/photo.png"]
  verdict: SAT — witness key "files/admin.html" is admitted but unintended
```

For `after`:

```
=== after  (exact-mode) ===
  policy mode: exact   exemplar: files/abc-uuid/photo.png
  admitted set: [files/abc-uuid/photo.png]
  intended set: ["files/abc-uuid/photo.png"]
  verdict: UNSAT — every admitted key is intended
```

Z3 returns `SAT` on the prefix-mode policy with a witness key
the policy admits but the application never wanted —
`files/admin.html`. On the exact-mode policy it returns
`UNSAT`: every admitted key is in the intended set.

## Modelling note — what Z3 is actually doing

The `aclements/go-z3` binding does not expose Z3's string
theory, so the program models the search space as a finite
enum of named witness keys encoded as integer constants:

```
0 = "files/abc-uuid/photo.png"   (intended)
1 = "files/admin.html"            (admitted by prefix, NOT intended)
2 = "files/../etc/passwd"         (admitted, path traversal)
```

The constraint set encodes:

```
admitted = key ∈ admitted_set      (prefix mode: {0, 1, 2}; exact mode: {0})
intended = key == 0
unsafe   = admitted AND NOT intended
```

Z3 discharges the unsafe predicate. SAT → at least one
admitted key is unintended; the model returns its index, the
program looks up the label, the article shows a concrete
witness. UNSAT → every admitted key is intended.

A production-shaped model would parse the policy's Resource
pattern as a finite-state automaton (or use a Z3 binding with
string theory) and let Z3 enumerate over all strings matching
the prefix. The integer-enum encoding here keeps the Z3
mechanics legible without hiding behind the binding's
limitations.

## What this iteration adds

Iter 1, 2, and 3 were CEL-only — the unsafe predicate is a
simple state assertion. Iter 4 is the first iteration where
the *consequence* of the unsafe state (which keys does the
policy actually admit?) is logically richer than the
predicate, and where Z3's witness-extraction earns its
complexity. The iter-3 article's "Why Z3 doesn't help" section
made the converse case; the iter-4 article makes this one.

No new `pkg/stave` API was needed. The CEL side reuses
`FindingsForControl` from iter-1 unchanged. The Z3 side does
not depend on Stave at all.

## Where this fits

This is **Iteration 4, Phase B** of the examples roadmap.
Phase C is the article in `channels/devto/`, which uses the
SAT model output (witness: `files/admin.html`) as the
demonstrated breach path and the UNSAT verdict as proof that
the remediation closes the *class* of attack, not just the
specific exploit.
