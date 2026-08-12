# Example — S3 Public List Policy

Demonstrates the `s3-public-list-policy` pattern using Stave's
library API, grounded in
**3** of the 35 H1/disclosure fixtures catalogued in
the HackerOne stages reference: `e2e-h1-shopify-57505`,
`e2e-h1-zomato-507097` (read+list), and the `e2e-disclosure-sriram-2017`
LIST+WRITE pattern.

The bug: `Principal: "*"` on `s3:ListBucket` against the bucket
ARN. Listing reveals object keys — filenames, prefixes, sizes,
timestamps — without reading object contents. That key inventory
is the **discovery** signal an attacker uses to plan targeted
exfiltration.

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

## What it does

This program embeds two observation fixtures and evaluates each
against `CTL.S3.PUBLIC.LIST.001` using `pkg/stave`:

- `fixtures/before/` — bucket policy admits Principal `*` for
 `s3:ListBucket`. The control fires.
- `fixtures/after/` — policy scoped to a single IAM role, full
 Public Access Block on. The control is silent.

Output is captured into `expected/before-output.txt` and
`expected/after-output.txt`. The article in
`channels/devto/s3-public-list-policy.md` (Phase C of iteration 2)
quotes those files verbatim.

## Run

From the repo's `stave/` directory:

```bash
go run ./examples/s3-public-list-policy # both phases
go run ./examples/s3-public-list-policy before # vulnerable only
go run ./examples/s3-public-list-policy after # remediated only
```

## Expected output

```
=== before (vulnerable) ===
 status: NON_COMPLIANT total_assets=1 violations=1
 CTL.S3.PUBLIC.LIST.001 fired on 1 asset(s):
 - arn:aws:s3:::acme-public-archive severity=high exposure_score=100.00
 assertion: fires=true (expected) ✓

=== after (remediated) ===
 status: COMPLIANT total_assets=1 violations=0
 CTL.S3.PUBLIC.LIST.001: no findings
 assertion: fires=false (expected) ✓
```

Severity is `high` — not `critical` as for public read. Listing
is the recon step; the data exfiltration that follows requires
either public read on objects (a separate control,
`CTL.S3.PUBLIC.001`) or a path-traversal / sensitive-key-name
exposure that pairs with listing to produce a breach.

## Layout

```
examples/s3-public-list-policy/
├── README.md
├── main.go
├── controls/
│ └── CTL.S3.PUBLIC.LIST.001.yaml # scoped to one invariant
├── fixtures/
│ ├── before/observations/{T1,T2}.json # public_list=true × 2 weeks
│ └── after/observations/{T1,T2}.json # remediated × 2 weeks
└── expected/
 ├── before-output.txt
 └── after-output.txt
```

## ListBucket vs GetObject — note on Resource ARNs

The `s3:ListBucket` action operates on the bucket itself, not on
objects. Its `Resource` field is the bare bucket ARN
(`arn:aws:s3:::<bucket>`), without the `/*` suffix that
`s3:GetObject` uses. This is a real-world authoring mistake:
policies that grant `s3:ListBucket` on `arn:aws:s3:::bucket/*`
silently fail to grant listing — the action's `Resource` doesn't
match. Stave's predicate is unaffected (it reads the engine's
boolean fold, not the policy text), but a Z3 model that parses
`policy_json` directly must encode the action-to-resource-arity
constraint. See the `s3-broad-write-scope` example for the same
distinction in the write direction.

## Z3 prover (companion binary)

Sibling Go module under `z3prove/`. Reads the bucket's
`storage.policy_json` and enumerates concrete (principal,
action, resource) ListBucket-family requests the policy
admits outside the intended scope. CEL detects the unsafe
state ("public_list is true"); Z3 names the witness.

```bash
cd stave/examples/s3-public-list-policy/z3prove
go mod tidy
CGO_ENABLED=1 go run . before # SAT with witness
CGO_ENABLED=1 go run . after # UNSAT
```

Captured output for `before`
(`expected/z3-before-output.txt`):

```
=== before (Principal:*) ===
 policy statements: 1
 [0] Effect=Allow Principal=* Action=s3:ListBucket Resource=arn:aws:s3:::acme-public-archive
 admitted requests: 2 / 4
 intended scope: [arn:aws:iam::111122223333:role/AcmeArchiveReader s3:ListBucket arn:aws:s3:::acme-public-archive]
 verdict: SAT — witness: Principal="*" Action=s3:ListBucket Resource=arn:aws:s3:::acme-public-archive
```

The matcher correctly distinguishes the bucket-level Resource
arity — statements with `bucket/*` would silently fail to
grant ListBucket on the bucket itself; the matcher rejects
those, which is why `admitted requests: 2 / 4` (only the two
witnesses where the action actually targets the bucket
resource).

After scoping:

```
=== after (scoped Principal) ===
 ...
 admitted requests: 1 / 4
 verdict: UNSAT — no anonymous list admitted outside the intended scope
```

## Where this fits

this
shipped the `pkg/stave` API surface (`FindingsForControl` etc.)
this example reuses unchanged. The Z3 prover was added in a
future extension, mirroring this example's backfill — same matcher
template adapted to the ListBucket domain.
