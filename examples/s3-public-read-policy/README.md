# Example — S3 Public Read Policy

Demonstrates the `s3-public-read-policy` pattern using Stave's
library API, grounded in
**11** of the 35 H1/disclosure fixtures catalogued in
the HackerOne stages reference: the same configuration
defect appears across Greenhouse, Mapbox, Mozilla, Omise, Slack,
Uber, Zomato, multiple Shopify reports, and three named
disclosures.

The bug is always the same: an S3 bucket policy with
`Principal: "*"` and `Action: "s3:GetObject"`.

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

This program embeds **two** observation fixtures and evaluates
each against `CTL.S3.PUBLIC.001` using `pkg/stave`:

- `fixtures/before/` — bucket policy admits Principal `*` for
 `s3:GetObject`. The control fires.
- `fixtures/after/` — policy scoped to a single IAM role, full
 Public Access Block on. The control is silent.

Output is captured into `expected/before-output.txt` and
`expected/after-output.txt`. The article in
`channels/devto/s3-public-read-policy.md` (Phase C of iteration 1)
quotes those files verbatim.

## Run

From the repo's `stave/` directory:

```bash
go run ./examples/s3-public-read-policy # both phases
go run ./examples/s3-public-read-policy before # vulnerable only
go run ./examples/s3-public-read-policy after # remediated only
```

You can also build the binary and invoke it from the example
directory:

```bash
cd stave
go build -o /tmp/s3prr ./examples/s3-public-read-policy
cd examples/s3-public-read-policy
/tmp/s3prr
```

## Expected output

```
=== before (vulnerable) ===
 status: NON_COMPLIANT total_assets=1 violations=1
 CTL.S3.PUBLIC.001 fired on 1 asset(s):
 - arn:aws:s3:::acme-customer-uploads severity=critical exposure_score=100.00
 assertion: fires=true (expected) ✓

=== after (remediated) ===
 status: COMPLIANT total_assets=1 violations=0
 CTL.S3.PUBLIC.001: no findings
 assertion: fires=false (expected) ✓
```

The example exits 0 when both assertions hold; non-zero otherwise.
A diagnostic WARN about a coverage validator with `min_span=0s`
may appear on stderr — it is unrelated to the example's
correctness and is filtered out of the captured `expected/*.txt`
files.

## Layout

```
examples/s3-public-read-policy/
├── README.md
├── main.go
├── controls/
│ └── CTL.S3.PUBLIC.001.yaml # scoped to one invariant
├── fixtures/
│ ├── before/observations/
│ │ ├── 2026-01-01T000000Z.json # public_read=true
│ │ └── 2026-01-08T000000Z.json # still unsafe (>168h)
│ └── after/observations/
│ ├── 2026-01-01T000000Z.json # public_read=false, full PAB
│ └── 2026-01-08T000000Z.json # still safe
└── expected/
 ├── before-output.txt
 └── after-output.txt
```

Each fixture ships **two** snapshots a week apart. Stave's
`MaxUnsafe=168h` rule means a finding requires the unsafe
condition to persist across the window — a single snapshot would
not be enough to fire the control.

## What the bucket policy looks like

The observation carries the raw policy under
`properties.storage.policy_json` so `pkg/stave/ExportPolicies`
can surface it for downstream solver work (this — broad write
scope — will use this path).

Before:

```json
{
 "Version": "2012-10-17",
 "Statement": [{
 "Sid": "PublicRead",
 "Effect": "Allow",
 "Principal": "*",
 "Action": "s3:GetObject",
 "Resource": "arn:aws:s3:::acme-customer-uploads/*"
 }]
}
```

After:

```json
{
 "Version": "2012-10-17",
 "Statement": [{
 "Sid": "AppRoleOnly",
 "Effect": "Allow",
 "Principal": {"AWS": "arn:aws:iam::111122223333:role/AcmeUploadsApp"},
 "Action": "s3:GetObject",
 "Resource": "arn:aws:s3:::acme-customer-uploads/*"
 }]
}
```

## Z3 prover (companion binary)

Sibling Go module under `z3prove/` — a Z3 SAT solver that
reads the same fixture's `storage.policy_json` and enumerates
specific (principal, action, resource) requests the policy
admits outside the application's intended scope. CEL detects
the unsafe state ("public_read is true"); Z3 names the
concrete witness.

Prerequisites (Ubuntu): `sudo apt install libz3-dev pkg-config`.

```bash
cd stave/examples/s3-public-read-policy/z3prove
go mod tidy
CGO_ENABLED=1 go run . before # SAT with witness
CGO_ENABLED=1 go run . after # UNSAT
```

Captured output for `before` (`expected/z3-before-output.txt`):

```
=== before (Principal:*) ===
 policy statements: 1
 [0] Effect=Allow Principal=* Action=s3:GetObject Resource=arn:aws:s3:::acme-customer-uploads/*
 admitted requests: 4 / 4
 intended scope: [arn:aws:iam::111122223333:role/AcmeUploadsApp s3:GetObject arn:aws:s3:::acme-customer-uploads/intended-input.csv]
 verdict: SAT — witness: Principal="*" Action=s3:GetObject Resource=arn:aws:s3:::acme-customer-uploads/customer-data.csv
```

`Principal: "*"` admits every witness in the search set; the
solver returns `customer-data.csv` as the first
dangerous-and-unintended one. After the policy is scoped:

```
=== after (scoped Principal) ===
 ...
 admitted requests: 1 / 4
 ...
 verdict: UNSAT — no anonymous read admitted outside the intended scope
```

The Z3 binary lives in a sibling Go module so its libz3 link
stays out of Stave's main vendored tree (Stave's own binary
is `CGO_ENABLED=0`).

## Where this fits

Phase A
documented the `pkg/stave` API surface and shipped the
`Assessment.FindingsForControl` helper this example uses. Phase C
is the article (`channels/devto/`) that builds the business
narrative around the captured before/after output. The Z3
prover was added so the reachability
verdict could appear alongside the CEL state assertion in the
article — same shape as this example, this example, this example, this example.
