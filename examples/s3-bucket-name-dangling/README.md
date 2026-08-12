# Example — S3 Bucket Name Dangling

Demonstrates the `s3-bucket-name-dangling` (bucket-takeover)
pattern using Stave's library API, grounded in
**8** of the 35 H1/disclosure fixtures catalogued in
the HackerOne stages reference: Bime, Brave (twice — for
their APT and RPM package channels), DoD, HackerOne, IBM, Khan
Academy, Tendermint.

The bug: a CDN origin or DNS CNAME inside the organization
references an S3 bucket name that is *not* an S3 bucket inside
the organization's AWS account. Anyone with an AWS account can
register the same name (S3 bucket names are globally unique
across AWS) and serve attacker content under the company's
domain — with the company's TLS certificate, indexed by the
company's SEO, trusted by the company's users.

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
against `CTL.S3.BUCKET.TAKEOVER.001` using `pkg/stave`:

- `fixtures/before/` — a CloudFront origin references the
 bucket `acme-cdn-assets`; the bucket does not exist in the
 account (`bucket_exists: false`, `bucket_owned: false`). The
 control fires.
- `fixtures/after/` — same reference, but the bucket has been
 claimed (`bucket_exists: true`, `bucket_owned: true`). The
 control is silent.

Output is captured into `expected/before-output.txt` and
`expected/after-output.txt`. The article in
`channels/devto/s3-bucket-name-dangling.md` (Phase C of
iteration 3) quotes those files verbatim.

## Run

From the repo's `stave/` directory:

```bash
go run ./examples/s3-bucket-name-dangling # both phases
go run ./examples/s3-bucket-name-dangling before # dangling only
go run ./examples/s3-bucket-name-dangling after # claimed only
```

## Expected output

```
=== before (dangling) ===
 status: NON_COMPLIANT total_assets=1 violations=1
 CTL.S3.BUCKET.TAKEOVER.001 fired on 1 asset(s):
 - acme-cdn-origin-assets severity=critical exposure_score=100.00
 assertion: fires=true (expected) ✓

=== after (claimed) ===
 status: COMPLIANT total_assets=1 violations=0
 CTL.S3.BUCKET.TAKEOVER.001: no findings
 assertion: fires=false (expected) ✓
```

Severity is `critical` — bucket takeover lets an attacker serve
arbitrary content from a trusted domain. The blast radius is
the entire user base of whatever points at the dangling
reference.

## Asset modelling

The asset is a `s3_bucket_reference`, **not** an `aws_s3_bucket`.
This is the key difference from the `s3-public-read-policy` example
and the `s3-public-list-policy` example:

```json
{
 "id": "acme-cdn-origin-assets",
 "type": "s3_bucket_reference",
 "vendor": "aws",
 "properties": {
 "s3_ref": {
 "reference_kind": "cloudfront_origin",
 "endpoint": "assets.acme.example",
 "bucket": "acme-cdn-assets",
 "bucket_exists": false,
 "bucket_owned": false
 }
 }
}
```

The vulnerability lives in the **reference** — the DNS record,
the CDN origin, the application config — not in any bucket
inside the account. A CSPM that inventories in-account buckets
finds nothing, because the unsafe state is precisely "no bucket
exists in this account with the referenced name." Stave models
the reference as an asset so the predicate has something to
evaluate.

## Why Z3 doesn't help here

this, this example, this example, and this example are *reachability* questions
("can a public principal reach this bucket?"). This one is a
**name lookup** — does the referenced bucket name resolve to a
bucket the account owns? That's a discrete equality check, not
a logic question; CEL is the right tool. The plan
(the catalog) marks this pattern explicitly as
not-Z3-suited.

## Layout

```
examples/s3-bucket-name-dangling/
├── README.md
├── main.go
├── controls/
│ └── CTL.S3.BUCKET.TAKEOVER.001.yaml # scoped to one invariant
├── fixtures/
│ ├── before/observations/{T1,T2}.json # bucket_exists=false × 2 weeks
│ └── after/observations/{T1,T2}.json # bucket_exists=true × 2 weeks
└── expected/
 ├── before-output.txt
 └── after-output.txt
```

## Where this fits

No
new `pkg/stave` API was needed — `FindingsForControl` from
this example still does the work; the only change is that the asset
type is `s3_bucket_reference` instead of `aws_s3_bucket`. The
predicate's field paths (`properties.s3_ref.*`) are observation-
schema concerns, transparent to the library API.
