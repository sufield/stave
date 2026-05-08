# Z3 Public-Exposure Example

A small Go program that uses Stave's library API to load an
observation snapshot and uses a Go binding to libz3 to verify a
tiny S3 public-exposure property. Demonstrates the shape of the
pipeline:

```
observations dir
 -> Stave loader (library API)
 -> []asset.Snapshot
 -> per-bucket Z3 model
 -> Z3 solver SAT/UNSAT verdict
```

The main `stave` binary is built with `CGO_ENABLED=0` and has no
Z3 dependency. **Only this example links libz3** — it lives
under `examples/` precisely so the main release artefact is
unaffected.

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

## Architectural note

Stave's evaluator is the in-process Google CEL backend. This
example does not replace, swap with, or shadow that evaluator;
it shows how a separate Go program can compose Stave's library
API with an SMT solver to answer a different shape of question
(SAT/UNSAT over a logical model) than CEL is built for.

If you want Z3 reasoning across more service domains, fork this
example or copy its pattern. Anything you build stays
independent of the Stave release pipeline.

## Run it via the demo Docker image

The simplest way is via the existing demo image, which already
builds this example with libz3 linked:

```bash
cd <repo-root>/stave
docker compose build
docker compose run --rm -T stave --z3-example
```

The container runs `z3-example` against scenario 01's
observations and prints the verdict.

## Build and run on the host

You need libz3 development headers and pkg-config installed
(Ubuntu):

```bash
sudo apt install libz3-dev pkg-config
```

The Go binding is `github.com/aclements/go-z3`. Add it to
Stave's `go.mod` and tidy on first build:

```bash
cd <repo-root>/stave
go get github.com/aclements/go-z3
go mod tidy
```

Build the example with cgo enabled. The source uses the
`z3example` build tag so it stays out of bare `go build ./...`
runs that don't have libz3 installed:

```bash
CGO_ENABLED=1 go build -tags z3example -o /tmp/z3-example ./examples/z3-public-exposure
```

Run it against any obs.v0.1 directory. The other examples in
this folder ship suitable inputs:

```bash
/tmp/z3-example examples/public-bucket/observations
```

Sample output:

```
UNSAFE arn:aws:s3:::demo-public-bucket — public read is provably possible (policy_public=true, pab=false)
SAFE arn:aws:s3:::demo-private-bucket — public read is provably impossible under this model
```

## Inputs the example reads

For each `aws_s3_bucket` asset in the snapshot, the example
reads two boolean properties:

| Property path | Meaning |
|---------------|---------|
| `policy_allows_public_read` | Bucket policy admits Principal `*` for `s3:GetObject` |
| `public_access_block_enabled` | The bucket-level PublicAccessBlock blocks public access |

A production-shaped solver would parse the full bucket-policy
JSON and encode condition operators rather than asking the
collector to pre-compute these booleans. The example
abstracts that parsing work to keep the Z3 mechanics legible.

## What the example does NOT cover

- **Cross-resource composition** — the Z3 model here is one
 bucket at a time. Real solver work would compose bucket
 policy + IAM policy + PAB + ACL into one constraint system.
- **Suggested-fix extraction** — Z3 can return the satisfying
 assignment that proves the bucket unsafe; the example only
 prints SAT/UNSAT.
- **Other service domains** — IAM authorization beyond S3
 reach, KMS key policies, VPC endpoint policies. Each would
 be its own model.

The point of this example is to show how to compose the Stave
library and a Go Z3 binding inside a small program. Extending
it is a project decision.

## Swapping the Z3 binding

`github.com/aclements/go-z3` is one Go binding to libz3. Other
options exist (e.g., projects under `Z3Prover/`'s ecosystem,
custom cgo wrappers). The example's `checkBucket` function is
the only place that calls Z3 APIs; swap that block to use a
different binding without touching the loader / asset
traversal.
