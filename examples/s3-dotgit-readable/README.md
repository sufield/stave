# Example — S3 .git Readable

Demonstrates the `s3-dotgit-readable` pattern using Stave's
library API. Pattern P11 in
[`examples-plan.md`](../../../examples-plan.md), grounded in
**1** of the 35 H1/disclosure fixtures in
[`h1-stages.md`](../../../h1-stages.md): Mozilla report
[2383486](https://hackerone.com/reports/2383486).

The bug: a public S3 bucket serving a static site contains
the project's `.git/` directory. A reader can pull every
historical commit — old credentials, deploy keys,
`.env` files that were rotated but never rewritten out of
history, infrastructure diagrams that were committed and
later "deleted." Source-code disclosure paired with public
read produces the supply-chain primitive.

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

Loads two fixture snapshot directories — fixtures/before
(`.git/`-exposed) and fixtures/after (artefacts removed) —
and asserts that `CTL.S3.REPO.ARTIFACT.001` fires on the
first and is silent on the second.

Severity is `medium` (lower than `CTL.S3.PUBLIC.001`'s
`critical`) because the *intended* content of the public
bucket is by definition public. The escalation comes from
what the artefact paths reveal beyond the intended payload.

## Run

From the repo's `stave/` directory:

```bash
go run ./examples/s3-dotgit-readable           # both phases
go run ./examples/s3-dotgit-readable before    # vulnerable only
go run ./examples/s3-dotgit-readable after     # remediated only
```

## Expected output

```
=== before (.git/ exposed) ===
  status: NON_COMPLIANT   total_assets=1   violations=1
  CTL.S3.REPO.ARTIFACT.001 fired on 1 asset(s):
    - arn:aws:s3:::acme-marketing-site   severity=medium   exposure_score=51.10
  assertion: fires=true (expected) ✓

=== after  (artefacts removed) ===
  status: COMPLIANT   total_assets=1   violations=0
  CTL.S3.REPO.ARTIFACT.001: no findings
  assertion: fires=false (expected) ✓
```

## How the predicate composes

The control fires only when **both** conditions hold:

1. The bucket is publicly accessible (`public_read` OR
   `public_list` is true).
2. The bucket's content carries `exposed_repo_artifacts: true`.

Either alone is fine — a private bucket can carry whatever
it wants; a public marketing site that's clean of repo
artefacts is the intended use case. The combination is what
flips the bucket from "intentionally public" to "supply-chain
disclosure."

```yaml
unsafe_predicate:
  all:
    - any:
        - field: properties.storage.access.public_read
          op: eq
          value: true
        - field: properties.storage.access.public_list
          op: eq
          value: true
    - field: properties.storage.content.exposed_repo_artifacts
      op: eq
      value: true
```

## Why Z3 doesn't help

Same shape as iter-3 (bucket name dangling) — this is a
**presence check**, not a reachability question. The
collector observes the bucket's object inventory and reports
whether sensitive paths are present; CEL's predicate is a
two-leaf conjunction. There is no logical search space for
Z3 to chew on.

## Layout

```
examples/s3-dotgit-readable/
├── README.md
├── main.go
├── controls/
│   └── CTL.S3.REPO.ARTIFACT.001.yaml
├── fixtures/
│   ├── before/observations/{T1,T2}.json   # public_read + .git/ exposed × 2 weeks
│   └── after/observations/{T1,T2}.json    # public_read + clean × 2 weeks
└── expected/
    ├── before-output.txt
    └── after-output.txt
```

The `after` fixture leaves `public_read: true` on purpose —
the bucket is *intentionally* public (it's a marketing
site). The remediation is removing the `.git/` directory
from the bucket, not making the bucket private. This is
what makes the article's framing distinct from iter-1: the
fix is at the *deployment-pipeline* level, not at the bucket
policy level.

## Where this fits

This is **Iteration 6, Phase B** of the examples roadmap.
No new `pkg/stave` API was needed. Phase C is the article
in `channels/devto/`, which frames source-code disclosure
as a discovery primitive — the surface that turns a public
bucket from "leaking marketing assets" into "leaking the
secrets that were rotated three years ago."
