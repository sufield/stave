# Examples

Self-contained examples you can run on your machine. Most have
their own observations, controls, and expected output and
exercise the `stave` CLI directly. The `z3-public-exposure`
example is different: it is a small Go program that composes
Stave's library API with a Go binding to libz3 to answer a
SAT/UNSAT question over a snapshot. See its own README for
build and run instructions.

## Prerequisites

Build stave from source:

```bash
cd stave
make build
```

## 1. Public bucket detection

A bucket with public read access. Stave detects the exposure.

```bash
./stave apply \
  --controls examples/public-bucket/controls \
  --observations examples/public-bucket/observations \
  --max-unsafe 12h \
  --now 2026-01-02T00:00:00Z \
  --allow-unknown-input
```

Exit code 3 — violation found. The bucket has `public_read: true` for
24 hours, exceeding the 12-hour threshold.

## 2. Missing Public Access Block

A bucket without Public Access Block. Not currently public, but one
policy change away from exposure.

```bash
./stave apply \
  --controls examples/missing-pab/controls \
  --observations examples/missing-pab/observations \
  --max-unsafe 12h \
  --now 2026-01-02T00:00:00Z \
  --allow-unknown-input
```

Exit code 3 — violation found. Public Access Block has been disabled
for 24 hours.

## 3. Duration tracking

A bucket stays publicly readable across three snapshots over 9 days.
Stave tracks the unsafe duration and fires when it exceeds the
threshold.

```bash
./stave apply \
  --controls examples/duration/controls \
  --observations examples/duration/observations \
  --max-unsafe 12h \
  --now 2026-01-10T00:00:00Z \
  --allow-unknown-input
```

Exit code 3 — violation found. The bucket has been publicly readable
for 216 hours (9 days), exceeding the 12-hour threshold.

## 4. Z3 public-exposure (Go example)

A standalone Go program (not driven by the `stave` CLI) that
loads an observation snapshot via Stave's library API and uses
a Go binding to libz3 to verify a tiny S3 public-exposure
property. Build it with cgo + libz3 — see
[`z3-public-exposure/README.md`](z3-public-exposure/README.md)
for the full instructions. The simplest way to run it is via
the demo Docker image:

```bash
cd <repo-root>/stave
docker compose build
docker compose run --rm -T stave --z3-example
```

## 5. Graph export (Go library example)

A standalone Go program that uses Stave's library API
(`pkg/stave.ExportGraph`) to project an `Assessment` into the
cross-service relationship view — assets, the findings and chains
that hang off them, and the edges between — then shows the
`WithSIRDocument` enrichment that adds transitive IAM role chains
and per-asset lifecycle. No external data or cgo required.

```bash
cd stave
go run -tags graphexample ./examples/lib/graph-export
```

The `graphexample` build tag keeps it out of the normal module
build. See
[`lib/graph-export/README.md`](lib/graph-export/README.md) for the
export shape, JSON output, and downstream consumers (Neo4j
visualisers, Z3 reachability queries).

## What each example contains

The first three examples follow this shape:

```
examples/<name>/
  controls/      One YAML control (the safety rule)
  observations/  Two or three JSON snapshots (the bucket state over time)
  README.md      Scenario details and expected output
```

The Go-code examples follow a different shape:

```
examples/z3-public-exposure/
  main.go        The Go program (uses Stave library + go-z3)
  README.md      Build, run, and architectural notes

examples/lib/graph-export/
  main.go        The Go program (uses pkg/stave.ExportGraph)
  README.md      Export shape, JSON output, downstream consumers
```

## Flags explained

| Flag | Purpose |
|---|---|
| `--controls` | Directory containing YAML control definitions |
| `--observations` | Directory containing JSON observation snapshots |
| `--max-unsafe` | Maximum time a bucket may remain unsafe before violation |
| `--now` | Fixed timestamp for deterministic output |
| `--allow-unknown-input` | Accept observations with custom source types |
