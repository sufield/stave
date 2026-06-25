# Fuzzing Stave

Stave fuzzes its untrusted-input boundaries with Go's native `testing.F`
harnesses (`make fuzz`) and, optionally, with
[gosentry](https://github.com/trailofbits/gosentry) — Trail of Bits'
security-oriented Go toolchain fork that swaps the native fuzzer for LibAFL and
adds grammar-based fuzzing, struct-aware mutation, goroutine-leak detection,
data-race detection, and integer-overflow detection. Same `testing.F` API, so
every harness runs under both.

## Quick start

```bash
# Native Go fuzzing — no extra tooling, runs in normal CI
make fuzz

# Gosentry (one-time build, not vendored)
make fuzz-install
make fuzz-all                 # all targets, 30m each
make fuzz-iam FUZZ_TIME=10m   # one target
make fuzz-coverage            # coverage reports
```

## Targets

| Target | Harness | Package | What it tests |
|---|---|---|---|
| `fuzz-cel` | `FuzzCompile` | `internal/adapters/cel/` | The ctrl.v1 predicate compiler — `(field, op, value)` → CEL program. Must never panic on any triple. |
| `fuzz-snapshot` | `FuzzLoadSnapshotFromReader` | `internal/adapters/observations/` | The obs.v0.1 snapshot parser. Pins the fail-loud contract: any input → a non-nil error **or** a fully-formed snapshot, never a half-populated one, never a panic. |
| `fuzz-iam` | `FuzzParsePolicyDocument` | `internal/platform/providers/aws/iam/` | The full IAM resolution pipeline: `ParsePolicyDocument` → `Resolve` (wildcard/effective permissions) → `AddResourcePolicy`. Grammar mode. |

These are Stave's real untrusted-input boundaries: a control predicate, an
ingested snapshot, and an IAM policy document. There is intentionally **no
free-text CEL harness** — Stave never evaluates raw CEL strings; controls are a
structured `{field, op, value}` predicate compiled to CEL, so `FuzzCompile` is
the CEL-side surface. A free-text CEL grammar would only fuzz the upstream
`cel-go` dependency, not Stave.

## Bug classes gosentry adds over native fuzzing

- Data races (`--catch-races`)
- Goroutine leaks (`--catch-leaks`)
- Integer overflows (go-panikint)
- Silent `log.Fatal` exits (`--panic-on=log.Fatal`)

(Native `make fuzz` still catches panics, hangs, and the fail-loud violations
in the harness assertions.)

## Grammars

Grammar files live in `fuzz/grammars/` and shape gosentry's input generation so
it produces structurally valid documents instead of random bytes. Grammar mode
requires a single-string (or `[]byte`) harness.

- `iam-policy-grammar.json` — IAM policy JSON, seeded with Stave's real control
  surface: MicroVM actions (`lambda:CreateMicrovmShellAuthToken`), Batch/ECS
  escalation actions, `cognito-idp:Admin*`, `sts:TagSession`, and the condition
  keys the tag-integrity controls rely on.

> **Nautilus gotcha:** in a gosentry grammar, `{` and `}` are reserved for
> nonterminal references (`{Statement}`). Because IAM policies are JSON objects,
> every *literal* brace must be escaped as `\{` / `\}` (i.e. `\\{` / `\\}` in the
> JSON string). An unescaped literal `{` makes the Nautilus parser panic with
> zero executions — so when editing the grammar, escape every literal brace and
> leave only real nonterminal references unescaped.

`fuzz-cel` and `fuzz-snapshot` run without a grammar (`FuzzCompile` is
multi-argument; the snapshot parser is exercised well by raw JSON mutation).

## CI

`.github/workflows/fuzz.yml` runs gosentry weekly (Mondays 02:00 UTC) and on
manual dispatch. It builds gosentry from source (cached), caches the corpus
between runs so campaigns resume, and uploads crash/leak artifacts on failure.
It is **opt-in and never gates PRs** — PR-time fuzzing is the fast native
`make fuzz`.

## Debugging

```bash
GOSENTRY_VERBOSE_AFL=1 make fuzz-iam FUZZ_TIME=1m        # show grammar inputs
GOSENTRY_VERBOSE_AFL_ALL_INPUTS=1 make fuzz-iam FUZZ_TIME=1m  # very noisy
```

To focus a campaign on recently changed code (useful right after shipping new
controls), flip `--focus-on-new-code=false` to `true` in the relevant Makefile
target.

## Notes

- gosentry is **not vendored** — `make fuzz-install` builds it at
  `GOSENTRY_PATH` (default `/tmp/gosentry`); it needs a Rust toolchain.
- A reproducible crash is written under the package's
  `testdata/fuzz/<Harness>/` — commit it as a regression seed once fixed.
