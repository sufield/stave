# Stave Commands Reference

Quick lookup for the commands the `verifying-cloud-security` skill drives.
Run `stave <cmd> --help` for the full flag set; this page lists the flags
and exit codes the workflow depends on.

## Discovery

| Command | Purpose | Exit codes |
|---|---|---|
| `stave search "<intent>"` | Find capabilities by problem description | 0 always |
| `stave capabilities catalog` | Browse all capabilities grouped by service / category | 0 always |
| `stave contract show --asset-type <T>` | Schema + read-paths + Steampipe mapping for one asset type | 0, 2 (bad flag) |
| `stave contract show --list` | All asset types with control/chain counts and mapping presence | 0 always |

### Example

```bash
stave search "public S3 bucket"
# Returns ranked capabilities. Synonyms (open ↔ public, ghost ↔
# orphan, mfa ↔ two-factor) expand automatically.

stave contract show --asset-type aws_s3_bucket --format json | jq '.property_paths[0:3]'
# Lists the property paths the catalog actually reads for S3 buckets,
# ordered by chain-unlock then control-unlock count.
```

## Validation

| Command | Purpose | Exit codes |
|---|---|---|
| `stave validate --in <file> --kind observation --strict` | Schema-validate an observation file | 0 valid, 2 invalid (with field-level error) |

`--strict` rejects partial / under-specified observations. Always pass
it in agent workflows; the looser default exists for hand-debugging.

## Evaluation

| Command | Purpose | Exit codes |
|---|---|---|
| `stave apply --observations <dir> --eval-time <RFC3339> --format json` | Evaluate controls + chains, emit findings | 0 no findings, 3 findings present, 2 input error, 4 internal |
| `stave gaps --observations <dir> --format json` | Missing properties, typed by remediation class | 0 always |
| `stave readiness --observations <dir> --format json` | Three-bucket coverage report | 0 always |

### Critical flags

- `--eval-time <RFC3339>` — **always pass** for deterministic output. Match the
  observation's `captured_at` for reproducibility across CI runs and
  agent iterations.
- `--max-unsafe <duration>` — override the SLA threshold (default 7 days).
  Affects duration-gated controls only.

### Reading the output

```bash
stave apply --observations ./obs --format json --eval-time $(date -u +%Y-%m-%dT%H:%M:%SZ) | jq '{
  total: (.findings | length),
  by_severity: (.findings | group_by(.control_severity) | map({(.[0].control_severity): length}) | add),
  chains: (.chain_findings // [] | length)
}'
```

`.findings` are individual control hits.
`.marker_findings` are fact-recording markers (compose into chains, never
fail SLA on their own).
`.chain_findings` are compound findings — read these BEFORE the
individual findings; they're the high-leverage signal.

## Export for external solvers

| Command | Purpose | Exit codes |
|---|---|---|
| `stave export-sir --format jsonl --observations <dir>` | One (subject, predicate, object) triple per line — Soufflé / Clingo | 0 always |
| `stave export-sir --format smt2 --observations <dir>` | SMT-LIB v2 declarations + assertions — Z3 / cvc5 / Yices | 0 always |
| `stave export-sir --format json --observations <dir>` | Full nested SIR document for inspection | 0 always |

Always pass `--eval-time` for byte-stable output. The export covers the SIR's
projected scope (13 top-level domains today); see `--help` for the
domain list.

## Snapshot diff

| Command | Purpose | Exit codes |
|---|---|---|
| `stave snapshot diff --before <dir1> --after <dir2>` | Property-level changes between two snapshots of the same assets | 0 no changes, 3 changes |
| `stave snapshot manifest --observations <dir>` | List asset IDs + last-seen timestamps | 0 always |

## CI gates

| Command | Purpose | Exit codes |
|---|---|---|
| `stave ci baseline --observations <dir>` | Write a baseline of accepted findings | 0 always |
| `stave ci gate --observations <dir> --baseline <file>` | Fail if NEW findings appear vs baseline | 0 no new findings, 3 new findings |
| `stave ci fix-loop --observations <dir>` | Apply automatic remediation suggestions and re-evaluate | 0 fixes converged, 3 unfixable findings remain |
