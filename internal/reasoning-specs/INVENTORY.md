# Reasoning Engine Inventory

Output of Phase 1 — exhaustive scan of `examples/`, `docs/`, and
`internal/adapters/graph/` for every reasoning engine or downstream
export pathway with a working example AND a committed golden output.

## Engines with working examples (specs written)

| Engine | Example | Question | Fixture | Golden answer source |
|---|---|---|---|---|
| **Z3** (SMT) | `s3-public-read-policy` | Can an unauthenticated principal read from an S3 bucket whose PAB is disabled? | `examples/s3-public-read-policy/query.smt2` + facts from `stave export-sir --format smt2` on the `before/` observations | `examples/s3-public-read-policy/expected/z3-before-output.txt` (`SAT — witness: Principal="*"`) and `…/expected/z3-after-output.txt` (`UNSAT`). Reproduced byte-for-byte by running `z3` on the appended facts+query during inventory. |
| **Soufflé** (Datalog) | `souffle-reachability` | Across the SIR triples, how many tuples are anonymous-reachable, self-register-reachable, and privesc-chain-reachable per fixture? | per-predicate `.facts` TSVs produced by `transform.sh` from `stave export-sir --format jsonl` | `examples/souffle-reachability/expected/output.txt` — committed tuple counts per relation per fixture (e.g. `cognito writeup-config: reachable=42, anonymous_reachable=12, self_register_reachable=9`). |
| **Clingo** (ASP) | `clingo-constraints` | Which assets violate the bundled rules — privesc 2-hop, latent compute-trust risk, advanced-security-off, mfa-disabled, unauth-cognito-S3-read, wildcard-action-resource? | Clingo atoms produced from `stave export-sir --format jsonl` via `convert.sh` | `examples/clingo-constraints/expected/output.txt` — committed violation atoms per fixture (e.g. `cognito-writeup: violation: unauth_cognito_s3_read (1)`). |
| **Prolog** | `prolog-proof-trees` | Trace the proof chain anchored at "anonymous reaches X via action Y" through the Cognito identity pool → IAM role → resource edges. | Prolog facts derived from `stave export-sir --format jsonl` | `examples/prolog-proof-trees/expected/output.txt` — committed multi-line proof tree (rooted at `anonymous reaches <arn>`, leaves at IAM grants + resources). |
| **PRISM** (risk model) | `prism-risk-prioritization` | Per attack shape (e.g. `cognito_unauth`, `cognito_self_reg`), what's the probability of successful exploitation given the observed configuration? | observation snapshot directory | `examples/prism-risk-prioritization/expected/output.txt` — committed step probabilities and aggregate P (e.g. `cognito_unauth P = 41.2%`). |

## Engines with working examples (specs not yet written)

| Engine | Example | Question | Fixture | Golden answer source |
|---|---|---|---|---|
| **PySAT** (SAT) | `sat-control-regression` | Can all member controls of a compound chain fail simultaneously on this fixture? | JSONL facts from `stave export-sir --format jsonl` per fixture | `examples/sat-control-regression/expected/output.txt` — per-fixture SAFE/UNSAFE verdicts with fired compound names and member controls. |
| **TLA+** (temporal) | `tlaplus-temporal-safety` | How many reachable states violate safety invariants, and what's the drift margin to the nearest new violation? | JSONL facts from `stave export-sir --format jsonl` via `temporal_check.py`; `.tla` + `.cfg` for TLC | `examples/tlaplus-temporal-safety/expected/output.txt` — per-fixture state counts, initial violations, drift margins, and UNSAFE/AT_RISK verdicts. |
| **Game theory** (cost) | `game-theory-cost` | What's the cheapest attack path, and which remediation has the highest ROI? | JSONL facts from `stave export-sir --format jsonl` via `cost_model.py` | `examples/game-theory-cost/expected/output.txt` — per-fixture attack paths with dollar costs, remediation ROI rankings, and CRITICAL/HIGH/MEDIUM/MINIMAL verdicts. |
| **Evidence packs** (HIPAA/CIS/NIST) | `compliance-evidence` | What's the compliance posture per framework for this fixture? | Assessment output from `stave apply` per (fixture, framework) pair | `examples/compliance-evidence/expected/cognito-writeup-hipaa-technical/executive-summary.md` — single-document PASS/FAIL with control counts and non-compliant citations. |

## Export-format engines without fixture-tied goldens (gap)

| Engine | Status | What's missing |
|---|---|---|
| **STIX 2.1** | Graph exporter in `internal/adapters/graph/marshal_stix.go` ships. `stave graph export --format stix` works. No committed fixture → STIX round-trip with an asserted output. | A `stave graph export --format stix` invocation on a specific fixture with a committed expected STIX document. |
| **JSON-LD / GraphML** | Exporters at `internal/adapters/graph/export_jsonld.go` and `export_graphml.go` ship. `stave graph export --format jsonld|graphml` works. No fixture-tied expected output. | Same as STIX — a committed round-trip with an asserted comparison. |
| **OSCAL / OCSF** | `stave export oscal` and `stave export ocsf` commands ship. No fixture-tied tool output to compare against. | A `stave export oscal` or `stave export ocsf` invocation on a specific fixture with a committed expected document. |

## How the inventory was done

Searches (Phase 1 in the brief):

```bash
find . -name '*.smt2' -not -path './vendor/*'
find . -name '*.dl'
find . -name '*.lp'
find . -name '*.pl'
find . -name 'multi-engine-results.md'
find examples -name 'expected*' -o -name '*.golden'
```

For each candidate, the golden answer was obtained by reading the
committed `expected/*.txt` file. Where the example had a `run.sh`
that re-derives the output, the script was spot-checked but not
re-run end-to-end during inventory (the golden file is the
artifact; the script is the producer).

The nine engines in the first two tables each have:

1. A reproducible input pipeline (`stave export-sir --format <...>`
   plus an example-local conversion script when needed).
2. A committed golden output the trial agent's answer can be
   diffed against.
3. A reasoning chain documented in the example's `README.md`.

The three gap entries have working Go exporters but no committed
fixture-tied golden output. Writing a spec for an engine in the
gap list would require inventing a golden answer, which the brief
explicitly forbids.

## Trial packages

Trial packages under `reasoning-specs/trials/<name>/`, one per
spec. Each package contains:

- `spec.yaml` — the reasoning spec the trial agent reads
- `input.<ext>` — the actual fixture data the spec references
- `export-schema.md` — Stave's export-format documentation for the
  format the input uses

Trial packages are self-contained. The trial agent receives ONE
package directory and nothing else.
