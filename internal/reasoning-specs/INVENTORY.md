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

## Engines without working examples (gap)

| Engine | Status | What's missing |
|---|---|---|
| **PySAT** | Code in `examples/engines/pysat/compound_sat.py` (Iter 5 of an earlier brief). No fixture-tied expected output committed. | A `expected/output.txt` produced by running the script on a specific fixture. The Python script does not have a committed reference output beyond what appears as "SAFE" / "UNSAFE" rows in the per-example `multi-engine-results.md` files, which are auto-generated and not the kind of stable golden we can pin a trial against. |
| **TLA+** | Referenced in `multi-engine-results.md` as `AT_RISK` / `UNSAFE today` but no `.tla` spec file ships in `examples/`. | A `.tla` specification file plus a TLC config plus a captured TLC output. The verdicts that appear in `multi-engine-results.md` are produced by a small Python BFS, not by TLC itself. |
| **Game theory** | Same as TLA+ — appears in `multi-engine-results.md` as `$300 attack today` etc. but no Lean-style spec or game-theoretic solver wired. | A solver invocation (e.g. nashpy, gambit) with a payoff matrix derived from the snapshot. The Python in `examples/game-theory-cost/` outputs textual costs but is not adversary-modelled in a verifiable way. |
| **STIX 2.1** | `docs/ontology/examples/chain.stix.json` is a static handwritten example, not a tool-produced artifact. The graph exporter in `internal/adapters/graph/marshal_stix.go` ships, but there is no committed fixture → STIX round-trip with an asserted output. | A `stave export ... --format stix` invocation with a committed expected STIX document the trial agent could reproduce. |
| **JSON-LD / GraphML** | Exporters at `internal/adapters/graph/export_jsonld.go` and `export_graphml.go` ship. No fixture-tied expected output. | Same as STIX — a committed round-trip with an asserted comparison. |
| **OSCAL / OCSF compliance mapping** | Examples at `docs/ontology/examples/assessment.oscal.json` and `finding.ocsf.json` are handwritten reference shapes; no fixture-tied tool output to compare against. | A `stave ... --format oscal` or `--format ocsf` invocation with a committed expected document. |
| **HIPAA / CIS / NIST evidence packs** | `examples/compliance-evidence/` ships per-control evidence dirs (`expected/cognito-writeup-hipaa-technical/` etc.). The generation pipeline runs but the output shape is per-control evidence directories rather than one verdict to compare — not the kind of single-answer golden a trial spec pins against. | A flattened single-document per fixture (e.g. "HIPAA technical safeguards: PASS / FAIL with citations") that the trial could compare to. |

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

The five engines in the first table each have:

1. A reproducible input pipeline (`stave export-sir --format <...>`
   plus an example-local conversion script when needed).
2. A committed golden output the trial agent's answer can be
   diffed against.
3. A reasoning chain documented in the example's `README.md`.

The seven gap entries all have at least one of those three missing.
Writing a spec for an engine in the gap list would require
inventing a golden answer, which the brief explicitly forbids.

## Trial packages

Five trial packages under `reasoning-specs/trials/<name>/`, one per
spec. Each package contains:

- `spec.yaml` — the reasoning spec the trial agent reads
- `input.<ext>` — the actual fixture data the spec references
- `export-schema.md` — Stave's export-format documentation for the
  format the input uses

Trial packages are self-contained. The trial agent receives ONE
package directory and nothing else.
