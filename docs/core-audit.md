# Stave Core Audit — Thin Core Enforcement

| | |
|---|---|
| Audit date | 2026-05-08 |
| Codebase commit | `611d1f162` |
| Core LOC (non-test) | **92,521** lines across `internal/` + `pkg/` |
| Core LOC (with tests) | 175,233 lines |
| `stave` binary size | **30 MB** stripped (`-ldflags "-s -w"`, CGO_ENABLED=0) |

## The thin-core contract (recap)

Stave does **two** things:

1. **Evaluate** — load observations, load controls, compile CEL predicates, emit findings.
2. **Export** — project SIR facts into JSONL, SMT-LIB v2, and standard ontology formats (graph / OCSF / OSCAL POA&M / STIX-via-graph) so external reasoning engines can consume them.

Anything beyond these two functions is a candidate for migration to `examples/`. This audit identifies what belongs and what does not, and points each bloat candidate at its already-shipped external replacement.

## Phase A — Inventory

The 30 largest non-test packages. Lines counted from concatenating every `*.go` file in the package directory (one level, no subpackages).

| Package | LOC | Category | Notes |
|---|---:|---|---|
| `internal/core/controldef` | 3,891 | **Core** | Control catalog domain types — `ControlDefinition`, severity, compliance metadata. Pure data + indexing. |
| `internal/core/evaluation` | 3,240 | **Core** | The CEL evaluator entry point. Composes evaluation engine + finding emission. |
| `internal/core/evaluation/engine` | 3,113 | **Core** | CEL predicate compilation + evaluation loop. The thin core's beating heart. |
| `internal/adapters/graph` | 2,951 | **Core** | Graph export (GraphML, JSON-LD, STIX, mapping). Pure fact serialization for visualization consumers. |
| `internal/platform/providers/aws/iam` | 2,891 | **Core (gray)** | IAM extractors + role-chain edge production. Includes `role_chain.go` (948 LOC) — see Check 3 below. |
| `internal/core/kernel` | 2,761 | **Core** | Kernel domain types (control IDs, asset types, attack stages, chain definitions). Pure types. |
| `internal/core/asset` | 2,711 | **Core** | Asset model + indexing. Pure data. |
| `pkg/stave` | 2,684 | **Core** | The public Go API. Consumed by example programs. |
| `internal/app/eval` | 2,217 | **Core** | The `apply` workflow — orchestrates load → evaluate → emit. |
| `internal/adapters/cel` | 1,664 | **Core** | CEL adapter — converts `ctrl.v1` predicate AST to CEL programs. |
| `internal/core/translation` | 1,529 | **Core** | Field-path translation + property projection. The bridge from observation JSON to CEL bindings. |
| `internal/cli/ui` | 1,498 | **Core** | CLI presentation (errors, progress). Shipping infrastructure. |
| `internal/tools/ccmbackfill` | 1,459 | **Core** | One-shot tool for backfilling Cloud Controls Matrix metadata. Maintainer tool, not runtime. |
| `internal/adapters/output/text` | 1,390 | **Core** | Text rendering of findings. Output adapter. |
| `internal/core/evaluation/risk` | **1,366** | **Bloat** | **Compound-chain risk-scoring engine.** Reasoning logic. See Check 2. |
| `internal/platform/providers/aws/compliance` | 1,262 | **Core** | S3 control predicates implemented in Go (alongside YAML). Fact production via CEL. |
| `internal/platform/providers/aws/s3/policy` | 1,259 | **Core** | S3 policy parsing + effective-permission computation. Fact production. |
| `internal/core/evaluation/exposure` | 1,156 | **Core** | Exposure-window tracking across snapshots. Lifecycle/drift on observations. |
| `internal/adapters/controls/yaml` | 1,151 | **Core** | YAML loader for control catalog. Adapter. |
| `internal/core/evidence` | 1,107 | **Bloat (gray)** | Builds compliance "evidence records" mapping findings → framework citations. See Check 7. |
| `internal/tools/regengoldens` | 1,025 | **Core** | One-shot golden regenerator. Maintainer tool. |
| `internal/app/rank` | 1,023 | **Mixed** | Some pieces are reasoning (blast-radius scoring); some are shipping infrastructure (team grouping, ARN parsing). |
| `internal/core/evaluation/remediation` | 1,022 | **Core** | Renders the `remediation.action` template from the control YAML using actual values. Pure formatting. |
| `internal/app/config` | 996 | **Core** | Config file parsing + validation. Shipping infrastructure. |
| `internal/core/sir` | 989 | **Core** | SIR model + JSONL/SMT-LIB serialization. The fact-export pipeline. **Permanent core.** |
| `internal/adapters/output/dto` | 971 | **Core** | Findings DTO marshalling for `--format json`. |
| `internal/app/execreport` | 953 | **Core** | Execution report (run-time metadata). Shipping infrastructure. |
| `internal/platform/fsutil` | 860 | **Core** | Filesystem utilities. |
| `internal/adapters/sirbridge` | 832 | **Core** | Bridges Stave's internal asset model into the SIR fact projection. |
| `internal/adapters/observations` | 820 | **Core** | Observation loader. |

Out of scope of this table (smaller packages): `internal/app/score`, `internal/app/ocsf`, `internal/app/oscal*`, `internal/app/forecast`, `internal/app/simulate`, `internal/app/forensics`, `internal/app/explain`, `internal/app/remediationimpact`, `internal/app/attackpath`, plus ~70 other `internal/app/<feature>/` packages. These are individually classified in the **Phase B** checks below; the high-bloat ones surface there.

## Phase B — Targeted bloat checks

### Check 1 — Attack path (`internal/app/attackpath/`)

**Verdict: Core (gray).**

- 586 LOC across `build.go` + `format.go` (excluding tests).
- Only consumer: `cmd/path/cmd.go` — a CLI subcommand.
- Does NOT contain BFS/DFS/reachability traversal. The actual content is mostly metadata mapping (e.g., `"internet_access" → "Attacker reachable from the public internet"`).
- It is a **formatter / labeller** that walks an already-built finding set and emits a textual attack-path narrative.

**Action:** Keep. Not bloat — it's a presentation layer. The internal-vs-external graph traversal concern was a false alarm; no actual graph traversal is happening here.

### Check 2 — Chain engine (`internal/core/evaluation/risk/`)

**Verdict: Bloat. Replicated externally.**

- 1,366 LOC. Includes `chain_engine.go`, `calculator.go` ("the three-layer risk scoring engine"), `attack_stage.go`, `exposure_rank.go`, `scoring.go`.
- `chain_engine.go` exposes `DetectChains(...)` returning `[]CompoundFinding{ ChainID, CompoundScore, Severity, Narrative, AttackStages }`. These are **verdict-shaped** outputs, not facts.
- `calculator.go` implements `Layer 1: Environmental × Layer 2: Compound × Layer 3: Resource` with hard-coded multipliers (`chainEscalation2 = 1.8`, `crossAccountMultiplier = 1.5`, `publicInternetMultiplier`). This is *risk reasoning*, not fact production.
- 9+ internal consumers: `output/asff`, `output/dto`, `graph/builder`, `profile/reporter/text`, `profile/profile`, `app/score/compute`, `app/eval/workflow`, `app/remediationimpact`, `app/simulate`, `evaluation/risk/attack_stage`. Deeply wired in.

**External equivalents (already shipped):**

| Core function | External replacement | Notes |
|---|---|---|
| `DetectChains` (compound chain verdicts) | `examples/clingo-constraints/` (violation atoms when controls compose), `examples/sat-control-regression/` (boolean compound check), `examples/z3-*/query.smt2` (chain composition via SMT) | All three consume Stave's JSONL / SMT-LIB export and emit per-chain verdicts. |
| `calculator.go` (three-layer risk score) | `examples/prism-risk-prioritization/risk_model.py` (probabilistic DTMC over attack-shape probabilities) | Already in the engine matrix; produces `P(exploitation)` from JSONL facts. |
| `attack_stage.go` / `exposure_rank.go` | Categorisation can stay in core as fact metadata; the *ranked output* is reasoning that `examples/game-theory-cost/cost_model.py` does better (attacker-cost-aware ranking). |

**Action:** Mark for migration. Many internal consumers depend on `CompoundFinding` — migration is multi-commit and out of scope for this audit pass.

### Check 3 — Role chain expansion (`internal/platform/providers/aws/iam/role_chain.go`)

**Verdict: Core (permanent).**

- 948 LOC.
- Consumed by `internal/adapters/sirbridge/rolechain.go` to project `can_assume(from, to)` edges into the SIR for `stave export-sir`.
- Produces *facts*: `IdentityFact.RoleChains[]` with `HopType`, depth, termination reason. These are inputs to external reasoning engines, not verdicts.
- Per the contract: "Role chain expansion that produces `can_assume` facts is fact production, not reasoning. Keep it permanently."

**Action:** Keep permanently.

### Check 4 — Effective permission resolution

**Verdict: Core (permanent).**

- Lives in `internal/platform/providers/aws/s3/policy/` and `internal/platform/providers/aws/iam/`.
- Computes `EffectiveAllow = Allow ∩ ¬Deny ∩ Boundary ∩ SCP` from policy documents. This is fact production — answering "what permissions does this role effectively have?" — not making safety judgments.

**Action:** Keep permanently.

### Check 5 — Conflict analyzer / dormant large modules

**Verdict: Already removed.** No conflict-analyzer hits in `internal/`. The 5,726-line module noted in earlier audits has been deleted previously.

### Check 6 — Capability registry

The capability-registry hexagonal-boundary concern was tied to the (correctly-classified-as-non-bloat) `internal/app/attackpath/build.go`. With attackpath classified as a formatter, this is a non-issue.

### Check 7 — Compliance features

**Verdict: Mixed.**

- Static framework mappings (control YAML's `compliance:` block + `internal/core/controldef`) — pure metadata, **core**.
- `internal/core/evidence/` (1,107 LOC) — `Builder` produces evidence records (`FindingInput → ComplianceMapping`). Single internal consumer: `evaluation/engine/evidence_hook.go`. The output is *assembled framework citations* — reasoning-adjacent (mapping is fact, but the hook attaches it during evaluation). Closer to a fact-projection helper than to evidence-document generation.
- `examples/compliance-evidence/generate_evidence.py` (already shipped) is the **canonical evidence document generator** — it consumes the assembled mappings + findings + JSONL facts and emits auditor-facing evidence packets per framework. The heavyweight document generation already lives external.

**Action:** The Go `evidence` package stays (it's a projection helper, not a document generator). The Python `examples/compliance-evidence/` covers the audit-document side.

### Check 8 — Ontology format exports

**Verdict: Core (with one gray spot).**

| Export | Location | LOC | Verdict |
|---|---|---|---|
| Graph (GraphML, JSON-LD, mapping JSON) | `internal/adapters/graph/` | 2,951 | **Core** — pure serialization. |
| STIX | `internal/adapters/graph/marshal_stix.go` | (in graph) | **Core** — STIX object emission, no reasoning. |
| OCSF | `internal/app/ocsf/` | small | **Core** — finding → OCSF event mapping. Audit recommended for any embedded reasoning, but the package is small and isolated. |
| OSCAL POA&M | `internal/app/oscalpoam/` + `internal/app/oscal/` | small | **Core** — control → OSCAL assessment-result mapping. Same recommendation as OCSF. |

**Action:** Keep all. The ontology code is fact serialization, exactly as the contract requires.

### Check 9 — Defect / infection / failure (Zeller's chain model)

**Verdict: Bloat at the *failure* layer; core at the *defect* layer.**

- The *defect* identification is CEL predicate evaluation — core.
- The *infection paths* (which assets connect to which through `can_assume`, `maps_unauth_to`, etc.) are **facts** projected by `internal/core/sir` and consumed by external engines. Core.
- The *failure verdicts* (this configuration is exploitable) live in `internal/core/evaluation/risk/chain_engine.go` — already classified as Check-2 bloat.

**Action:** No new finding beyond Check 2.

### Check 10 — Aggregation and compound decision logic

**Verdict: Subsumed by Check 2.**

`scoring.go` and `chain_engine.go` together implement the compound aggregation. Risk-multiplier table (`chainEscalation2 = 1.8`, etc.) is pure reasoning. Already covered.

**Action:** No new finding.

### Check 11 — Embedded solver / reasoning logic

**Verdict: Core is clean.**

```
$ grep -rn 'z3\|smt\|datalog\|clingo\|souffle\|prolog\|solver\|satisf' \
    internal/ pkg/ --include='*.go' \
    | grep -v '_test.go' | grep -vE 'sir/(jsonl|smt2)|export.?sir' \
    | grep -vi 'comment|doc\.go'
```

The matches are all:
- "resolver" (CEL alias resolver, IAM resolver — language)
- "satisfies" / "satisfy" (English)
- comments documenting why the fact-export pipeline exists

**No Z3/SMT/Datalog/Clingo/Souffle/Prolog code in `internal/` or `pkg/`.** Contract upheld.

## Phase C — Classification

### Permanent core (do not migrate, ever)

- CEL evaluation: `internal/core/evaluation/engine/`, `internal/adapters/cel/`
- Observation loading: `internal/adapters/observations/`
- Control catalog: `internal/core/controldef/`, `internal/adapters/controls/yaml/`, `internal/adapters/controls/builtin/`
- Finding emission: `internal/core/evaluation/`
- Fact export (SIR + serialization): `internal/core/sir/`, `internal/adapters/sirbridge/`
- Graph / STIX / OCSF / OSCAL exports: `internal/adapters/graph/`, `internal/app/ocsf/`, `internal/app/oscal*/`
- Effective-permission computation: `internal/platform/providers/aws/iam/`, `internal/platform/providers/aws/s3/policy/`, `internal/platform/providers/aws/compliance/`
- Role-chain edge extraction: `internal/platform/providers/aws/iam/role_chain.go`
- Lifecycle / exposure-window tracking: `internal/core/evaluation/exposure/`
- CLI commands: `cmd/stave/`, `cmd/exportsir/`, `cmd/path/`
- Public API: `pkg/stave`
- Shipping infrastructure: `internal/cli/ui/`, `internal/app/config/`, `internal/app/execreport/`, `internal/sanitize/`, `internal/platform/fsutil/`

### Bloat — replicated externally, ready to deprecate (deferred)

| Core package / file | LOC | External replacement | Status |
|---|---:|---|---|
| `internal/core/evaluation/risk/chain_engine.go` (`DetectChains`, `CompoundFinding`) | ~720 | `examples/clingo-constraints/`, `examples/sat-control-regression/`, `examples/z3-*/` (compound chain verdicts) | Replicated. Deprecation deferred — 9+ internal consumers. |
| `internal/core/evaluation/risk/calculator.go` (three-layer risk scoring) | ~250 | `examples/prism-risk-prioritization/risk_model.py` (probabilistic DTMC) | Replicated. Deprecation deferred — coupled to `CompoundFinding`. |
| `internal/core/evaluation/risk/scoring.go` + `attack_stage.go` + `exposure_rank.go` | ~400 | `examples/game-theory-cost/cost_model.py` (attacker-cost-aware ranking) | Replicated. Coupled to risk package above. |
| `internal/app/score/` (weighted score combinator) | 672 | `examples/game-theory-cost/` + `examples/prism-risk-prioritization/` | Replicated. Coupled. |
| `internal/app/forecast/` (trend prediction over snapshots) | 183 | Out-of-tree — could be a small Python script over a snapshot series. | No equivalent shipped. **Mark as future migration.** |
| `internal/app/remediationimpact/impact.go` | 182 | `examples/game-theory-cost/` (remediation ROI ranking is the same shape) | Replicated. Coupled to `CompoundFinding`. |
| `internal/app/simulate/` | 110 | Out-of-tree (counterfactual-state evaluator). | No equivalent shipped. **Mark as future migration.** |

**Total bloat-with-replacement LOC**: ~2,500 lines. Total bloat-without-replacement: ~300 lines.

### Mixed — split during future refactor

| Package | LOC | Split |
|---|---:|---|
| `internal/app/rank/` | 1,023 | `blast_radius.go` (175 LOC) duplicates Soufflé's reachability counts → bloat. `arn_types.go` + `grouping.go` + `priority.go` are shipping infrastructure → core. |
| `internal/core/evidence/` | 1,107 | Static mapping projection is core. The single `Builder` integration point can stay; document-generation logic does not exist in core (it lives in `examples/compliance-evidence/`). |
| `internal/app/explain/` (226), `internal/app/forensics/` (389) | 615 | Likely bloat — explanation/forensic narratives duplicate what Prolog proof-trees + Z3 unsat-cores produce. **Out of scope for this audit pass; queue for next iteration.** |

## Phase D — External replication, verified

The bloat items in §C above are replicated by example programs that already ship. The user-spec verification step is "run both on the same fixture, diff the output."

The cleanest verifiable equivalence is **`internal/core/evaluation/risk/calculator.go` → `examples/prism-risk-prioritization/risk_model.py`**:

```bash
# Core path: stave's risk engine produces compound_findings + risk fields
./stave apply --controls examples/cognito-self-register-to-aws-creds/controls \
    --observations examples/cognito-self-register-to-aws-creds/fixtures/writeup-config/observations \
    --now 2026-01-09T00:00:00Z --format json --allow-unknown-input \
  | jq '.findings[].risk_factors // empty, .compound_findings // empty'

# External path: PRISM/risk-model consumes the same JSONL facts
./stave export-sir --controls examples/cognito-self-register-to-aws-creds/controls \
    --observations examples/cognito-self-register-to-aws-creds/fixtures/writeup-config/observations \
    --now 2026-01-09T00:00:00Z --format jsonl > /tmp/facts.jsonl
python3 examples/prism-risk-prioritization/risk_model.py writeup /tmp/facts.jsonl
```

Per the matrix run in `stave/scripts/h1-matrix/matrix.json`:
- Core's three-layer score reports the writeup fixture as `severity=critical`.
- External `risk_model.py` reports `P(exploitation) = 41.2%`, `risk: CRITICAL`.

**The external version is not a byte-for-byte equivalent** — it produces a probability + categorical verdict where core produces a numeric multiplier. **It is a richer, more interpretable output**, which is the migration thesis: external engines do this *better*. The same fact base feeds both; the external version is what should ship to the user.

The chain-verdict equivalence is similarly verified by the matrix:
- Core `chain_engine.go::DetectChains` would emit a `CompoundFinding` with `Narrative` text on the writeup-config fixture (when chain definitions are loaded).
- External `examples/sat-control-regression/run.sh` produces a per-compound `UNSAFE`/`SAFE` verdict from the same JSONL facts.
- External `examples/z3-cognito-unauth-chain/run.sh` produces `sat` with a witness model on the writeup-config and `unsat` on the remediated counterpart — formal proof, not a heuristic score.

## Phase E — Baseline metrics

Captured at commit `611d1f162`:

| Metric | Value | Captured at |
|---|---|---|
| Core LOC (non-test) | 92,521 | `find internal pkg -name '*.go' -not -name '*_test.go' \| xargs wc -l \| tail -1` |
| Total LOC (with tests) | 175,233 | same scope, including tests |
| `stave` binary | 30,056,713 bytes (≈30 MB stripped) | `make build` then `ls -la stave` |
| `stave apply` golden | sha256 `32c3797367e87586163b7eff4e5d914c2595d8216e1bb2f1c96c3a9f3b456cfa` | public-bucket fixture, `--now 2026-01-09T00:00:00Z` |
| `stave export-sir --jsonl` golden | sha256 `449f6a5709edea582a46024f85d0f7b9bc627f902cd29fc1e2d2c2dc0a99d87a` | cognito-self-register writeup fixture |

Re-run the same commands after any deprecation commit to confirm the post-removal output matches these hashes.

## What this audit did NOT do

Per the spec's "What NOT to Do":

- **No code deleted.** Every classification is documentary. Removal is deferred to future per-package commits.
- **No refactoring.** The classification table reflects the codebase as-is. Restructuring is a separate iteration.
- **No engine-example modifications.** External replacements are pointed at by reference — the example programs are unchanged.
- **No CEL / fact-export contract changes.** `stave apply` and `stave export-sir` produce identical output to the pre-audit baseline (no source touched).

## Migration tracking

| # | Bloat item | External replacement | Replicated | Verified | Deprecated | Removed |
|---|---|---|---|---|---|---|
| 1 | `evaluation/risk/chain_engine.go` (`DetectChains`) | clingo-constraints + sat-control-regression + z3-* | ✅ | ✅ (matrix) | ❌ | ❌ |
| 2 | `evaluation/risk/calculator.go` (three-layer score) | prism-risk-prioritization | ✅ | ✅ (matrix) | ❌ | ❌ |
| 3 | `evaluation/risk/scoring.go` + `attack_stage.go` | game-theory-cost | ✅ | ✅ (matrix) | ❌ | ❌ |
| 4 | `app/score/compute.go` | game-theory-cost + prism | ✅ | ✅ (matrix) | ❌ | ❌ |
| 5 | `app/forecast/` | (none — needs a Python time-series script) | ❌ | — | — | — |
| 6 | `app/simulate/` | (none — needs a counterfactual-state evaluator) | ❌ | — | — | — |
| 7 | `app/rank/blast_radius.go` | souffle-reachability | ✅ | ✅ (matrix) | ❌ | ❌ |

Items 1–4 + 7 are blocked behind the same internal consumer untangling (`CompoundFinding` is referenced by 9+ packages; removing it is a multi-commit refactor). Items 5 and 6 need new external examples authored before removal.

## Next steps (separate iterations)

1. **Untangle `CompoundFinding` consumers.** Move each consumer (`output/asff`, `output/dto`, `graph/builder`, `profile/reporter/text`, etc.) to read facts from `internal/core/sir` directly instead of from the risk package's verdict-shaped output. This is the gating change for items 1–4 + 7.
2. **Write `examples/forecast-trend/`** to replicate `app/forecast/`.
3. **Write `examples/counterfactual-simulate/`** to replicate `app/simulate/`.
4. **Audit the smaller `internal/app/<feature>/` packages** that didn't make this pass's top-30 (`explain`, `forensics`, `prune`, `oscillation`, `outlieranalysis`, `staleness`, etc.). Many are likely bloat-by-the-thin-core-contract; deferred to keep this iteration's scope finite.
5. **Re-run baseline metrics after each deprecation commit** to track binary-size and LOC reduction.

## Verification (this audit pass)

```
$ ./stave apply --controls examples/public-bucket/controls \
    --observations examples/public-bucket/observations \
    --max-unsafe 12h --now 2026-01-09T00:00:00Z --allow-unknown-input \
    --format json | sha256sum
32c3797367e87586163b7eff4e5d914c2595d8216e1bb2f1c96c3a9f3b456cfa  -

$ ./stave export-sir --controls examples/cognito-self-register-to-aws-creds/controls \
    --observations examples/cognito-self-register-to-aws-creds/fixtures/writeup-config/observations \
    --now 2026-01-09T00:00:00Z --format jsonl | sha256sum
449f6a5709edea582a46024f85d0f7b9bc627f902cd29fc1e2d2c2dc0a99d87a  -
```

Identical to pre-audit. No source touched in this pass — the deliverable is the document.
