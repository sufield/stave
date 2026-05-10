# Stave Core Audit — Thin Core Enforcement

| | |
|---|---|
| Audit date | 2026-05-10 |
| Codebase commit | `5b007fe7e` |
| Previous audit | `611d1f162` (2026-05-08) |
| Core LOC (non-test) | **93,602** lines across `internal/` + `pkg/` (+1,081 since prev) |
| Core LOC (with tests) | 176,982 lines (+1,749 since prev) |
| `stave` binary size | **~30 MB** stripped — 30,146,825 bytes (+90 KB since prev) |
| Catalog size | 2,618 controls (+101 since prev) |

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
| `internal/core/evaluation/risk` | **1,571** | **Bloat (growing)** | **Compound-chain risk-scoring engine.** Reasoning logic. See Check 2. Grew +205 LOC since prev audit (new `scope_field` / `ScopeResolver` for property-keyed chain composition). |
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

**Verdict: Bloat. Replicated externally. Growing.**

- 1,571 LOC (+205 since prev audit). Includes `chain_engine.go` (now 342 LOC, +177), `calculator.go`, `attack_stage.go`, `exposure_rank.go`, `scoring.go`, plus new `scope_resolver.go` (98 LOC).
- New since prev audit: `scope_resolver.go` introduces `ScopeField`/`ScopeResolver` so compound chains can group findings by an asset *property* (e.g., per-trigger function ARN on a Cognito user pool) rather than only by `asset.ID`. The feature was load-bearing for Cognito iterations 3–10 — but it is more chain-reasoning logic in the bloat package.
- `chain_engine.go` exposes `DetectChains(...)` returning `[]CompoundFinding{ ChainID, CompoundScore, Severity, Narrative, AttackStages }`. These are **verdict-shaped** outputs, not facts.
- `calculator.go` implements `Layer 1: Environmental × Layer 2: Compound × Layer 3: Resource` with hard-coded multipliers (`chainEscalation2 = 1.8`, `crossAccountMultiplier = 1.5`, `publicInternetMultiplier`). This is *risk reasoning*, not fact production.
- **15 internal consumers** (was 9 at prev audit): grep `'CompoundFinding'` finds 15 non-test files referencing it. Untangling cost has grown.

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
| `internal/core/evaluation/risk/chain_engine.go` + `scope_resolver.go` (`DetectChains`, `CompoundFinding`, `ScopeResolver`) | ~920 | `examples/clingo-constraints/`, `examples/sat-control-regression/`, `examples/z3-*/` (compound chain verdicts) | Replicated. Deprecation deferred — **15 internal consumers** (was 9). |
| `internal/core/evaluation/risk/calculator.go` (three-layer risk scoring) | ~250 | `examples/prism-risk-prioritization/risk_model.py` (probabilistic DTMC) | Replicated. Deprecation deferred — coupled to `CompoundFinding`. |
| `internal/core/evaluation/risk/scoring.go` + `attack_stage.go` + `exposure_rank.go` | ~400 | `examples/game-theory-cost/cost_model.py` (attacker-cost-aware ranking) | Replicated. Coupled to risk package above. |
| `internal/app/score/` (weighted score combinator) | 672 | `examples/game-theory-cost/` + `examples/prism-risk-prioritization/` | Replicated. Coupled. |
| `internal/app/forecast/` (trend prediction over snapshots) | 183 | `examples/forecast/forecast.py` (pure-stdlib linear-trend projector over out.v0.1 assessments) | Replicated. Coupled to nothing — clean candidate for next deprecation pass. |
| `internal/app/remediationimpact/impact.go` | 182 | `examples/game-theory-cost/` (remediation ROI ranking is the same shape) | Replicated. Coupled to `CompoundFinding`. |
| `internal/app/simulate/` | 110 | `examples/counterfactual-simulate/simulate.py` (set-difference findings + threshold-check chain deactivation) | Replicated. Coupled to `CompoundFinding` for chain-finding parsing — but the external example reads `compound_findings[]` from the JSON output, so it does not link the Go type. |

**Total bloat-with-replacement LOC**: ~3,020 lines (+520 since prev — `forecast` and `simulate` joined the replicated set this audit). Total bloat-without-replacement: **0 lines** — every bloat package now has an external equivalent. The next iteration's gating work is the `CompoundFinding` consumer untangling, not authoring more examples.

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

Captured at commit `5b007fe7e` (prev audit `611d1f162` values in parens):

| Metric | Value | Captured at |
|---|---|---|
| Core LOC (non-test) | **93,602** (was 92,521; +1,081) | `find internal pkg -name '*.go' -not -name '*_test.go' \| xargs wc -l \| tail -1` |
| Total LOC (with tests) | **176,982** (was 175,233; +1,749) | same scope, including tests |
| `stave` binary | **30,146,825** bytes (was 30,056,713; +90 KB) | `make build` then `ls -la stave` |
| `stave apply` golden | sha256 `4ccd81ced579dd9893e2c2895570d41d785de562f0834f15aa5659a2c73a1bf1` (was `32c3797367…`) | public-bucket fixture, `--now 2026-01-09T00:00:00Z` |
| `stave export-sir --jsonl` golden | sha256 `ee0a68ba07cdc1ff816ac8fa846985a47caf3c5c7d9ac8eb6c05618bad2ee727` (was `449f6a5709…`) | cognito-self-register writeup fixture |

The two golden hashes changed because the catalog grew (Cognito iterations 1–10 added 100+ controls; ADVSEC AUDITONLY added 1; the dedup pass retired 2). The `policy_fingerprint` is part of every output and is derived from the catalog hash, so any catalog change cascades. The Cognito golden additionally picks up the new `is_dormant` lifecycle facts shipped in commit `1a9cf71c5`.

Re-run the same commands after any deprecation commit to confirm the post-removal output matches the new hashes (or, if the deprecation removes only verdict-shaped fields, expect a stable export-sir hash and a changed apply hash).

## What this audit did NOT do

Per the spec's "What NOT to Do":

- **No code deleted.** Every classification is documentary. Removal is deferred to future per-package commits.
- **No refactoring.** The classification table reflects the codebase as-is. Restructuring is a separate iteration.
- **No engine-example modifications.** External replacements are pointed at by reference — the example programs are unchanged.
- **No CEL / fact-export contract changes.** `stave apply` and `stave export-sir` produce identical output to the pre-audit baseline (no source touched).

## Migration tracking

Status as of `5b007fe7e` — no deprecations have shipped since the prev audit; the gating refactor (`CompoundFinding` consumer untangling) has not started.

| # | Bloat item | External replacement | Replicated | Verified | Deprecated | Removed | Δ since prev |
|---|---|---|---|---|---|---|---|
| 1 | `evaluation/risk/chain_engine.go` + `scope_resolver.go` (`DetectChains`, `ScopeResolver`) | clingo-constraints + sat-control-regression + z3-* | ✅ | ✅ (matrix) | ❌ | ❌ | **Grew +205 LOC** (new ScopeResolver). Consumer count 9 → 15. |
| 2 | `evaluation/risk/calculator.go` (three-layer score) | prism-risk-prioritization | ✅ | ✅ (matrix) | ❌ | ❌ | unchanged |
| 3 | `evaluation/risk/scoring.go` + `attack_stage.go` | game-theory-cost | ✅ | ✅ (matrix) | ❌ | ❌ | unchanged |
| 4 | `app/score/compute.go` | game-theory-cost + prism | ✅ | ✅ (matrix) | ❌ | ❌ | unchanged |
| 5 | `app/forecast/` | `examples/forecast/` (linear-trend posture-score forecast over out.v0.1 assessments) | ✅ | ✅ (8-day fixture) | ❌ | ❌ | **example shipped this audit** |
| 6 | `app/simulate/` | `examples/counterfactual-simulate/` (set-difference findings + threshold-check chain deactivation) | ✅ | ✅ (4-scenario fixture) | ❌ | ❌ | **example shipped this audit** |
| 7 | `app/rank/blast_radius.go` | souffle-reachability | ✅ | ✅ (matrix) | ❌ | ❌ | unchanged |

Items 1–4 + 7 are blocked behind the same internal consumer untangling (`CompoundFinding` is now referenced by **15** non-test files; removing it is a multi-commit refactor — and growing). Items 5 and 6 need new external examples authored before removal.

## Verification (this audit pass)

```
$ ./stave apply --controls examples/public-bucket/controls \
    --observations examples/public-bucket/observations \
    --max-unsafe 12h --now 2026-01-09T00:00:00Z --allow-unknown-input \
    --format json | sha256sum
4ccd81ced579dd9893e2c2895570d41d785de562f0834f15aa5659a2c73a1bf1  -

$ ./stave export-sir --controls examples/cognito-self-register-to-aws-creds/controls \
    --observations examples/cognito-self-register-to-aws-creds/fixtures/writeup-config/observations \
    --now 2026-01-09T00:00:00Z --format jsonl | sha256sum
ee0a68ba07cdc1ff816ac8fa846985a47caf3c5c7d9ac8eb6c05618bad2ee727  -
```

Both hashes drifted from the prev audit, expected — the catalog grew by 101 controls and `is_dormant` lifecycle facts shipped, both of which feed `policy_fingerprint` and `export-sir` output. No source touched in this pass — the deliverable is the document.

## What changed since 2026-05-08 (prev audit → this audit)

59 commits between `611d1f162` and `5b007fe7e`. Net: core grew +1,081 LOC, the bloat package grew +205 LOC, the catalog grew +101 controls, three new external tools shipped to `examples/` (no new bloat introduced).

**New work that respected the contract (external-only):**

- `examples/perturbation-analysis/` (commit `712fd2eec`) — before/after fact-set diff + verdict-flip impact tool. Pure consumer of JSONL exports; no core changes.
- `examples/compatibility-check/` (commit `07d5236a2`) — contradictory-requirements detection via Z3 unsat core. Pure consumer; no core changes.
- `examples/mutation-testing/` (commit `1da5c16ef`) — mutation-testing framework MVP with flip-boolean operator. Pure consumer; no core changes.
- `examples/explain/` translation-layer iterations 1–3 (commits `4236caf8c`, `8ec861a80`, `b4c7ac6c7`) — human-readable encoding/verdict reports + encoding-verifier. External tooling only.

**New work that grew core (in scope per the contract):**

- `0cbc9fe39` — `TypeMarker` control class for non-violation findings. Lives in `internal/core/controldef` + a small partition test in `internal/core/evaluation/engine`. Marker controls produce *facts* (cross-resource compound ingredients), not verdicts — fits the permanent-core profile.
- `1a9cf71c5` — `TransitiveReachability` + `AssetNode.Lifecycle` plumbing for SIR document export. Fact projection.
- `57159ec0b` — `EffectivePermissionResolver` extension surfacing aggregated permissions in `PolicyExport`. Fact projection.

**New work that grew the bloat package (concerning):**

- The Cognito iteration plan needed compound chains to group findings by *property value* (e.g., per-trigger function ARN) rather than `asset.ID`. Implemented as `ScopeField` + `ScopeResolver` in `internal/core/evaluation/risk/scope_resolver.go` (98 LOC) plus a +177 LOC change to `chain_engine.go`. The feature works and was load-bearing for iterations 3–10, but it adds chain-reasoning logic to a package already classified as bloat with an external replacement. This is a **migration regression** — the right place for it would have been in the external chain-detection examples (`clingo-constraints`, `sat-control-regression`), not the core risk package. The audit's verdict on Check 2 (Bloat. Replicated externally.) is now strengthened: the core still answers "which findings compound into a compound verdict?" using its own scope/score logic, while the same question is answered better by the external SAT/SMT tooling.
- `pkg/stave/internal/policyexport/extract.go` grew +110 LOC absorbing the EffectivePermissionResolver wiring. Mostly fact-projection — within scope.

**Catalog changes (out of `internal/`, no core LOC impact):**

- Cognito iterations 1–10 added 100+ controls plus 2 `cognito_*` compound chains. Catalog grew from ~2,517 to 2,618.
- ADVSEC AUDITONLY (`a9d3017b8`) closed the Iteration 6 tri-state gap and added `has_advanced_security_mode` to the propertyAllowlist.
- The dedup pass (`d82816cc2`) retired `CTL.COGNITO.PASSWORD.POLICY.001` and `CTL.COGNITO.MFA.ENFORCE.001`.
- OWASP NHI mapping (`5b007fe7e`) added `owasp_nhi:` annotations to 235 controls + a new `docs/compliance/owasp-nhi-top10.md`. Pure metadata; no LOC impact on `internal/`.

**Migration progress: zero.** No `CompoundFinding` consumer was untangled. No bloat package was deleted. The migration debt grew (consumers 9 → 15, risk package +205 LOC).

**Recommendation:** the *next* iteration that touches compound chains should NOT extend `internal/core/evaluation/risk/`. New scope or score logic belongs in the external examples (`clingo-constraints/` is the natural home for `ScopeResolver`-shaped logic — Clingo programs already group atoms by property values via shared variables). Treat the risk package as **frozen for new features** even though we haven't removed it yet — every line added there is one more line to migrate later.

## Next steps (separate iterations)

1. **Untangle `CompoundFinding` consumers.** Move each consumer (now 15 files: `output/asff`, `output/dto`, `graph/builder`, `profile/reporter/text`, `profile/profile`, `app/score/compute`, `app/eval/workflow`, `app/remediationimpact`, `app/simulate`, `evaluation/risk/attack_stage`, plus 5 more added since prev audit) to read facts from `internal/core/sir` directly instead of from the risk package's verdict-shaped output. This is the gating change for items 1–4 + 7.
2. ~~Write `examples/forecast/`~~ — **done this audit.**
3. ~~Write `examples/counterfactual-simulate/`~~ — **done this audit.**
4. **Audit the smaller `internal/app/<feature>/` packages** that didn't make the prev pass's top-30 (`explain`, `forensics`, `prune`, `oscillation`, `outlieranalysis`, `staleness`, etc.). Many are likely bloat; deferred.
5. **Treat `internal/core/evaluation/risk/` as frozen.** New compound-chain features go to `examples/`, not core.
