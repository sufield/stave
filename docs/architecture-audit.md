# Architecture Right-Sizing Audit

Audit date: 2026-03-30

---

## Phase 1: Quantitative

| Metric | Value |
|---|---|
| Total production LOC | 59,321 |
| Total test LOC | 63,232 |
| Total Go files | 1,048 |
| HIPAA source files (no tests) | 22 |
| HIPAA total files (with tests) | 42 |
| Packages | 171 |
| Avg imports per package | 9.7 |
| Avg conditionals per HIPAA file | 4.6 |
| Direct + transitive dependencies | 31 |
| Test-to-production ratio | 1.07:1 |

---

## Phase 2: Structural (Decision Matrix)

### 1. Testability: "Do you need real files or complex mocks to test a HIPAA rule?"

**No.** All 14 HIPAA control tests use in-memory `asset.Snapshot`
structs with `map[string]any` properties. Zero test files touch the
filesystem. Zero mocking frameworks are imported. Tests are 5-line
stubs satisfying interfaces.

Verdict: AIRS is implemented and working.

### 2. Repetition: "Do you touch more than 2 files to add a new control?"

**No.** Adding a new HIPAA control requires exactly 1 file (the control
+ `init()`) and optionally 1 test file. The auto-discovery profile
system picks it up from `ComplianceProfiles("hipaa")` metadata. The
profile file (`hipaa.go`) has zero references to individual control IDs.
This was verified when implementing 4 new controls in one commit —
only the control files were created, no registry or profile changes.

Verdict: Registry + auto-discovery pattern eliminates maintenance friction.

### 3. Integration: "Could this logic be called from something other than a CLI?"

**Yes.** The entire evaluation pipeline lives in `internal/core/` and
`internal/app/` with zero imports from `cmd/` or `cobra`. The
`app/workflow.Evaluate()` function accepts domain types and returns
domain types. The architecture boundary test (`architecture_dependency_test.go`)
enforces this at CI time. The existing `stave evaluate` command and
`stave apply` command are two separate CLI adapters calling the same core.

Verdict: Headless core is implemented and enforced.

### 4. Complexity: "Does a typical HIPAA check have 3+ conditional branches?"

**Yes.** Average is 4.6 conditionals per HIPAA source file. Examples:
- ACCESS.001: checks 4 BPA flags + account-level BPA fallback (5 branches)
- RETENTION.002: routes severity by Object Lock mode (COMPLIANCE/GOVERNANCE/none)
- CONTROLS.001.STRICT: checks algorithm + key ID + AWS-managed key alias

Verdict: Complexity justifies dedicated package structure.

### 5. Concurrency: "Does processing take longer than 2 seconds?"

**No.** Full evaluation pipeline (apply with violations) completes in
under 200ms. Testscript build + execute under 1.5s. No concurrency
patterns are needed for the evaluation path.

Verdict: Sequential processing is sufficient. No errgroup/channels needed.

---

## Phase 3: Recommendation

### Decision Matrix Result

| Criterion | Approach A (<2K LOC) | **Approach B (2-10K LOC)** | Approach C (>10K LOC) |
|---|---|---|---|
| Total LOC | | | 59K (production) |
| HIPAA checks | | 14 controls + 3 compound | |
| Future API/Lambda | | Yes (headless core) | |
| Complexity per check | | Yes (avg 4.6 branches) | |
| Concurrency needed | No | | |
| External API calls | | | No (offline-only) |

### Verdict: **Approach B — "Modular Tool"** (with elements of C in scale)

The codebase is at **59K LOC** which exceeds the 10K threshold for
Approach C by scale, but the architecture choices are firmly Approach B:

- **Headless core**: enforced by architecture tests
- **Registry + auto-discovery**: adding a control = 1 file
- **AIRS**: all tests use in-memory snapshots, no mocking frameworks
- **No concurrency needed**: offline-only, sub-200ms evaluations
- **No external API calls**: extractors produce `obs.v0.1` JSON externally

The scale (59K LOC) comes from breadth (171 packages covering
evaluation, diagnosis, remediation, exposure, security audit, CI
integration, snapshot management, enforcement) rather than depth in any
single control. The HIPAA control layer itself is lean (22 source files,
~1,200 LOC) — the rest is the evaluation engine, CLI, and adapters.

### What would trigger a move to Approach C

- Adding live AWS API calls to the evaluation path (rate limiting needed)
- Processing 1000+ controls in a single run (concurrency for file I/O)
- Adding a gRPC/REST server mode (DI factories for client lifecycle)

None of these are on the current roadmap. The architecture is
right-sized.

---

## Summary

| Question | Answer | Pattern Used |
|---|---|---|
| Testability | In-memory only | AIRS (Accept Interfaces, Return Structs) |
| Repetition | 1 file per control | Registry + auto-discovery |
| Integration | Core is headless | Architecture boundary tests |
| Complexity | 4.6 branches avg | Dedicated package structure |
| Concurrency | Not needed (<200ms) | Sequential processing |
| **Overall** | **Approach B** | **Modular Tool — correctly sized** |
