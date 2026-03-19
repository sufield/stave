# Audit: Library Substitution & Code Pruning (v0.0.3)

Analysis of "reinvented wheels" in the Stave codebase that can be replaced
by standard Go libraries or specialized packages.

---

## 1. Logic & Evaluation

The CEL migration (iterations 1-5) already removed the largest custom
evaluation layer (~3,000 lines). What remains:

| File/Package | Purpose | LoC | Library Alternative | Net Reduction |
|-------------|---------|----:|---------------------|------:|
| `domain/policy/checks.go` | `Walk()` recursive visitor on predicate tree | 92 | None — domain-specific tree walker | 0 |
| `domain/policy/rule.go` | `ExtractMisconfigurations()` + `collectFields()` | 71 | Could use CEL `EvalDetails` in future | ~40 |
| `domain/asset/scope_filter.go` | Pre-indexed asset filter by tags/IDs | 247 | `slices.ContainsFunc` for simple cases; indexed lookup is faster | 0 |
| `domain/asset/delta_filter.go` | Filter observation deltas | 80 | Already delegates to `samber/lo` | 0 |
| `domain/kernel/sanitizable_map.go` | Map with selective key redaction | 131 | None — security-specific type | 0 |

**Verdict:** No actionable substitutions. The remaining tree-walking and
filtering is domain-specific business logic, not generic algorithms.

---

## 2. Data Validation & Schema

| File/Package | Purpose | LoC | Library Alternative | Net Reduction |
|-------------|---------|----:|---------------------|------:|
| `contracts/validator/` | JSON schema validation + caching | 405 | Already uses `santhosh-tekuri/jsonschema/v6` correctly | 0 |
| `contracts/schema/` | Schema registry with `//go:embed` | 112 | Already minimal | 0 |
| `domain/asset/validation.go` | Cross-snapshot consistency checks | 342 | None — domain validation logic | 0 |
| `safetyenvelope/validate.go` | Output envelope validation | 56 | Uses existing validator | 0 |

**Verdict:** Schema validation is already library-backed. The
`santhosh-tekuri/jsonschema` integration is clean — proper compilation,
caching, and error classification. No protobuf-based schemas are needed
since the data format is JSON/YAML.

Hand-coded validation (`if field == ""`) exists only in domain types where
struct-tag validation would add more complexity than it saves. The
cross-snapshot validation in `asset/validation.go` is a single-pass
analysis that no generic validator could replace.

---

## 3. CLI & Orchestration

| File/Package | Purpose | LoC | Library Alternative | Net Reduction |
|-------------|---------|----:|---------------------|------:|
| `cmd/cmdutil/projconfig/` | Config loading: filesystem + YAML + env resolution | 447 | Viper could replace filesystem discovery + layered resolution | ~200 |
| `cmd/cmdutil/projconfig/config_bridge.go` | Type conversion between config layers | 162 | Eliminate if configservice accepts Evaluator directly | ~150 |
| `cmd/flags.go` | Global flag registration with dynamic defaults | 52 | Standard Cobra pattern | 0 |
| `cmd/cmdutil/compose/resolve.go` | Time/format resolution helpers | 47 | Already minimal | 0 |
| `internal/metadata/cli.go` | CLI constants + URL helpers | 46 | Could be `cmd/` constants | 0 |

### Speculative Commands (dev-only, behind `stavedev` tag)

| Command | LoC | Test Coverage | Risk |
|---------|----:|:---:|------|
| `security-audit` | ~100 | None | HIGH — moved to `make security-audit` |
| `prompt` | 209 | None | HIGH — experimental interactive analysis |
| `docs open` | 182 | None | MEDIUM — platform-dependent browser open |
| `graph` | 249 | None | MEDIUM — coverage visualization |
| `schemas` | ~40 | None | LOW — introspection |
| `controls list` | 193 | None | LOW — discovery tool |

**Verdict:** Config loading is the one area where Viper could eliminate
~350 lines. The current 3-layer abstraction (domain types → evaluator →
projconfig → configservice bridge) is over-engineered for the current
scope. However, the migration cost is medium and the current code works.

No speculative commands should be promoted to prod. The `prompt` command
(209 lines, 0 tests) is the strongest deletion candidate.

---

## 4. Observability & Tracing

| File/Package | Purpose | LoC | Library Alternative | Net Reduction |
|-------------|---------|----:|---------------------|------:|
| `platform/logging/` | `slog` wrapper + sensitive-key sanitization | 399 | Already uses `log/slog` (Go 1.21+) | 0 |
| `internal/cel/trace.go` | CEL-based trace output | 92 | New — replaces 841-line custom trace engine | N/A |
| `internal/doctor/` | Environmental diagnostics | 642 | Table-driven pattern could reduce | ~100 |

**Verdict:** Logging is already `slog`-based. The wrapper adds:
- Deterministic mode (suppress timestamps by default)
- Sensitive-key detection in CLI arguments
- Output routing (stdout for results, stderr for diagnostics)

These are domain policies, not generic logging concerns. OpenTelemetry
would add ~5MB binary size for tracing capabilities not needed by an
offline CLI tool.

The doctor module (642 lines) could be reduced ~100 lines by converting
12 individual `checkFoo()` functions into a table-driven pattern, but the
current modular approach aids readability.

---

## 5. Utility Bloat

| File/Package | Purpose | LoC | Library Alternative | Net Reduction |
|-------------|---------|----:|---------------------|------:|
| `pkg/jsonutil/jsonutil.go` | `WriteIndented()` — 1:1 wrapper around `json.Encoder.SetIndent` | 13 | Inline `json.Encoder` at call sites | ~13 |
| `pkg/fp/fp.go` | `ToSet()`, `SortedKeys()` | 38 | `maps.Keys()` + `slices.Sort()` (Go 1.21+) | ~20 |
| `pkg/maps/value.go` | Typed extraction from `map[string]any` | 149 | None — domain-specific adapter DSL | 0 |
| `pkg/suggest/closest.go` | Levenshtein fuzzy matching for CLI | 90 | External dep (intentionally avoided) | 0 |
| `pkg/timeutil/duration.go` | RFC3339 parsing + user error messages | 55 | `time.Parse()` + custom messages | 0 |
| `platform/fsutil/` | Security-hardened filesystem I/O | 461 | None — custom symlink/traversal guards | 0 |
| `platform/crypto/` | SHA-256 + Ed25519 stdlib wrappers | 176 | Already pure stdlib | 0 |
| `platform/shlex/shlex.go` | POSIX shell tokenization | 117 | `google/shlex` (intentionally avoided) | 0 |
| `platform/identity/runid.go` | Deterministic run ID generation | 44 | Already uses `crypto/sha256` | 0 |
| `platform/state/firstrun.go` | First-run marker file | 38 | Already uses `os.Stat` | 0 |
| `platform/scrub/scrub.go` | Package stub (empty) | 1 | Delete | ~1 |

**Verdict:** Utility packages are lean. The only clear candidates:
- `jsonutil` (13 lines) — pure wrapper, inline at ~50 call sites
- `fp` (38 lines) — `ToSet` and `SortedKeys` are now available via Go 1.21+ stdlib
- `scrub` (1 line) — empty package stub, delete

Total recoverable: ~34 lines. Not worth the churn of 50+ call-site changes
for `jsonutil`.

---

## Summary Table

| File/Package Path | Purpose | Current LoC | Library Alternative | Potential Net Reduction |
|-------------------|---------|------------:|---------------------|------------------------:|
| `cmd/cmdutil/projconfig/config_bridge.go` | Config layer bridging | 162 | Refactor configservice to accept Evaluator | -150 |
| `cmd/cmdutil/projconfig/config_loader.go` | Filesystem config discovery | 220 | Viper | -200 |
| `internal/doctor/checks.go` | 12 individual check functions | 190 | Table-driven pattern | -100 |
| `pkg/jsonutil/jsonutil.go` | `WriteIndented()` wrapper | 13 | Inline `json.Encoder` | -13 |
| `pkg/fp/fp.go` | `ToSet()`, `SortedKeys()` | 38 | `maps.Keys()` + `slices.Sort()` | -20 |
| `domain/policy/rule.go` | Evidence extraction (pre-CEL) | 71 | CEL `EvalDetails` (future) | -40 |
| `platform/scrub/scrub.go` | Empty package stub | 1 | Delete | -1 |
| `internal/cel/trace.go` | CEL trace output | 92 | Already new | 0 |
| `platform/logging/` | slog wrapper + sanitization | 399 | Already uses slog | 0 |
| `contracts/validator/` | JSON schema validation | 405 | Already uses santhosh-tekuri | 0 |
| `platform/fsutil/` | Security-hardened I/O | 461 | None (security-critical) | 0 |
| `platform/crypto/` | SHA-256 + Ed25519 | 176 | Already pure stdlib | 0 |
| **Total potential** | | | | **~524** |

---

## Top 3 High-Impact Actions for "Thin Core"

### 1. Eliminate config bridge layer (-350 lines, medium effort)

Refactor `internal/configservice/` to accept the `app/config.Evaluator`
directly instead of requiring the `projconfig/config_bridge.go` adapter
layer. This collapses a 3-layer abstraction (domain → evaluator →
projconfig → bridge → configservice) into 2 layers (domain → evaluator →
configservice). Eliminates `config_bridge.go` (162 lines) and simplifies
`config_loader.go` (~200 lines).

### 2. Replace evidence extraction with CEL introspection (-40 lines, low effort)

`ExtractMisconfigurations()` in `policy/rule.go` manually walks the
predicate tree to collect field values. CEL's `program.EvalDetails()`
provides this information natively during evaluation. Wire it through the
`TraceResult` and delete the tree-walking evidence collector.

### 3. Delete untested dev commands (-400+ lines, low effort)

The `prompt` command (209 lines, 0 tests) and `docs open` (182 lines,
0 tests) are speculative. They add binary size to `stave-dev` without
proven utility. Delete them and re-add if needed.

---

## What NOT to Change

- **`platform/fsutil/`** — Security-hardened I/O with symlink, traversal,
  and TOCTOU protection. No library replaces this.
- **`platform/logging/`** — Already `slog`-based. The sanitization layer
  is policy, not generic logging.
- **`pkg/maps/value.go`** — Domain-specific typed extraction DSL for
  `map[string]any`. No stdlib equivalent.
- **`pkg/suggest/closest.go`** — Intentionally inlined Levenshtein to
  avoid external dependency.
- **`contracts/validator/`** — `santhosh-tekuri/jsonschema` is used
  correctly with proper caching and error classification.
