# Reduction Plan: Surgical Execution

Execution plan to remove ~824 lines of code across three phases,
ordered from lowest risk to highest structural impact.

---

## Phase 1: Dev Cleanup & Utilities (-34 lines, low risk)

### 1a. Inline `pkg/fp/` (38 lines → 0)

**Current state:** 2 functions (`ToSet`, `SortedKeys`), 10 files, 20 call sites.

**Replacements:**

`fp.ToSet[T](items)` — No direct stdlib equivalent. Inline as:
```go
set := make(map[T]struct{}, len(items))
for _, item := range items {
    set[item] = struct{}{}
}
```

`fp.SortedKeys[K, V](m)` — Replace with `slices.Sorted(maps.Keys(m))` (Go 1.23+).

**Affected files (9 non-test):**

| File | Calls | What to change |
|------|------:|----------------|
| `cmd/prune/upcoming/filter.go` | 3 | Inline ToSet for 3 filter sets |
| `cmd/enforce/graph/handler.go` | 1 | Replace SortedKeys |
| `internal/app/eval/filters.go` | 1 | Inline ToSet |
| `internal/app/eval/project_config.go` | 1 | Inline ToSet |
| `internal/app/hygiene/service.go` | 3 | Inline ToSet for 3 risk filter sets |
| `internal/domain/asset/delta_diff.go` | 1 | Replace SortedKeys |
| `internal/domain/asset/tag_set.go` | 2 | Replace SortedKeys |
| `internal/pruner/plan/build.go` | 1 | Replace SortedKeys |

**After:** Delete `internal/pkg/fp/fp.go` and `internal/pkg/fp/fp_test.go`.

**Net:** -38 lines (inline code is ~same length but eliminates the package).

### 1b. Keep `pkg/jsonutil/` (decision: not worth the churn)

**Current state:** 1 function (`WriteIndented`), 31 files, 38 call sites.

**Decision: KEEP.** Replacing 38 call sites with 3-line `json.Encoder`
blocks adds more code than it removes. The wrapper is 13 lines and
provides consistent indentation across the entire codebase. The
package earns its keep.

### 1c. Delete empty `platform/scrub/` stub

**Current state:** Package declaration only (1 line, `scrub.go`).

**Action:** Delete `internal/platform/scrub/scrub.go` if no other files
remain in the directory after the iteration-5 cleanup.

---

## Phase 2: CEL Evidence Extraction (-40 lines, medium risk)

### Current State

Evidence extraction runs as a **post-hoc tree walk** after CEL evaluation:

```
CEL evaluator → boolean (unsafe/safe)
                    ↓ (if unsafe)
ExtractMisconfigurations() → walks UnsafePredicate tree
    → collectFields() → reads each field value from properties
    → produces []Misconfiguration{Property, ActualValue, Operator, UnsafeValue}
```

**Files involved:**

| File | Lines | Role |
|------|------:|------|
| `policy/rule.go` | 71 | `ExtractMisconfigurations` + `collectFields` |
| `policy/fields.go` | 103 | `getFieldValueByParts` + namespace dispatch |
| `policy/misconfiguration.go` | 70 | `Misconfiguration` type + display |
| `engine/finding_gen.go` | 114 | `CreateDurationFinding` + root cause + source evidence |

### CEL EvalDetails Readiness

**CEL-go v0.27.0 does NOT provide field-access tracing.** The `EvalDetails`
return from `Program.Eval()` gives AST state and type-checker diagnostics,
not field-level access logs.

### Recommended Approach: Hybrid

Instead of replacing the tree walker with CEL introspection (which would
require CEL-go instrumentation), **keep the tree walker but simplify it**:

1. **Delete `policy/fields.go`** (103 lines) — the namespace-dispatch field
   resolver that handled `identities.*`, `identity.*`, `params.*`, and
   `properties.*` lookups. This was needed for evaluation; evidence
   extraction only needs property values.

2. **Simplify `collectFields()`** to use direct `properties` map access
   instead of the full namespace-aware resolver. Evidence extraction always
   operates on asset properties — it doesn't need identity or param lookups.

3. **Delete identity field accessors** — `getIdentityField()` (20 lines)
   was only called by the field resolver for evaluation context.

**Net reduction:** ~60 lines (fields.go simplified, identity accessors removed).

**Deferred:** Full CEL introspection replacement. Wait for CEL-go to add
native field-access tracing, or build a custom `logFieldAccess()` CEL
function in a future iteration.

### Verification

- `ExtractMisconfigurations` is called from `finding_gen.go:38`
- The `Misconfiguration` type is used by finding enrichment, output
  formatters, and the diagnose command
- Keep the type and the tree walker; simplify the field resolution

---

## Phase 3: Config Bridge Elimination (-300 lines, high structural impact)

### Current Architecture (4 layers)

```
cobra flags → projconfig.Global() → appconfig.Evaluator → configservice.Service
                                          ↑
                                    config_bridge.go
                                    (162 lines of adapters)
```

**The problem:** `configservice.Service` defines 3 interfaces
(`ConfigValidator`, `ConfigResolver`, `KeepMinResolver`) that are
implemented by adapter types in `config_bridge.go` which convert between
`configservice.Config` ↔ `appconfig.ProjectConfig` on every call.

**The flow for each resolved value:**
```
configservice.Resolver.MaxUnsafe(cfg *Config, cfgPath)
  → ToProjectConfig(cfg)           // convert configservice → appconfig
  → defaultEvaluator()             // lazy-create evaluator
  → .WithProject(projCfg, cfgPath) // inject converted config
  → .ResolveMaxUnsafe()            // actual resolution (env > project > user > default)
  → return ValueSource{...}        // wrap result back
```

This round-trip happens 4 times (once per resolvable field).

### Target Architecture (2 layers)

```
cobra flags → projconfig.Global() → appconfig.Evaluator
                                          ↑
                                    configservice.Service
                                    (takes Evaluator directly)
```

### Execution Steps

**Step 1: Make configservice accept Evaluator directly**

Modify `internal/configservice/config.go`:
- Remove `ConfigValidator`, `ConfigResolver`, `KeepMinResolver` interfaces
- Add `Evaluator *appconfig.Evaluator` field to `Service`
- Resolution methods call `s.Evaluator.Resolve*()` directly

**Step 2: Delete the bridge adapters**

Delete `cmd/cmdutil/projconfig/config_bridge.go` (162 lines):
- `staveConfigValidator`, `staveConfigResolver`, `staveKeepMinResolver` — gone
- `FromProjectConfig`, `ToProjectConfig`, `MutateProjectConfig` — gone
- `CopyProjectConfig` — gone

**Step 3: Update config store**

Modify `cmd/initcmd/config/store.go`:
- Replace `MutateProjectConfig()` calls with direct field mutation on
  `appconfig.ProjectConfig`
- Replace `FromProjectConfig()` calls with direct Evaluator access

**Step 4: Simplify singleton**

Modify `cmd/cmdutil/projconfig/config_resolution.go`:
- `Global()` returns `*appconfig.Evaluator` (already does)
- `ConfigKeyService` is constructed with the Evaluator directly

**Step 5: Update Service construction**

Modify `cmd/root.go`:
- Pass `projconfig.Global()` to `configservice.New(evaluator)` instead
  of the 3 adapter types

### Files Changed

| File | Action | Lines |
|------|--------|------:|
| `cmd/cmdutil/projconfig/config_bridge.go` | DELETE | -162 |
| `internal/configservice/config.go` | Simplify (remove interfaces) | -40 |
| `internal/configservice/service.go` | Simplify (use Evaluator) | -30 |
| `cmd/initcmd/config/store.go` | Update (direct mutation) | -20 |
| `cmd/cmdutil/projconfig/config_resolution.go` | Simplify | -10 |
| Various test files | Update construction | ~+30 |
| **Total** | | **~-230** |

### Risk Mitigation

- The `stave config get/set/delete` commands are the primary consumers
- Run `stave config show` and `stave config get max_unsafe` before/after
  to verify resolution still works
- The 4-layer cascade (env > project > user > default) must produce
  identical results

---

## Summary

| Phase | Target | Lines Removed | Effort | Risk |
|-------|--------|-------------:|--------|------|
| 1a | Inline `pkg/fp/` | -38 | Low | Low |
| 1c | Delete empty `scrub/` | -1 | Trivial | None |
| 2 | Simplify evidence extraction | -60 | Medium | Medium |
| 3 | Config bridge elimination | -230 | High | High |
| **Total** | | **~329** | | |

### Execution Order

1. **Phase 1a** first — mechanical replacement, no behavioral change
2. **Phase 2** next — simplify field resolution, keep tree walker
3. **Phase 3** last — structural refactor, dedicated commit, full regression test

### What NOT to Do

- **Don't inline jsonutil** — 38 call sites, not worth the churn for 13 lines
- **Don't add Viper** — the current YAML loading in `config_loader.go` is
  simpler than Viper's convention-heavy approach
- **Don't wait for CEL introspection** — the tree walker is 40 lines and
  correct; replace it when CEL-go adds field-access tracing
- **Don't delete `config_loader.go`** (220 lines) — filesystem discovery
  and YAML loading is genuine I/O logic, not bridge boilerplate
