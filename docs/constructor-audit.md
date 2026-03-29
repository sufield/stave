# Constructor Pattern Audit

Audit of the stave codebase for non-idiomatic constructor patterns:
incomplete state, long parameter lists, factory bloat, interface
returns, and stuttering names.

---

## Summary

| Category | Scanned | Issues Found |
|---|---|---|
| Incomplete state (bare literals + field assignment) | 629 files | 0 |
| Long parameter lists (4+ params on New*) | 157 New* functions | 7 found, all justified |
| Factory method bloat (switch in New*) | 157 New* functions | 0 |
| New* returning interface | 157 New* functions | 2, both intentional |
| Stuttering names (pkg.NewPkg) | 157 New* functions | 0 |
| Bare struct literals in production code | 629 files | 10, all acceptable |

**No refactoring required.** The codebase is clean.

---

## Detail

### Incomplete State

No instances of `&Type{}` followed by mandatory field assignments in
production code. All bare literals are either zero-value types (runners,
scanners) or use the functional options pattern.

### Long Parameter Lists

7 constructors with 4+ parameters. All have distinct types and clear
roles:

| Function | Params | Location |
|---|---|---|
| `NewRunner(celEval, loadCtl, writer, clock, rt)` | 5 | `cmd/apply/profile.go:70` |
| `NewBuilder(logger, opts, params, sio)` | 4 | `cmd/apply/deps.go:65` |
| `NewCmd(obsRepo, ctlRepo, celEval, rt)` | 4 | `cmd/apply/validate/cmd.go:62` |
| `NewCmd(obsRepo, ctlRepo, celEval, rt)` | 4 | `cmd/apply/verify/cmd.go:20` |
| `NewEvaluator(proj, projPath, user, userPath)` | 4 | `internal/app/config/evaluator.go:23` |
| `NewArtifactWriter(outDir, opts, stdout, fs)` | 4 | `internal/app/fix/artifacts.go:52` |
| `NewAssetEvalContext(a, params, parser, ids...)` | 4 | `internal/core/controldef/predicate.go:31` |

None are boolean/nil traps — parameters are distinct types.

### Factory Method Bloat

No switch-case factories found. Good separation of concerns.

### Interface Returns

Two `New*` functions return interfaces:

1. `cel.NewPredicateEval() (policy.PredicateEval, error)` — returns
   closure-based implementation. Justified: the interface is the point.
2. `catalog.NewBuiltInProvider(fn) ControlProvider` and
   `catalog.NewFSProvider(repo, dir) ControlProvider` — polymorphic
   loading strategies. Justified: caller selects strategy at runtime.

Both follow "accept interfaces, return structs" in spirit — the
returned types are private structs satisfying public interfaces for
dependency injection.

### Stuttering Names

None found. Examples of clean naming:
- `sanitize.New()` not `sanitize.NewSanitize()`
- `lint.NewLinter()` describes purpose, not package

### Existing Good Patterns

- **Functional options**: 11 packages use `type Option func(*T)` with
  `New(opts ...Option)` pattern
- **Builder pattern**: `cli/ui/error.go` uses `WithTitle().WithAction()`
  chaining
- **Dependency injection**: CLI layer consistently injects factories
  rather than concrete types
