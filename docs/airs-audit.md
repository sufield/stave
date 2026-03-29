# Accept Interfaces, Return Structs (AIRS) Audit

Audit of the stave codebase for AIRS violations at package boundaries:
interface returns, concrete over-specification, fat interfaces, boundary
enforcement, and test friction.

---

## Summary

| Category | Scanned | Issues |
|---|---|---|
| New* returning interface | 157 functions | 2 (both intentional) |
| Input over-specification | core + app packages | 0 |
| Fat interfaces (5+ methods) | all interfaces | 0 (largest is 8, cohesive) |
| Package boundary violations | core/app/adapters | 0 (enforced by tests) |
| Test friction | all test files | Minimal, justified |

**No refactoring required.**

---

## Return Audit

Two `New*` functions return interfaces instead of concrete types:

### 1. catalog.NewBuiltInProvider / NewFSProvider

**File**: `internal/app/catalog/provider.go:25-32`

Returns `ControlProvider` interface. The underlying types (`builtInProvider`,
`fsProvider`) are intentionally private — callers select a loading strategy
at runtime. This is correct adapter-pattern usage.

### 2. cel.NewPredicateEval

**File**: `internal/cel/factory.go:10`

Returns `policy.PredicateEval` (a function type alias). The closure
captures a compiled CEL environment. Returning a concrete type would be
meaningless since the value *is* the function.

Both are justified architectural decisions, not oversights.

---

## Input Audit

### HIPAA controls accept asset.Snapshot

Each `Evaluate(snap asset.Snapshot)` implementation accesses only a
subset of the snapshot (iterates `snap.Assets`, checks type and
properties). However, `Snapshot` is a domain value object representing
"the complete observed state." Narrowing the parameter would break
domain semantics for no practical gain.

### Evaluation strategies accept *asset.Timeline

Strategies use Timeline's temporal methods (`CurrentlySafe()`,
`ExceedsUnsafeThreshold()`, etc.) without accessing the underlying
Asset directly. Timeline is the correct abstraction for time-aware
evaluation.

No input over-specification found.

---

## Fat Interface Audit

All interfaces have 4 or fewer methods, with one exception:

### hipaa.Control — 8 methods

```
ID, Description, Severity, ComplianceProfiles, ComplianceRefs,
ProfileRationale, ProfileSeverityOverride, Evaluate
```

All 8 methods are cohesive metadata accessors + one evaluation method.
The interface represents "a compliance control" as a domain concept.
Splitting into `ControlMetadata` + `ControlEvaluator` would create
artificial abstractions — every consumer needs both.

### Key interfaces (well-sized)

| Interface | Methods | Package |
|---|---|---|
| `ObservationRepository` | 1 | `app/contracts` |
| `ControlRepository` | 1 | `app/contracts` |
| `FindingMarshaler` | 1 | `app/contracts` |
| `ContentHasher` | 2 | `app/contracts` |
| `Clock` | 1 | `core/ports` |
| `Digester` | 1 | `core/ports` |
| `IdentityGenerator` | 1 | `core/ports` |

---

## Package Boundary Audit

Two architecture tests enforce dependency direction:

- `internal/core/enginetest/boundary_test.go` — core cannot import
  adapters, app, platform, or cli
- `internal/app/architecture_dependency_test.go` — app cannot import
  adapters, platform, or cmd; adapters may only import `app/contracts`

Both tests scan all non-test `.go` files and fail on violations. They
run on every `make test` invocation.

### Adapter → Core direction

Adapters correctly depend on core types to translate between external
formats and domain objects. This is expected dependency inversion.

---

## Test Friction Audit

Test files import adapter packages only for integration testing (14
total imports, all in `_test.go` files). Unit tests use lightweight
stubs (typically 5-15 lines each).

Largest test helpers are in `internal/core/enginetest/` for evaluation
integration tests — justified by domain complexity.

No excessive setup patterns found.
