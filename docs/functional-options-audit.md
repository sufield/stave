# Functional Options Audit

Audit of the stave codebase for configuration smells where the
Functional Options (`WithXYZ`) pattern would improve readability,
safety, or extensibility.

---

## Existing Best Practices (already correct)

These packages already use functional options well:

| Package | Type | Options Count |
|---|---|---|
| `internal/app/eval/config.go` | `Option func(*EvaluateConfig)` | 11 `WithXYZ` helpers |
| `internal/core/hipaa/control.go` | `Option func(*Definition)` | 6 `WithXYZ` helpers |
| `internal/core/diag/translator.go` | `Option func(*Translator)` | 2 options |
| `internal/sanitize/policy.go` | `Option func(*Sanitizer)` | 2 options |
| `internal/contracts/validator/issues.go` | `Option func(*options)` | 1 option |
| `internal/adapters/output/sarif/finding_writer.go` | `Option func(*FindingWriter)` | SARIF config |

No telescoping constructors (`New*With*`) found anywhere. Good.

---

## Smells Found

### 1. Post-Init Setter: ObservationLoader (HIGH)

**File**: `internal/adapters/observations/loader_core.go:104-109`

Two setters called after construction:
- `SetOnProgress(fn func(processed, total int))`
- `ConfigureIntegrityCheck(manifestPath, publicKeyPath string)`

Plus a public field `OnProgress` that callers mutate directly.

**Call site** (`cmd/apply/deps.go:190`):
```go
loader := observations.NewLoader(validator)
loader.ConfigureIntegrityCheck(manifestPath, keyPath)
```

**Fix**: Convert to functional options on `NewLoader`:
```go
loader := observations.NewLoader(validator,
    observations.WithIntegrityCheck(manifestPath, keyPath),
    observations.WithOnProgress(fn),
)
```

### 2. Post-Init Setter: ControlLoader (MEDIUM)

**File**: `internal/adapters/controls/yaml/loader.go:53`

Has `SetOnProgress(fn)` setter, but the constructor already uses
`LoaderOption` for other fields. Inconsistent — `OnProgress` should
be another `LoaderOption`.

**Fix**: Add `WithOnProgress()` to existing `LoaderOption` type.

### 3. Zero Value Ambiguity: SecurityAudit Request (MEDIUM)

**File**: `internal/app/securityaudit/security_audit_request.go:29-59`

12-field `Request` struct with 8 implicit defaults assigned in
`normalizeRequest()`:

| Field | Default | Ambiguity |
|---|---|---|
| `Now` | `time.Now().UTC()` | Can't distinguish "not set" from "zero time" |
| `StaveVersion` | `"unknown"` | Can't distinguish "not set" from empty string |
| `Cwd` | `"."` | Can't distinguish "not set" from empty string |
| `SBOMFormat` | `spdx` | Zero value is empty string, not a valid format |
| `VulnSource` | `hybrid` | Same |
| `FailOn` | `HIGH` | Same |
| `SeverityFilter` | `[CRITICAL, HIGH]` | nil vs empty slice |
| `OutDir` | auto-generated | Same as Cwd |

**Fix**: Functional options would make defaults explicit and intent clear.

### 4. Large Positional Parameter List: diagnosis.NewInput (LOW)

**File**: `internal/core/evaluation/diagnosis/types.go:78`

8 positional parameters, all required. Single call site. Not a problem
today but adding a 9th parameter would break the only caller.

**Fix**: No action needed now. If it grows, switch to struct literal or
options.

### 5. Post-Init Mutation: Timeline.SetAsset (LOW)

**File**: `internal/core/asset/timeline.go:45`

Internal state mutation during timeline building. Encapsulated within
the package — not a constructor configuration issue.

**Fix**: No action needed. This is internal state management, not
post-init configuration.

---

## Not Smells (reviewed and cleared)

| Location | Pattern | Why it's fine |
|---|---|---|
| `app/eval/build.go` | `BuildDependenciesInput` (23 fields across nested structs) | Well-grouped, all required, single call site |
| `app/diagnose/run.go` | `Config` (6 fields) | All fields are required |
| `app/diagnose/run.go` | `FindingDetailConfig` (nested) | Intentional grouping for specific workflow |
| `app/eval/intent_evaluation.go` | `IntentEvaluationConfig` (boolean flags) | Flags are intentional and documented |

---

## Fixes Applied

1. **ObservationLoader** — Replaced `SetOnProgress` and
   `ConfigureIntegrityCheck` setters with `WithOnProgress` and
   `WithIntegrityCheck` loader options. Removed
   `IntegrityCheckConfigurer` interface from ports.
2. **ControlLoader** — Added `WithOnProgress` to existing `LoaderOption`
   type. Removed `SetOnProgress` setter.
3. **SecurityAudit Request** — Replaced `normalizeRequest()` with
   `NewRequest(...RequestOption)` constructor. 15 `WithXYZ` options
   provide explicit defaults and clear intent at call sites.
4. **diagnosis.NewInput** — Changed from 8 positional parameters to
   `NewInput(Input{...})` struct literal. Extensible without breaking
   callers.
