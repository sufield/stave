# Severity Unification Plan

## Problem

Three separate `Severity` types exist in the codebase:

| Package | Type | Backing | Constants | Callers |
|---------|------|---------|-----------|---------|
| `controldef` | `int` (iota) | `SeverityHigh` = 4 | lowercase `"high"` | 15 |
| `securityaudit` | `string` | `SeverityHigh` = `"HIGH"` | UPPERCASE `"HIGH"` | 46 |
| `compliance` | `string` | `High` = `"HIGH"` | UPPERCASE `"HIGH"` | 17 |

All three have `Rank()`, `Gte()`, `ParseSeverity()`, and `String()`.
The `controldef` version is the most complete (has JSON/YAML/Text marshaling).

## Why this matters

- Adding a new severity level requires changes in 3 places
- `securityaudit` and `compliance` use string comparison via `Rank()` maps;
  `controldef` uses int comparison — different performance characteristics
- No compile-time guarantee that a `securityaudit.Severity` and a
  `controldef.Severity` represent the same value

## Recommended approach

1. **Keep `controldef.Severity`** as the single source of truth (int + marshaling)
2. **Delete `compliance.Severity`** — replace with `controldef.Severity` (alias `policy`)
3. **Delete `securityaudit.Severity`** — replace with `controldef.Severity`
4. **Case difference**: `controldef` marshals as lowercase (`"high"`),
   `securityaudit` uses UPPERCASE (`"HIGH"`). The security-audit output
   contract needs to decide: normalize to lowercase (breaking) or add
   uppercase marshaling option to `controldef`.

## Blast radius

| Package | Files | Changes |
|---------|-------|---------|
| `compliance/` | 14 | `compliance.High` → `policy.SeverityHigh` |
| `securityaudit/` | 8 | `securityaudit.SeverityHigh` → `policy.SeverityHigh` |
| `app/securityaudit/` | 10 | Same |
| `cmd/securityaudit/` | 5 | Same |
| `profile/` | 5 | Uses `compliance.Severity` |
| `adapters/output/securityaudit/` | 5 | Same |
| Tests | 20+ | Constant renames |

## Contract decision needed

The security-audit JSON output currently uses UPPERCASE severity:
```json
{"severity": "HIGH", "fail_on": "CRITICAL"}
```

After unification with `controldef.Severity`, it would produce:
```json
{"severity": "high", "fail_on": "critical"}
```

Options:
- **A**: Accept lowercase (breaking change, cleaner)
- **B**: Add `MarshalUppercase()` to controldef.Severity for security-audit output
- **C**: Keep UPPERCASE in security-audit by converting at the output boundary

## Execution order

1. Replace `compliance.Severity` → `controldef.Severity` (smaller, 17 refs)
2. Replace `securityaudit.Severity` → `controldef.Severity` (larger, 46 refs)
3. Delete `compliance/severity.go` and `securityaudit/types.go` Severity section
4. Update all tests
5. Regenerate golden E2E outputs if JSON case changes
