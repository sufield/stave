# Plan: Diff Options — Domain-Level Change Type Validation

Replace the inline switch validation in `parseChangeTypes` with a
domain-level `IsValid()` method on `asset.ChangeType`, matching the
validation pattern used by `OutputKind`, `Schema`, `ControlType`,
`Severity`, and `PrincipalScope` throughout the codebase.

## Changes

### 1. Add IsValid to asset.ChangeType

**Problem**: `parseChangeTypes` validates change types with an inline
switch against the three known constants. Every other validated domain
type (`OutputKind`, `Schema`, `ControlType`, `Severity`) uses an
`IsValid()` method. If a fourth change type is added to the domain,
`parseChangeTypes` silently rejects it.

**Change**: Add `IsValid()` to `asset.ChangeType` in
`internal/core/asset/delta.go`:

```go
// IsValid reports whether ct is a recognized change type.
func (ct ChangeType) IsValid() bool {
    switch ct {
    case ChangeAdded, ChangeRemoved, ChangeModified:
        return true
    default:
        return false
    }
}
```

### 2. Use IsValid in parseChangeTypes

```go
// Before (options.go:92-95)
ct := asset.ChangeType(val)
switch ct {
case asset.ChangeAdded, asset.ChangeRemoved, asset.ChangeModified:
    out = append(out, ct)
default:
    return nil, &ui.UserError{...}
}

// After
ct := asset.ChangeType(val)
if !ct.IsValid() {
    return nil, &ui.UserError{
        Err: fmt.Errorf("invalid --change-type %q (supported: added, removed, modified)", s),
    }
}
out = append(out, ct)
```

## No Change Needed

### Slice pre-allocation

`make([]asset.ChangeType, 0, len(raw))` + `append` is already
optimal. The `append` capacity check is a single branch — switching
to index-based assignment would require a separate length counter
for the same benefit. No change.

### Flag-changed checks

`ToConfig` doesn't need to distinguish default from user-set for
`--observations`. The path is normalized in `Prepare` and used
as-is. No change.

### Error unwrapping

`ui.UserError` already implements `Unwrap() error`, so
`errors.Is`/`errors.As` work through the chain. No change.

### Sanitizer placement

Sanitizer was moved to the `runner` in the prior commit
(`10fad06`). Config no longer carries it. No change.

## Files Changed

| File | Change |
|------|--------|
| `internal/core/asset/delta.go` | Add `IsValid()` method on `ChangeType` |
| `cmd/enforce/diff/options.go` | Replace switch with `ct.IsValid()` |

## Acceptance

- `ChangeType.IsValid()` covers all three constants
- `parseChangeTypes` uses `IsValid()` instead of inline switch
- `go vet ./...` clean
- `make test` zero failures
