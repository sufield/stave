# Plan: Refactor cmd/diagnose/docs/scanner.go

## Current State

The scanner is already well-structured:
- Hidden directories (`.git`, `.github`) skipped via `strings.HasPrefix(d.Name(), ".")`
- Deduplication via `seen` map on relative paths
- `filepath.ToSlash` used in `relativeDocPath` for cross-platform consistency
- `slices.SortFunc` for deterministic output

## Changes

### 1. Use `cmp.Compare` instead of `strings.Compare`

`strings.Compare` works but `cmp.Compare` is the modern Go 1.21+
idiom used throughout the rest of the codebase.

```go
// Before
slices.SortFunc(files, func(a, b docsFile) int {
    return strings.Compare(a.Rel, b.Rel)
})

// After
slices.SortFunc(files, func(a, b docsFile) int {
    return cmp.Compare(a.Rel, b.Rel)
})
```

### 2. Skip `node_modules` and `vendor` directories

These directories can contain thousands of files and are never
documentation. Add them to the directory skip list.

```go
// Before
if d.IsDir() {
    if strings.HasPrefix(d.Name(), ".") {
        return filepath.SkipDir
    }
    return nil
}

// After
if d.IsDir() {
    name := d.Name()
    if strings.HasPrefix(name, ".") || name == "node_modules" || name == "vendor" || name == "testdata" {
        return filepath.SkipDir
    }
    return nil
}
```

### 3. Key `seen` map by slashed relative path (already done)

The existing code uses `relativeDocPath` (which calls `ToSlash`) as
the key. This is already cross-platform safe. No change needed.

## What NOT to Change

- **No concurrency**: Doc tree is small (~60 files). `WalkDir` is
  fast enough. Adding goroutines for walking adds complexity for no
  measurable gain.
- **No `filepath.EvalSymlinks`**: Stave docs don't use symlinks.
  Adding EvalSymlinks would add a syscall per file for no benefit.
  The `stave-guide/` directory uses symlinks but isn't searched by
  this scanner.
- **No `filepath.Abs` for seen key**: The relative path key is
  correct — two different absolute paths can resolve to the same
  relative path, which is the right dedup behavior.

## Files Changed

| File | Change |
|------|--------|
| `cmd/diagnose/docs/scanner.go` | `cmp.Compare`, skip node_modules/vendor/testdata |

## Acceptance

- `cmp.Compare` used instead of `strings.Compare`
- `node_modules`, `vendor`, `testdata` directories skipped during walk
- `go test ./cmd/diagnose/docs/` passes
- `make script-test` passes
