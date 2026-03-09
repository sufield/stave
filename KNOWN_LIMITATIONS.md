# Known Limitations

This document tracks known limitations in the Stave CLI that are candidates for future contributor work. Each entry includes the affected area, a description, and a pointer to the relevant code.

## CLI

### Alias expansion does not respect shell quoting

**Area:** `cmd/runtime_helpers.go` — `expandAliasIfMatch()`

Alias values are tokenized with `strings.Fields`, which splits on whitespace without respecting shell quoting rules. Alias values that contain quoted arguments with embedded spaces will not tokenize correctly.

**Example:**

```
stave alias set myalias 'apply --controls "path with spaces/controls"'
stave myalias
# "path with spaces/controls" is split into three tokens instead of one
```

**Fix:** Replace `strings.Fields` with a shell-aware tokenizer that handles single quotes, double quotes, and backslash escapes (e.g., POSIX `shellwords` parsing).

### Test `t.Skip` may mask regressions

**Area:** Various `*_test.go` files

Some tests use `t.Skip` to bypass execution when preconditions are not met (e.g., missing fixtures, unavailable binaries). If the precondition is expected to always hold in CI, a `t.Skip` can silently hide a real regression.

**Fix:** Audit `t.Skip` call sites and convert to `t.Fatal` where the precondition should always be satisfied in CI. Reserve `t.Skip` for genuinely optional tests (e.g., integration tests that require external services).

### defaultComposition is an unexported package-level variable

**Area:** `cmd/cmdutil/compose/infra.go` — `defaultComposition`

`defaultComposition` is an unexported `var` holding adapter constructor functions. It is read through convenience functions (`NewObservationRepository`, `NewControlRepository`, etc.) used throughout the command layer. Tests that need to override it use `compose.OverrideForTest(t, ...)` which restores the original via `t.Cleanup`.

This is safe in practice because CLI commands execute sequentially, but it prevents future test parallelism and makes the dependency graph implicit.

**Fix (future):** Inject `Composition` through the `App` struct and pass it to command constructors. Replace the convenience functions with methods on the injected composition.

### ConfigKeyService is a write-once package global

**Area:** `cmd/cmdutil/projconfig/config_resolution.go` — `ConfigKeyService`

`ConfigKeyService` is a package-level `var` initialized at load time with stateless dependencies. It is effectively immutable and safe in sequential CLI execution, but creates an implicit dependency.

**Fix (future):** Pass `ConfigKeyService` as a dependency through command constructors.
