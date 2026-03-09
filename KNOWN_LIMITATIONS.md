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

### DefaultComposition is a mutable package-level variable

**Area:** `cmd/cmdutil/compose/infra.go` — `DefaultComposition`

`DefaultComposition` is an exported `var` holding adapter constructor functions. It is read through convenience functions (`NewObservationRepository`, `NewControlRepository`, etc.) used throughout the command layer. One test (`cmd/diagnose/handler_test.go`) directly replaces its value without synchronization.

This is safe in practice because CLI commands execute sequentially and tests using `t.Parallel()` do not touch it, but it prevents future parallelism and makes the dependency graph implicit.

**Fix:** Inject `Composition` through the `App` struct and pass it to command constructors. Replace the convenience functions with methods on the injected composition. Update the test to pass a custom `Composition` directly to the function under test.

### Other write-once package globals add implicit coupling

**Area:** `cmd/cmdutil/projconfig/config_resolution.go` — `ConfigKeyService`, `cmd/initcmd/alias/commands.go` — `rootCmd`

`ConfigKeyService` is a package-level `var` initialized at load time. `rootCmd` is set via `SetRootCmd()` during app wiring for alias collision detection. Both are effectively write-once and safe in sequential CLI execution, but they create implicit dependencies that complicate testing and prevent parallel test execution.

**Fix:** Pass `ConfigKeyService` as a dependency through command constructors. For `rootCmd`, pass the root command (or a collision-checking interface) as a parameter to `NewAliasCmd()` or `runAliasSet()`.
