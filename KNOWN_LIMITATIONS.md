# Known Limitations

This document tracks known limitations in the Stave CLI that are candidates for future contributor work. Each entry includes the affected area, a description, and a pointer to the relevant code.

## CLI

### ~~Alias expansion does not respect shell quoting~~ ✅ Fixed

**Area:** `cmd/runtime_helpers.go` — `expandAliasIfMatch()`  
**Fixed in:** `cmd/cmdutil/shellwords.go`

`strings.Fields` has been replaced with `cmdutil.ParseShellTokens`, a POSIX
shell-aware tokenizer that handles single quotes, double quotes, and backslash
escapes. Alias values that contain quoted arguments with embedded spaces now
expand correctly.

**Example (previously broken, now works):**

```
stave alias set myalias 'apply --controls "path with spaces/controls"'
stave myalias
# "path with spaces/controls" is now preserved as a single token
```

Malformed alias values (unclosed quotes, trailing backslash) produce a clear
error on stderr instead of silently misexpanding.

---

### ~~Test `t.Skip` may mask regressions~~ ✅ Fixed

**Area:** Various `*_test.go` files

All `t.Skip` call sites have been audited. Two sites that guarded against
conditions that should always hold in CI were converted to `t.Fatal`:

- `cmd/apply/unit_test.go` — "no control YAML files in fixture": the
  `e2e-01-violation/controls/` directory always contains at least one `.yaml`
  file in the repository.
- `cmd/apply/profile_e2e_test.go` — "input file not found": the
  `testdata/e2e/aws-s3-obs-{public,private}/observations.json` files are
  committed to the repository.

The remaining `t.Skip` call sites are genuinely optional and have been left
unchanged:

| File | Reason for keeping `t.Skip` |
|---|---|
| `cmd/doctor/handler_test.go` | `chmod` behaviour is not guaranteed on all CI platforms |
| `internal/adapters/gitinfo/repo_test.go` | Requires the `git` binary to be installed |
| `internal/adapters/input/controls/yaml/loader_test.go` | References a canonical repo path that may not exist outside the main checkout |
| `internal/config/store_test.go` | `os.UserConfigDir()` may be unavailable in some container environments |
| `internal/platform/fsutil/hash_test.go` | Explicitly opted out via `testing.Short()` — creates large sparse files |
| `internal/platform/fsutil/io_test.go` | Symlink tests are unreliable on Windows |

---

### ~~`defaultComposition` is an unexported package-level variable~~ ✅ Fixed (structural)

**Area:** `cmd/cmdutil/compose/infra.go` — `defaultComposition`  
**Fixed in:** `cmd/root.go`, `cmd/bootstrap.go`, `cmd/cmdutil/compose/infra.go`

`App` now owns the composition explicitly via the `Composition compose.Composition`
field, initialised from `compose.DefaultComposition()` in `NewApp()`.
`compose.UseComposition(c)` is called in `App.bootstrap` (the
`PersistentPreRunE` hook) so that all package-level convenience functions
(`NewObservationRepository`, `NewControlRepository`, etc.) delegate through
`App.Composition` for the lifetime of the invocation.

`WireCommands` and `WireMetaCommands` now accept `*App` instead of
`*cobra.Command`, giving them access to all App-level dependencies and
establishing the injection path for future work.

The `compose.OverrideForTest` helper remains available for tests that need
scoped overrides with automatic cleanup.

**Remaining future work:** thread `Composition` through individual command
constructors (apply, validate, verify, diagnose, enforce, prune, etc.) so each
handler receives the composition explicitly rather than reading it from the
package global. This completes the dependency-injection path and enables
parallel test execution across `App` instances.

---

### ~~`ConfigKeyService` is a write-once package global~~ ✅ Fixed

**Area:** `cmd/cmdutil/projconfig/config_resolution.go` — `ConfigKeyService`  
**Fixed in:** `cmd/root.go`, `cmd/commands.go`, `cmd/initcmd/config/`

`App` now holds a `ConfigKeyService *configservice.Service` field, initialised
from `projconfig.ConfigKeyService` in `NewApp()` and passed explicitly to
`initconfig.NewConfigCmd` through `WireCommands`.

The config command tree (`commands.go`, `handlers.go`, `store.go`) no longer
calls the package-level `projconfig.ConfigKeyService` directly:

- `NewConfigCmd(rt, svc)` accepts the service as a required parameter; passing
  `nil` falls back to the package-level default for backward compatibility.
- `configCommand` stores the injected service and passes it to
  `projectConfigStore` and to the `resolveServiceConfigKeyValue` /
  `deleteConfigKeyValue` / `setConfigKeyValue` helpers.
- Shell-completion `ValidArgsFunction` closures use
  `projconfig.ConfigKeyCompletionsFrom(cc.svc)` instead of the global
  `ConfigKeyCompletions()`.
- `projconfig.ConfigKeyCompletionsFrom(svc)` was added alongside the existing
  `ConfigKeyCompletions()` (which now delegates to it) so callers that hold an
  injected service can avoid the package global.