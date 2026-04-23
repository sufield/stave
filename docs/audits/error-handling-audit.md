# Error Handling Audit

Systematic scan of 6 bug patterns across the Stave codebase.
Two rounds of fixes addressed 12 bugs. This audit ensures no
remaining instances require a third round.

## Summary

- **Total occurrences scanned**: 45 discarded errors
- **BUG**: 0 (all bugs from patterns 1-2 were fixed in rounds 1-2)
- **RISK**: 3 (unlikely input but suboptimal outcome)
- **OK**: 42 (intentional or harmless)

## Pattern 1: Discarded Parse Errors — CLEAN

Zero remaining instances. All `time.Parse`, `strconv.*`,
`json.Unmarshal`, `yaml.Unmarshal` calls either handle errors
or were fixed in rounds 1-2.

## Pattern 2: Discarded Function Call Errors

### Load* functions — CLEAN
Zero remaining `Load*` callers with discarded errors. All 10
LoadChains callers now handle errors (2 from round 1, 8 from
round 2). No LoadControls, LoadSnapshots, or other Load*
functions have discarded errors.

### Close() — 10 occurrences, all OK

| Location | Context | Classification |
|---|---|---|
| fsutil/io.go (4) | Cleanup after write failure (error already captured) | OK — best-effort cleanup |
| pruner/fsops/archive.go (3) | Cleanup in archive operations | OK — defer cleanup |
| pruner/repository.go | Cleanup after read | OK — read-only |
| telemetry/export.go | Best-effort cleanup (has //nolint comment) | OK — documented |

All Close() discards occur in cleanup/defer paths where the
primary error is already captured. The round-1 fsutil fix
(errors.Join) covers the critical write+close case.

### Write() — 5 occurrences

| Location | Context | Classification |
|---|---|---|
| cmd/rank/cmd.go (2) | CSV writer to stdout | RISK — CSV write error lost |
| cmd/inventory/cmd.go (2) | CSV writer to stdout | RISK — CSV write error lost |
| profile/reporter/text.go | Write to buffer | OK — in-memory buffer |

The CSV writer discards are low-risk: stdout writes rarely fail,
and when they do (broken pipe), the process is already terminating.

### fmt.Fprintf to stderr — 18 occurrences (ui/runtime.go, ui/progress.go, etc.)

All OK. These are progress/status writes to stderr. Stderr write
failures are unrecoverable — there's nowhere to report them.

### Remaining — 12 occurrences

| Location | Context | Classification |
|---|---|---|
| compliance/prop_helper.go (15) | Type assertions with ok on map values | OK — zero value is correct default |
| app/explain/explain.go | params.Get with discarded ok | OK — empty string is valid fallback |
| cmd/bundle/audit.go | json.MarshalIndent for optional field | OK — empty JSON on error |
| cmdutil/compose/git.go | os.Getwd fallback | RISK — empty base dir on error |

## Pattern 3: Multi-Error Gaps — CLEAN

The round-1 fsutil fix (errors.Join for write+close) is the only
location where sequential errors both matter. No other sequential
error patterns found where both errors carry actionable information.

## Pattern 4: Type Assertions — CLEAN

All type assertions in production code use the `, ok` pattern
(prop_helper.go) or switch statements. The round-1 fix for
`value == true` on `any` type was the only instance. No remaining
unchecked type assertions that could panic.

## Pattern 5: Silent Continues — 10 occurrences, all OK

| Location | Context | Classification |
|---|---|---|
| doctor/platform.go | Skip unsupported platform check | OK — expected |
| app/collect/daemon.go | Log and continue (has CRITICAL comment) | OK — documented |
| app/exemptlapse/lapse.go | Skip invalid entry | OK — item-level skip |
| app/exempt/store.go | Skip malformed entry | OK — item-level skip |
| app/exempt/status.go | Skip unavailable status | OK — item-level skip |
| compliance/policy_helper.go | Skip non-matching policy | OK — expected |
| enforce/graph/run.go | Skip node creation error | OK — best-effort graph |
| trend/metrics.go | Skip metrics computation error | OK — partial results |
| nep/resource.go | Skip resource evaluation error | OK — item-level skip |
| pathinfer/resolver.go | Skip path resolution (fixed in round 1 — now has slog.Debug) | OK — has diagnostic |

All silent continues are in item-processing loops where skipping
one item is correct behavior. The round-1 pathinfer fix added
diagnostic logging for the only case where the skip was truly silent.

## Pattern 6: Nested Structure Handling — No issues found

prop_helper.go handles nested map access with type assertions using
the ok pattern throughout. Type changes at nesting boundaries
produce zero values (correct for optional properties).

## Recommendations

### No additional bugs to fix
All 6 patterns are clean. The 3 RISK items (CSV write, os.Getwd)
are low-impact edge cases not worth fixing.

### Prevention: Enable errcheck linter
Add errcheck to golangci-lint configuration to flag all discarded
errors at CI time. This prevents recurrence.

Recommended `.golangci.yml` addition:
```yaml
linters:
  enable:
    - errcheck
linters-settings:
  errcheck:
    exclude-functions:
      - fmt.Fprintf  # stderr progress writes
      - fmt.Fprintln
      - fmt.Fprint
      - (io.Closer).Close  # defer cleanup
```

This catches future Load*, Parse, and Write discards while allowing
the intentional stderr and cleanup patterns.

### Coding convention
Document in CONTRIBUTING.md:
- Never discard errors from Load*, Parse*, or Unmarshal functions
- Use errors.Join when both write and close errors matter
- Add slog.Debug when falling back from errors in non-critical paths
- Use the `, ok` pattern for all type assertions
