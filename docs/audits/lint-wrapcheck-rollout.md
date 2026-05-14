# wrapcheck Rollout Plan

`wrapcheck` enforces that every error returned from an external package is
wrapped with context via `fmt.Errorf("...: %w", err)`. Without wrapping,
the message bubbles up as `"key not found"` with no clue about which
operation produced it. With wrapping, it's `"apply: evaluate controls:
load control CTL.S3.ACCESS.001: key not found"` — the command, the phase,
the control, the root cause.

Stave shipped `wrapcheck` in the iteration that added this doc. **397
existing production violations are grandfathered** via a `path-except`
exclusion rule in `.golangci.yml`. The rule applies wrapcheck **only**
where the path matches `^internal/core/evaluation/engine/`. New code in
that directory must wrap. Everywhere else, wrapcheck is currently silent.

Every future iteration widens the `path-except` regex by one package
and fixes that package's wrapcheck violations in the same commit.

## Why path-except, not nolint per violation

With 397 violations the per-line `//nolint:wrapcheck` approach would
add 397 trailing comments to the codebase. The path-except exclusion
keeps the noncompliance signal *out of the source*, which means:

- Code reviews see real wrapping behavior, not suppression noise.
- The exclusion list is the to-do list — narrow it package by package.
- When a package lands wrapcheck-clean, it stays clean: new violations
  fail the build.

## Configuration anchor

In `stave/.golangci.yml`:

```yaml
linters:
  enable:
    - wrapcheck
  settings:
    wrapcheck:
      extra-ignore-sigs:
        - .WithHint(            # ui.WithHint annotates an error with a fix hint
        - .WithNextCommand(     # ui.WithNextCommand decorates with a "try X" hint
        - ui.UserError(         # constructs a user-facing error message
        - ui.EnumError(         # constructs a user-facing enum-validation error
      ignore-sig-regexps:
        - func fmt\.Fprint            # output writer; rarely actionable
        - \(io\.Writer\)\.Write
        - \(\*bufio\.Writer\)\.Flush
        - \(\*encoding/csv\.Writer\)\.Error
      ignore-package-globs:
        - encoding/*                  # json/csv marshal at type-boundary
  exclusions:
    rules:
      - linters: [wrapcheck]
        path-except: '^internal/core/evaluation/engine/'
```

The first three blocks (`extra-ignore-sigs`, `ignore-sig-regexps`,
`ignore-package-globs`) are forever — they encode signatures wrapcheck
should systematically skip because wrapping adds no value (UI helpers,
stream writers, JSON marshal at the type layer).

The fourth block (`exclusions.rules` with `path-except`) is the
**rollout switch**. Widen it iteration by iteration.

## Current violation tally (snapshot at rollout)

Distribution measured 2026-05-13 against the full codebase, excluding
test files (which are exempt from most strict linters per the existing
`_test\.go` rule):

| Directory | Violations | Notes |
|---|---:|---|
| `cmd/initcmd/config` | 19 | command flag plumbing |
| `cmd/exempt/cmd.go` | 16 | single file; risk-acceptance commands |
| `internal/platform/fsutil` | 13 | I/O wrappers |
| `cmd/diagnose/artifacts` | 13 | artifact subcommands |
| `internal/adapters/controls` | 11 | YAML / catalog loaders |
| `cmd/initcmd/contextcmd` | 10 | context wiring |
| `cmd/cmdutil/compose` | 10 | factory composition |
| `internal/app/artifacts` | 9 | artifact loaders |
| `internal/adapters/observations` | 8 | snapshot loaders |
| `cmd/prune/hygiene` | 8 | hygiene subcommand |
| ... | | |
| **All other prod directories** | **~280** | spread across 100+ packages |
| **Total prod** | **397** | |
| **In scope today** (`internal/core/evaluation/engine/`) | **0** | fixed in this iteration |

The shape says: the 10 largest directories account for ~30% of the
debt; the long tail is one or two errors per file across a hundred
packages. A naive widen-by-directory cadence will see fast wins on the
top-10 and a long grind on the rest.

## Recommended iteration order

Priority-1 (highest value per fix): packages where an unwrapped error
loses the most context to operators.

1. **`internal/core/evaluation/engine/`** — *DONE in this iteration*.
   Five violations fixed: three `ctx.Err()` returns inside `Assess` /
   `applyControl`, one `ExposureDuration` failure in `finding_gen`,
   one `NewExposureLifecycle` failure in `lifecycles`.
2. `cmd/apply/...` — the primary command. Errors from `compose.*`,
   `dircheck.*`, `app/eval.*`, `app/readiness.*` lose CLI context.
3. `internal/app/eval/...` — the application-layer evaluation
   orchestrator. Wraps engine and adapter errors.
4. `internal/adapters/controls/...` — YAML/catalog loader. Errors
   should name the control file and the field.
5. `internal/adapters/observations/...` — snapshot loader. Errors
   should name the snapshot file and the schema phase.

Priority-2 (medium value): command handlers that present errors to
operators.

6. Remaining `cmd/*` subdirectories.
7. `internal/app/*` outside the eval orchestrator.

Priority-3 (lowest value, longest tail): adapters that already produce
errors with enough internal context that one more layer rarely helps.

8. `internal/adapters/output/*` — formatters.
9. `internal/cli/*` — UI rendering.
10. `internal/platform/*` — file system / logging / fsutil.

## Per-iteration mechanic

For each iteration that widens the scope:

1. Pick one package or subtree from the priority list.
2. Add it to the `path-except` regex by extending the alternation:
   ```
   path-except: '^(internal/core/evaluation/engine/|cmd/apply/)'
   ```
3. Run `make lint` — the new package's violations now fire.
4. Wrap each error with operation + identifier context. Don't create
   helpers unless the same wrapping pattern repeats 5+ times in one file.
5. `make lint` returns to zero issues.
6. Commit. PR title: `lint(wrapcheck): widen enforcement to <package>`.

## When NOT to wrap

Wrapcheck's `extra-ignore-sigs` already lists the systematic
exceptions. For per-call exceptions, add `//nolint:wrapcheck // <reason>`:

- **Sentinel errors returned by design** — `io.EOF`, `errors.Is` markers.
  These are part of the function's contract; wrapping them breaks the
  `errors.Is` test downstream. Justification:
  `//nolint:wrapcheck // sentinel — callers test with errors.Is`.
- **Errors from within the same package** — wrapcheck shouldn't fire,
  but if it does (rare; usually a method on a struct from elsewhere),
  the suppression is fine. Justification:
  `//nolint:wrapcheck // intra-package error, not a boundary crossing`.

Per-violation suppressions in NEW code should be rare. If a package has
to add several `//nolint:wrapcheck` to land, that's a smell — the
package boundary is fuzzy or the helper signatures are too low-level.

## Verification commands

```bash
# Confirm wrapcheck is enabled and runs clean today
cd stave && make lint

# Count remaining violations by directory (run from stave/)
golangci-lint run ./... 2>&1 \
    | grep '(wrapcheck)' \
    | awk -F: '{print $1}' \
    | xargs -I{} dirname {} \
    | sort | uniq -c | sort -rn

# Test that the engine-scope enforcement still works:
# remove the path-except temporarily, expect 397 violations
```
