# Plan: Testscript for CLI Behavioral Tests

## Problem

`make clig-check` verifies **metadata** (every command has Long, Example,
exit codes, SilenceUsage). It cannot verify **behavior**: that examples
actually work, that JSON output is valid, that errors go to stderr, or
that NO_COLOR suppresses ANSI codes. These are clig.dev requirements
that only integration tests can prove.

## Strategy: Two Layers

| Layer | Tool | Scope |
|-------|------|-------|
| Metadata linter | `TestCligCompliance` (existing) | All 67 commands: flags, descriptions, exit codes |
| Behavioral tests | `testscript` (new) | Core 10 commands: streams, JSON validity, exit codes, env vars |

## Implementation Plan

### Phase 1: Wire testscript infrastructure

**Add dependency:**
```
go get github.com/rogpeppe/go-internal/testscript
```

**Create test harness in `cmd/stave/main_test.go`:**

```go
package main

import (
    "os"
    "testing"

    "github.com/rogpeppe/go-internal/testscript"
    "github.com/sufield/stave/cmd"
)

func TestMain(m *testing.M) {
    os.Exit(testscript.RunMain(m, map[string]func() int{
        "stave": func() int {
            app := cmd.NewApp()
            if err := app.Root.Execute(); err != nil {
                return cmd.ExitCode(err)
            }
            return 0
        },
    }))
}

func TestScripts(t *testing.T) {
    testscript.Run(t, testscript.Params{
        Dir: "testdata/scripts",
    })
}
```

**Directory structure:**
```
cmd/stave/
  main.go           (existing)
  main_test.go       (new — harness)
  testdata/scripts/  (new — .txtar files)
```

**Makefile target:**
```makefile
## script-test: Run testscript behavioral CLI tests
script-test:
    $(GOTEST) ./cmd/stave/ -run TestScripts -count=1
```

### Phase 2: Core behavioral scripts

Each `.txtar` file tests one clig.dev principle against real commands.

#### `testdata/scripts/streams.txtar`
Verify stdout/stderr separation.

```
# Data goes to stdout, not stderr
exec stave apply --controls controls --observations observations --now 2026-01-11T00:00:00Z --format json
stdout '"schema_version"'
! stderr '"schema_version"'

# No violations case: stderr gets the message
exec stave apply --controls controls --observations observations-clean --now 2026-01-11T00:00:00Z --format json
stderr 'No violations'
```

#### `testdata/scripts/exit_codes.txtar`
Verify exit codes match documentation.

```
# Exit 0 for clean evaluation
exec stave apply --controls controls --observations observations-clean --now 2026-01-11T00:00:00Z --format json

# Exit 3 for violations
! exec stave apply --controls controls --observations observations --now 2026-01-11T00:00:00Z --format json

# Exit 2 for invalid input
! exec stave apply --controls /nonexistent --observations /nonexistent
stderr 'error'
```

#### `testdata/scripts/no_color.txtar`
Verify NO_COLOR compliance.

```
env NO_COLOR=1
exec stave apply --controls controls --observations observations --now 2026-01-11T00:00:00Z --format text
! stdout '\x1b\['

env TERM=dumb
exec stave doctor
! stdout '\x1b\['
```

#### `testdata/scripts/json_validity.txtar`
Verify JSON output is parseable.

```
# apply produces valid JSON
exec stave apply --controls controls --observations observations-clean --now 2026-01-11T00:00:00Z --format json
stdout '"schema_version": "out.v0.1"'
stdout '"safety_status"'

# doctor produces valid JSON
exec stave doctor --format json
stdout '"checks"'

# validate produces valid JSON
exec stave validate --controls controls --observations observations --format json
stdout '"ready"'
```

#### `testdata/scripts/help.txtar`
Verify help discovery.

```
# --help works
exec stave --help
stdout 'Configuration safety evaluator'

# -h works
exec stave -h
stdout 'Configuration safety evaluator'

# Subcommand help
exec stave apply --help
stdout 'Exit Codes'

# Version
exec stave --version
stdout 'stave version'
```

#### `testdata/scripts/determinism.txtar`
Verify deterministic output (same inputs → same output).

```
exec stave apply --controls controls --observations observations --now 2026-01-11T00:00:00Z --format json
cp stdout run1.json

exec stave apply --controls controls --observations observations --now 2026-01-11T00:00:00Z --format json
cp stdout run2.json

cmp run1.json run2.json
```

#### `testdata/scripts/quiet.txtar`
Verify --quiet suppresses output.

```
exec stave apply --controls controls --observations observations-clean --now 2026-01-11T00:00:00Z --quiet --format json
! stderr 'No violations'
```

#### `testdata/scripts/sarif.txtar`
Verify SARIF output format.

```
! exec stave apply --controls controls --observations observations --now 2026-01-11T00:00:00Z --format sarif
stdout '"$schema"'
stdout '"runs"'
```

### Phase 3: Fixture data

Scripts need observation and control fixtures embedded in the .txtar
files (via the `-- filename --` syntax) or symlinked from testdata/e2e.

**Recommended approach:** Create minimal fixtures in each .txtar:

```
-- controls/CTL.TEST.001.yaml --
dsl_version: ctrl.v1
id: CTL.TEST.001
name: Test Control
type: unsafe_state
severity: high
unsafe_predicate:
  all:
    - field: properties.public
      op: eq
      value: true

-- observations/2026-01-10T000000Z.json --
{
  "schema_version": "obs.v0.1",
  "generated_by": {"source_type": "test", "tool": "testscript"},
  "captured_at": "2026-01-10T00:00:00Z",
  "assets": [{"id": "test-bucket", "type": "aws_s3_bucket", "vendor": "aws", "properties": {"public": true}}]
}

-- observations/2026-01-11T000000Z.json --
{
  "schema_version": "obs.v0.1",
  "generated_by": {"source_type": "test", "tool": "testscript"},
  "captured_at": "2026-01-11T00:00:00Z",
  "assets": [{"id": "test-bucket", "type": "aws_s3_bucket", "vendor": "aws", "properties": {"public": true}}]
}

-- observations-clean/2026-01-10T000000Z.json --
{
  "schema_version": "obs.v0.1",
  "generated_by": {"source_type": "test", "tool": "testscript"},
  "captured_at": "2026-01-10T00:00:00Z",
  "assets": [{"id": "safe-bucket", "type": "aws_s3_bucket", "vendor": "aws", "properties": {"public": false}}]
}

-- observations-clean/2026-01-11T000000Z.json --
{
  "schema_version": "obs.v0.1",
  "generated_by": {"source_type": "test", "tool": "testscript"},
  "captured_at": "2026-01-11T00:00:00Z",
  "assets": [{"id": "safe-bucket", "type": "aws_s3_bucket", "vendor": "aws", "properties": {"public": false}}]
}
```

### Phase 4: CI integration

Add to `.github/workflows/ci.yml`:

```yaml
- name: Behavioral CLI tests
  run: make script-test
```

## Scope

**In scope (Phase 1-2):**
- testscript harness wiring
- 8 behavioral scripts covering: streams, exit codes, NO_COLOR, JSON
  validity, help, determinism, quiet, SARIF
- Makefile target
- CI integration

**Out of scope:**
- Testing every command (metadata linter covers that)
- Testing cloud integration (stave is offline-only)
- Interactive TUI tests (stave has no TUI)

## Acceptance Criteria

- `make script-test` runs 8+ .txtar scripts
- Scripts verify behavioral compliance, not metadata
- No overlap with `make clig-check` (complementary, not duplicate)
- CI runs both: `make clig-check && make script-test`
- All scripts pass on current binary

## Dependencies

- `github.com/rogpeppe/go-internal/testscript` (vendored)
- Existing `cmd.NewApp()` and `cmd.ExitCode()` APIs
- Minimal observation/control fixtures (embedded in .txtar)
