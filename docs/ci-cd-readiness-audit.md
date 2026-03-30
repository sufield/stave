# CI/CD Readiness Audit

Audit date: 2026-03-30

Evaluates stave's readiness to function as a CI/CD gatekeeper in
GitHub Actions, GitLab CI, Jenkins, and similar pipeline environments.

---

## 1. Exit Codes

| Code | Meaning | Usage |
|---|---|---|
| 0 | Success | Clean evaluation, no violations |
| 1 | Security gating | `security-audit` findings exceed `--fail-on` threshold |
| 3 | Violations found | Evaluation completed with findings |
| 2 | Input error | Invalid flags, malformed JSON, missing files |
| 4 | Internal error | Unexpected failure |
| 130 | Interrupted | SIGINT (Ctrl+C) |

**Location**: `internal/cli/ui/error.go:14-21`

**Architecture compliance**: The core returns `(Result, error)`. The
`cmd/` layer maps these to exit codes via `ExitCode(err)`. No
`os.Exit` calls exist in `internal/core/` or `internal/app/` — only
in `cmd/root.go:86` and build tools (`internal/tools/`).

**Verdict**: PASS

---

## 2. Machine-Readable Output Formats

| Format | Flag | Commands | CI Use Case |
|---|---|---|---|
| JSON | `--format json` | apply, diagnose, validate, gate, diff, status, doctor, schemas | Pipeline parsing, artifact storage |
| SARIF | `--format sarif` | apply, security-audit | GitHub Code Scanning tab |
| Text | `--format text` | All commands (default) | Human-readable logs |
| Markdown | `--format markdown` | security-audit, hygiene | PR comments |

**SARIF support**: Full SARIF v2.1.0 output via dedicated writer at
`internal/adapters/output/sarif/finding_writer.go`. GitHub Actions
automatically highlights violations in "Files Changed" tab.

**Architecture compliance**: `internal/` returns `Result` structs.
Output formatting happens in `internal/adapters/output/` adapters.
Zero `fmt.Printf` in core logic.

**Verdict**: PASS

---

## 3. Stdout/Stderr Separation

| Stream | Content | Purpose |
|---|---|---|
| stdout | Findings, JSON, SARIF | Machine consumption (`stave apply > results.json`) |
| stderr | Progress, warnings, hints | Human debugging in CI logs |

**Evidence**: All commands use `cmd.OutOrStdout()` for data and
`cmd.ErrOrStderr()` for messages. The `--quiet` flag suppresses
stderr output. Progress indicators are stderr-only and suppressed
when stderr is not a TTY.

**Testscript verification**: `cmd/stave/testdata/scripts/streams.txtar`
explicitly tests that JSON goes to stdout and messages go to stderr.

**Verdict**: PASS

---

## 4. Environment Variable Configuration

All config keys support environment variable override via `STAVE_*`
prefix:

| Variable | Purpose |
|---|---|
| `STAVE_MAX_UNSAFE` | Override max-unsafe duration |
| `STAVE_CI_FAILURE_POLICY` | Gate failure policy (any/critical) |
| `STAVE_PROJECT_ROOT` | Override project root |
| `STAVE_CONTEXT` | Override context name |
| `STAVE_SNAPSHOT_RETENTION` | Override retention duration |
| `STAVE_RETENTION_TIER` | Override default tier |

**Resolution priority**: Environment > Project config > User config > Default.

**Architecture compliance**: The `Evaluator` accepts an injectable
`Getenv` function. Core logic never calls `os.Getenv` directly —
the `cmd/` layer wires `os.Getenv` at construction time.

**Verdict**: PASS

---

## 5. Determinism

| Feature | Mechanism |
|---|---|
| `--now` flag | Freezes evaluation time for reproducible output |
| Sorted output | Findings sorted by control ID, assets sorted by ID |
| Content hashing | Input hashes in output for verification |
| `stave apply verify` | Byte-for-byte determinism check |

**Testscript verification**: `cmd/stave/testdata/scripts/determinism.txtar`
runs the same evaluation twice and `cmp` verifies identical output.

**Verdict**: PASS

---

## 6. Quiet / Silent Mode

| Flag | Effect |
|---|---|
| `--quiet` | Suppresses all non-essential stderr output |
| `--format json` | Structured output only, no decorations |
| `NO_COLOR` | Disables ANSI escape sequences |
| Non-TTY detection | Automatically suppresses spinners/progress when stdout is not a terminal |

**Verdict**: PASS

---

## 7. No Global Mutable State

All package-level `var` declarations in `internal/` are:
- `//go:embed` filesystem references (immutable)
- Compile-time interface checks (`var _ I = (*T)(nil)`)
- Sentinel errors (`var ErrX = errors.New(...)`)
- Write-once registries initialized at startup
- Lookup tables and regex patterns (immutable)

Zero mutable global state. CI runners can safely run parallel jobs
without race conditions.

**Verdict**: PASS

---

## 8. CI-Specific Commands

| Command | Purpose | CI Workflow |
|---|---|---|
| `stave apply` | Evaluate controls | Gate PRs on violations |
| `stave enforce gate` | Policy-based gating | Block merge on policy failure |
| `stave enforce baseline save` | Snapshot baseline | Track violation count over time |
| `stave enforce baseline check` | Compare to baseline | Fail if violations increase |
| `stave ci diff` | Diff against baseline | Show new/resolved findings in PR |
| `stave validate` | Readiness check | Verify controls + observations before eval |
| `stave security-audit` | Full security audit | Produce SARIF/JSON report |

**Testscript verification**: `cmd/stave/testdata/scripts/ci_workflow.txtar`
exercises the full baseline save/check/gate/diff workflow.

**Verdict**: PASS

---

## 9. `os.Exit` Placement

| Location | Count | Acceptable |
|---|---|---|
| `cmd/root.go` | 1 (via `ExitFunc`) | Yes — CLI entrypoint |
| `internal/tools/genreadme/` | 6 | Yes — build tool, not runtime |
| `internal/tools/gencontroldocs/` | 5 | Yes — build tool, not runtime |
| `internal/core/` | 0 | Correct |
| `internal/app/` | 0 | Correct |
| `internal/adapters/` | 0 | Correct |

**Verdict**: PASS

---

## 10. Logging vs Reporting

| Channel | Content | Consumer |
|---|---|---|
| `slog.Debug` | Step timing, internal decisions | Developer debugging |
| `slog.Info` | Evaluation start/end | CI log visibility |
| stderr | Warnings, hints, first-run messages | CI operator |
| stdout | JSON/SARIF/text findings | Pipeline tools, artifact storage |

Logging uses structured `slog` with `--log-file` support for
capturing debug output without polluting stdout.

**Verdict**: PASS

---

## Summary

| Criterion | Status | Evidence |
|---|---|---|
| Exit codes | PASS | 6 semantic codes, core returns Result+error |
| Machine output | PASS | JSON, SARIF, text, markdown |
| Stdout/stderr | PASS | Data to stdout, messages to stderr, testscript verified |
| Env var config | PASS | STAVE_* variables, injectable Getenv |
| Determinism | PASS | --now flag, sorted output, verify command |
| Quiet mode | PASS | --quiet, NO_COLOR, TTY detection |
| No global state | PASS | Zero mutable globals in internal/ |
| CI commands | PASS | baseline, gate, ci diff, validate |
| os.Exit placement | PASS | Only in cmd/ and build tools |
| Log/report separation | PASS | slog for debugging, stdout for findings |

**Overall: CI/CD READY**

The headless core architecture means stave can be wrapped as a GitHub
Action, Lambda function, or gRPC service without modifying any code
in `internal/`. The CLI is one adapter among potentially many.
