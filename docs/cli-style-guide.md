# CLI Style Guide

This guide keeps Stave CLI output consistent, readable, and automation-friendly.

## Rules

1. Prefer explicit flags over ambiguous positional arguments.
2. Keep command/flag names in kebab-case.
3. Preserve script-safe behavior:
   - machine output on stdout
   - messaging/errors on stderr
4. Use stable exit codes from `internal/cli/ui`.
5. Never require prompts for normal operation.
6. Reserve `-v/--verbose` for verbosity and use `--version` for version display.
7. Use lowercase, concise descriptions for commands/flags and avoid trailing periods.
8. Prefer explicit flags over multiple positional args for clarity and ordering flexibility.

## Help format

Each public command help should include:

1. Purpose
2. Inputs
3. Outputs
4. Exit codes
5. Examples (most common first)

Recommended example order:

1. basic local usage
2. automation/CI usage
3. troubleshooting/fix usage

## Input policy

- Prompts are optional only. Every prompted value must have a non-interactive flag/arg bypass.
- Do not require users to `cd` to a directory when a path flag is practical.
- Keep recurring flags consistent across commands:
  - `--controls` / `-i`
  - `--observations` / `-o`
  - `--format` / `-f` when applicable
  - `--force` for destructive overwrite behavior
  - `--dry-run` for side-effect commands

## Output format policy

- Human-first defaults are acceptable, but machine-readable output must be available where useful.
- Prefer one stable convention per command family (`--format text|json` or equivalent).
- Human-readable output should remain grep-friendly.
- JSON output should remain stable for automation and jq-based pipelines.

## Human-readable command output

For text-mode output, prefer this section order:

1. `Summary`
2. Key details/findings/diagnostics
3. `Next step`

`Next step` should provide one actionable command.

## Error messaging

Use structured errors in both JSON and text paths with:

- error code
- short title
- description
- fix/action
- URL for more information

Stack traces must not be shown by default. Detailed debugging output is enabled via verbosity flags.

## Visual behavior

- Keep text output plain and grepable.
- Use progress updates only when stderr is a TTY.
- Respect `NO_COLOR` and `--no-color`.

## New command checklist

1. Help includes purpose, inputs, outputs, exit codes, examples.
2. Uses consistent recurring flags and aliases where applicable.
3. Supports non-interactive usage (no required prompt).
4. Keeps stdout/stderr separation.
5. Provides machine-readable output when command output is consumed by tooling.
6. Adds `--dry-run` if command writes/modifies files or generates artifacts.
