# Output Formats

Stave supports multiple output formats for different use cases.

## JSON

```bash
stave apply --controls testdata/e2e/e2e-01-violation/controls --observations testdata/e2e/e2e-01-violation/observations --format json
```

Structured output following the `out.v0.1` schema. Machine-readable, suitable for piping to `jq` or ingestion by other tools. Results go to stdout; errors and logs go to stderr. Text is the default format; pass `--format json` explicitly.

```bash
# Count violations
stave apply --controls testdata/e2e/e2e-01-violation/controls --observations testdata/e2e/e2e-01-violation/observations | jq '.summary.violations'

# List violated resource IDs
stave apply --controls testdata/e2e/e2e-01-violation/controls --observations testdata/e2e/e2e-01-violation/observations | jq -r '.findings[].resource_id'

# Get unique violated control IDs
stave apply --controls testdata/e2e/e2e-01-violation/controls --observations testdata/e2e/e2e-01-violation/observations | jq -r '.findings[].control_id' | sort -u
```

## Text

```bash
stave apply --controls testdata/e2e/e2e-01-violation/controls --observations testdata/e2e/e2e-01-violation/observations --format text
```

Human-readable output for terminal use. Includes color when the terminal supports it (respects `NO_COLOR` environment variable).

## SARIF

```bash
stave apply --controls testdata/e2e/e2e-01-violation/controls --observations testdata/e2e/e2e-01-violation/observations --format sarif
```

SARIF v2.1.0 output for integration with GitHub Code Scanning, VS Code SARIF Viewer, and other SARIF-compatible tools. Supports `--baseline` for baseline state comparison.

## Quiet Mode

```bash
stave apply --controls testdata/e2e/e2e-01-violation/controls --observations testdata/e2e/e2e-01-violation/observations --quiet
```

Suppresses all output. Use the exit code to determine the result:
- `0` = no violations
- `3` = violations found

## Writing Output to a File

```bash
stave apply --controls testdata/e2e/e2e-01-violation/controls --observations testdata/e2e/e2e-01-violation/observations > evaluation.json
```

Redirect stdout to persist output. Errors and logs still go to stderr.

## Validation Output

The `validate` command defaults to text output but supports JSON:

```bash
stave validate --controls testdata/e2e/e2e-01-violation/controls --observations testdata/e2e/e2e-01-violation/observations --format json
```

```json
{
  "schema_version": "validate.v0.1",
  "valid": true,
  "errors": [],
  "warnings": [],
  "summary": {
    "controls_checked": 10,
    "snapshots_checked": 2,
    "resource_observations_checked": 15,
    "identity_observations_checked": 0,
    "context_provided": false
  }
}
```

## Coverage Graph Output

The `graph coverage` command outputs in DOT (default) or JSON format:

```bash
# DOT graph (pipe to graphviz)
stave graph coverage --controls testdata/e2e/e2e-01-violation/controls --observations testdata/e2e/e2e-01-violation/observations | dot -Tpng > coverage.png

# JSON output
stave graph coverage --controls testdata/e2e/e2e-01-violation/controls --observations testdata/e2e/e2e-01-violation/observations --format json | jq .
```

## Downstream Artifacts

Stave can generate enforcement artifacts from evaluation results:

| Command | Output |
|---------|--------|
| `stave enforce --in eval.json --out ./dir --mode pab` | `dir/enforcement/aws/pab.tf` |
| `stave enforce --in eval.json --out ./dir --mode scp` | `dir/enforcement/aws/scp.json` |

## Severity Mapping

| Stave severity | SARIF level | Code Scanning display |
|---|---|---|
| critical | error | Error (red) |
| high | error | Error (red) |
| medium | warning | Warning (yellow) |
| low | note | Note (blue) |
| info | note | Note (blue) |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success (no violations, or command completed) |
| 1 | Security-audit gating (findings exceed `--fail-on` threshold) |
| 2 | Invalid input (bad flags, malformed files) |
| 3 | Violations found |
| 4 | Internal error |
| 5 | Indeterminate (no violations but data gaps exist) |
| 6 | Attestation failed (tampered or unsigned when required) |
| 130 | Interrupted (SIGINT) |

Exit 3 is a success — it means the tool found what it was looking for.

## Logging

Logs go to stderr and are separate from command output:

```bash
# Verbose logging
stave apply --controls testdata/e2e/e2e-01-violation/controls --observations testdata/e2e/e2e-01-violation/observations -v

# Debug logging
stave apply --controls testdata/e2e/e2e-01-violation/controls --observations testdata/e2e/e2e-01-violation/observations -vv

# doctest:skip — creates run.log in working tree
# JSON logs to file
stave apply --controls testdata/e2e/e2e-01-violation/controls --observations testdata/e2e/e2e-01-violation/observations --log-format json --log-file run.log

# Include timestamps (breaks determinism)
stave apply --controls testdata/e2e/e2e-01-violation/controls --observations testdata/e2e/e2e-01-violation/observations --log-timestamps
```
