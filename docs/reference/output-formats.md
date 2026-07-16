# Output Formats

Stave produces findings in multiple formats. Use `--format` to select.

## Formats

| Format | Flag | Use case |
|--------|------|----------|
| Text | `--format text` | Human reading, grep, terminal |
| JSON | `--format json` | Automation, jq pipelines, API consumption |
| SARIF | `--format sarif` | GitHub Code Scanning, IDE integration |
| JSONL | `--format jsonl` | Streaming, log aggregation, SIEM ingest |

## Schema reference

- **Finding schema**: see [schemas/](../../schemas/README.md)
- **Output envelope** (`out.v0.1`): wraps findings with summary, security state, risk signals
- **Control schema** (`ctrl.v1`): YAML control definition format
- **Observation schema** (`obs.v0.1`): input snapshot format

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success (no violations, or command completed) |
| 2 | Invalid input (bad flags, malformed files) |
| 3 | Violations found (findings exceed threshold) |
| 4 | Internal error |
| 130 | Interrupted (SIGINT) |

Exit 3 is a success — it means the tool found what it was looking for.
