# Telemetry Bridge

`stave telemetry` converts assessment output into structured NDJSON —
one JSON object per line, consumable by any log shipper or time series
database. This bridges Stave's deterministic reasoning into the
operational governance systems that business stakeholders already use.

## How it works

```bash
# Pipe from apply
stave apply --format json | stave telemetry

# From file
stave telemetry --in assessment.json

# Filter to critical findings only
stave telemetry --in assessment.json --severity critical,high
```

Each finding becomes one NDJSON line with a stable schema:

```json
{"schema_version":"telemetry.v1","captured_at":"2026-01-11T00:00:00Z","control_id":"CTL.S3.PUBLIC.001","control_name":"Public Bucket Access","severity":"critical","resource_id":"arn:aws:s3:::prod-phi","resource_type":"aws_s3_bucket","verdict":"violation","policy_fingerprint":"sha256:b75f334c843a","status":"NON_COMPLIANT"}
```

## Why NDJSON

In air-gapped and high-security environments (healthcare, government,
financial services), you cannot push to a cloud-hosted database. You
write to a file. A data diode or one-way transfer moves it across
the security boundary. NDJSON supports append-only streaming — results
are appended one line at a time without re-parsing the entire file.

Every major log shipper treats NDJSON as native input:
- Vector: `source.file` with `codec: "ndjson"`
- Fluent Bit: `parser: json`
- Splunk Universal Forwarder: `KV_MODE = json`
- Logstash: `json` codec

## Schema: telemetry.v2

| Field | Type | Description |
|-------|------|-------------|
| `schema_version` | string | `"telemetry.v2"` |
| `captured_at` | RFC3339 | Evaluation timestamp |
| `control_id` | string | Control that fired |
| `control_name` | string | Human-readable name |
| `severity` | string | critical/high/medium/low |
| `resource_id` | string | Asset identifier |
| `resource_type` | string | Asset type |
| `verdict` | string | `"violation"` |
| `policy_fingerprint` | string | Control set hash (catalog-wide) |
| `control_fingerprint` | string | Per-control logic hash (ID + severity + type + predicate) |
| `environmental_score` | float | `base_impact x sensitivity x exposure` (nil when inputs missing) |
| `window_id` | string | Violation window ID (null in single-assessment mode) |
| `status` | string | Overall security state |

### Two fingerprints for governance drift

`policy_fingerprint` changes when ANY control is added, removed, or
modified. `control_fingerprint` changes when THIS control's logic or
severity changes. Together they catch:
- Catalog-level deletion (fingerprint changes, control disappears)
- Control logic change (control fingerprint changes, catalog stable)
- Genuine posture improvement (both fingerprints stable, violations drop)

### Violation window tracking

In `--history` mode (directory of assessment JSONs), `window_id`
groups all events in the same continuous violation period for a
specific (control, resource) pair. Format:
`<resource_id>/<control_id>/<window_start_RFC3339>`

State transitions:
- Finding appears → new window opens, new window_id assigned
- Finding persists → same window_id reused
- Finding disappears → window closes
- Finding reappears → new window with new window_id

### Environmental score

Computed from `risk.Environmental(base_impact, sensitivity, exposure)`:
- `base_impact`: from control params (default 5)
- `sensitivity`: from asset data classification tag (phi=3.0, production=2.0)
- `exposure`: from control exposure vector (public=2.0, vpc=1.0)

## Three audiences

**Engineers** receive the CLI finding — actionable, per-resource, with
remediation steps. This already exists via `stave apply`.

**Auditors** receive the logic trace — the formal proof of how each
verdict was reached (via `stave apply --trace`).

**Leadership** receives the dashboard — violation trends by severity,
MTTR tracking, compliance trending. The telemetry bridge delivers
exactly this without requiring a new security tool.

## Relationship to other features

| Command | Purpose |
|---------|---------|
| `stave apply` | Evaluate current safety state |
| `stave rank` | Prioritize remediation from assessment |
| `stave telemetry` | Stream findings to dashboards and SIEM |
| `stave bundle` | Package evidence for air-gap GRC |

## Key files

| File | Purpose |
|------|---------|
| `cmd/telemetry/cmd.go` | CLI command |
| `internal/app/telemetry/event.go` | TelemetryEvent schema |
| `internal/app/telemetry/mapper.go` | Assessment → NDJSON mapper |
