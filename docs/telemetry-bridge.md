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

## Schema: telemetry.v1

| Field | Type | Description |
|-------|------|-------------|
| `schema_version` | string | `"telemetry.v1"` |
| `captured_at` | RFC3339 | Evaluation timestamp |
| `control_id` | string | Control that fired |
| `control_name` | string | Human-readable name |
| `severity` | string | critical/high/medium/low |
| `resource_id` | string | Asset identifier |
| `resource_type` | string | Asset type |
| `verdict` | string | `"violation"` |
| `policy_fingerprint` | string | Control set hash for governance drift detection |
| `status` | string | Overall security state |

The `policy_fingerprint` enables governance drift detection: if a
CISO's violation count drops but the fingerprint changed, a control
may have been removed rather than the posture genuinely improving.

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
