# Drift Detection

Drift detection answers the CISO's Tuesday question: "We were safe
on Monday. What specifically changed in our configuration that made
us unsafe on Tuesday?"

`stave drift` compares two observation snapshots and reports every
asset-level configuration change — resources added, removed, or
reconfigured. Configuration drift is treated as a violation (exit
code 3), making Stave an infrastructure integrity gate.

## How it works

```bash
stave drift --baseline monday.json --current tuesday.json
```

Stave loads both snapshots, computes property-level diffs for every
asset, and reports changes. The diff engine is deterministic — same
inputs always produce the same output.

### Change types

| Type | Meaning |
|---|---|
| `PROVISIONED` | New resource appeared in current snapshot |
| `DECOMMISSIONED` | Resource present in baseline is missing from current |
| `RECONFIGURED` | Existing resource has property changes |

### Security-relevant highlighting

In text output, attributes related to security posture are prefixed
with `[!]` to help researchers spot attack-relevant changes:

```
Changes:
  [RECONFIGURED] my-bucket
    [!] properties.storage.access.public_read: false → true
    [!] properties.storage.encryption.enabled: true → false
    properties.storage.tags.team: platform → data-eng
```

Highlighted attributes include: `public`, `encrypt`, `logging`,
`audit`, `mfa`, `policy`, `acl`, `iam`, `auth`, `tls`, `ssl`,
`versioning`, `backup`.

### Value redaction

Attributes containing `secret`, `token`, or `credential` have their
values automatically masked as `[REDACTED]` in text output.

## Output formats

### Text (default)

```
Drift Report
------------
Period: 2026-01-01T00:00:00Z → 2026-01-11T00:00:00Z

Summary: 2 changed (1 new, 0 removed, 1 reconfigured)

Changes:
  [PROVISIONED] new-public-bucket
  [RECONFIGURED] my-bucket
    [!] properties.storage.access.public_read: false → true
```

### JSON

```json
{
  "schema_version": "diff.v0.1",
  "kind": "observation_delta",
  "start_time": "2026-01-01T00:00:00Z",
  "end_time": "2026-01-11T00:00:00Z",
  "summary": {
    "provisioned": 1,
    "decommissioned": 0,
    "reconfigured": 1,
    "total": 2
  },
  "changes": [
    {
      "asset_id": "new-public-bucket",
      "action": "PROVISIONED",
      "current_type": "aws_s3_bucket"
    },
    {
      "asset_id": "my-bucket",
      "action": "RECONFIGURED",
      "previous_type": "aws_s3_bucket",
      "current_type": "aws_s3_bucket",
      "drifts": [
        {
          "attribute": "properties.storage.access.public_read",
          "old_value": false,
          "new_value": true
        }
      ]
    }
  ]
}
```

The JSON schema (`diff.v0.1`) is designed for SIEM ingestion —
flat, stable field names, deterministic ordering.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | No drift — baseline and current are identical |
| 2 | Input error — missing file, invalid JSON, schema mismatch |
| 3 | Drift detected — one or more resources changed |

Exit code 3 matches the violation convention used by `stave apply`,
making `stave drift` composable in CI/CD pipelines:

```bash
stave drift -b before-deploy.json -c after-deploy.json || exit 1
```

## CI/CD workflow

### Post-deploy verification

```bash
# Capture baseline before deploy
stave apply --format json > baseline.json

# ... deploy happens ...

# Capture current state after deploy
stave apply --format json > current.json

# Detect drift — exit 3 if anything changed unexpectedly
stave drift --baseline baseline.json --current current.json
```

### Scheduled drift monitoring

```bash
# Daily: compare yesterday's snapshot to today's
stave drift \
  --baseline observations/2026-04-11.json \
  --current observations/2026-04-12.json \
  --format json > drift-report.json
```

## Relationship to other features

| Feature | Question it answers |
|---|---|
| `stave apply` | Is the current state safe? |
| `stave drift` | What changed between two points in time? |
| `stave bisect` | When was a violation first introduced? |
| `stave apply --dry-run` | Are inputs well-formed before evaluation? |

`stave apply` evaluates safety. `stave drift` detects change.
`stave bisect` finds the temporal origin of a violation. Use them
together: drift finds *what* changed, bisect finds *when* the
violation started, apply determines *if* the change made things unsafe.

## Key files

| File | Purpose |
|---|---|
| `cmd/drift/cmd.go` | Top-level drift command |
| `internal/core/asset/drift.go` | ComputeDrift, InfrastructureDrift, DriftSummary |
| `internal/core/asset/drift_diff.go` | DiffAssets, property-level comparison |
