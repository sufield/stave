# Observation Format (obs.v0.1)

Stave evaluates **observations** — point-in-time JSON snapshots of cloud
configuration. The format is `obs.v0.1` (alias `obs.v1`). One file per
capture moment; multiple files in a directory form a time series the
engine reads in chronological order.

## Minimal valid observation

```json
{
  "schema_version": "obs.v0.1",
  "captured_at": "2026-05-17T00:00:00Z",
  "source": "deployed",
  "assets": [
    {
      "id": "arn:aws:s3:::example-bucket",
      "type": "aws_s3_bucket",
      "vendor": "aws",
      "properties": {
        "storage": {
          "kind": "bucket",
          "access": {
            "public_read": true
          }
        }
      }
    }
  ]
}
```

## Required fields

| Field | Type | Notes |
|---|---|---|
| `schema_version` | string | Must be `"obs.v0.1"` or `"obs.v1"`. |
| `captured_at` | RFC 3339 timestamp | The moment this snapshot was taken. UTC. |
| `assets` | array | Per-asset properties; may be empty but must be present. |

## Optional but commonly-set fields

| Field | Type | Notes |
|---|---|---|
| `source` | string | One of `"deployed"`, `"planned"`, `"local"`. Tells the engine whether this is reality, a Terraform plan, or a local dev snapshot. |
| `generated_by.source_type` | string | Collector identifier. Stave rejects observations missing this UNLESS `--allow-unknown-input` is passed. |
| `generated_by.tool` | string | Collector name (e.g. `"steampipe"`). |
| `generated_by.tool_version` | string | Collector version. |

## Per-asset fields

| Field | Type | Notes |
|---|---|---|
| `id` | string | Canonical resource identifier — typically the ARN for AWS. Stable across snapshots. |
| `type` | string | Asset-type slug (e.g. `aws_s3_bucket`, `aws_iam_role`). The catalog's `applicable_asset_types` declarations match this. Run `stave contract show --list` for the full set. |
| `vendor` | string | `aws` \| `gcp` \| `azure` \| etc. |
| `properties` | object | The per-asset property tree. Free-form; controls read from `properties.<path>` via CEL. |

## Properties tree

The properties tree is asset-type-specific. The per-asset JSON schema
under `schemas/observation/v1/asset-types/<type>.schema.json` declares
which properties the catalog reads, but `additionalProperties: true` is
set everywhere — extra fields don't fail validation. (They are just
unused by controls.)

To find what properties the catalog reads for a given asset type:

```bash
stave contract show --asset-type aws_iam_role --format json | jq '.property_paths[].path'
```

To validate an observation before evaluating it:

```bash
stave validate --in observations/*.obs.json --kind observation --strict
```

## What schema validation catches, what it doesn't

Schema validation catches **structure** — wrong types, missing required
fields, unknown additional properties at the top level.

Schema validation does **not** catch **values** — if the collector sets
`access.public_read: false` for a bucket that IS public, the schema is
happy and Stave reports the bucket as private. Value correctness is the
collector's responsibility; see `docs/architecture/boundaries.md` for
the full discussion.

## Common collector-set computed booleans

Some property paths are computed by the collector after walking the
inventory. These are **agent-not-fixable** at observation time — you
can't synthesize the answer from a single Steampipe row.

| Path | Meaning | Computed by |
|---|---|---|
| `identity.policy.has_ghost_resource_refs` | Policy references a deleted resource | Collector cross-inventory walk |
| `identity.trust_policy.has_wildcard_principal` | Trust policy admits `Principal: "*"` | Collector policy walk |
| `identity.permission_drift.threshold_exceeded` | Granted permissions exceed used permissions by N% | Collector + Access Advisor API |
| `identity.access_advisor.available` | Access Advisor data was collected | Collector |
| `storage.access.public_read` | Bucket effectively allows public read | Collector PAB + policy + ACL composition |
| `storage.tags.data-classification` | Operator-set tag | Operator (via tag-resource API) |

If `stave gaps` returns one of these as missing and you cannot extend
the collector, escalate to the operator with the gap report.

## Multi-snapshot time series

Stave's duration-based controls (credential TTL, observation
freshness, unsafe-duration thresholds) need **at least two snapshots**
in the same directory. Each file represents one moment in time;
filenames are by convention `<RFC3339>.obs.json`. Example:

```
observations/
├── 2026-05-15T00:00:00Z.obs.json
├── 2026-05-16T00:00:00Z.obs.json
└── 2026-05-17T00:00:00Z.obs.json
```

The engine reconstructs each asset's lifecycle by joining on `id`
across snapshots. An asset present in N-1 but absent in N is treated
as decommissioned at time N.
