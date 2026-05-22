# From Steampipe to Stave

You already collect cloud state with Steampipe. This guide turns that
state into a Stave-conforming snapshot and evaluates it.

> **Key point:** Stave evaluates `obs.v0.1` snapshots — a specific
> schema (`schema_version`, `captured_at`, `assets[]` with
> `type`/`vendor`/`properties`). A raw `select *` dump is **not** that
> shape. You map Steampipe columns to Stave property paths with a SQL
> `json_build_object(...)` query, then wrap the rows in a snapshot
> envelope. The full, per-service mapping lives in
> [docs/how-to/generate-snapshots/steampipe.md](../how-to/generate-snapshots/steampipe.md).

## Prerequisites

- Steampipe with the AWS plugin configured
- `jq` for JSON wrapping
- Stave: `go install github.com/sufield/stave/cmd/stave@latest`

## Step 1: Map Steampipe columns to Stave properties

Save a mapping query — e.g. `s3-mapping.sql`. The canonical S3 query is
in the [how-to](../how-to/generate-snapshots/steampipe.md); abbreviated:

```sql
select
  arn          as id,
  'aws_s3_bucket' as type,
  'aws'        as vendor,
  json_build_object(
    'storage', json_build_object(
      'kind', 'bucket',
      'name', name,
      'controls', json_build_object(
        'public_access_block', json_build_object(
          'block_public_acls', block_public_acls,
          'block_public_policy', block_public_policy,
          'ignore_public_acls', ignore_public_acls,
          'restrict_public_buckets', restrict_public_buckets
        )
      ),
      'encryption', json_build_object(
        'algorithm', coalesce(server_side_encryption_configuration->>'SSEAlgorithm', 'none')
      )
    )
  ) as properties
from aws_s3_bucket;
```

This produces one `{id, type, vendor, properties}` row per bucket — the
asset shape Stave's catalog reads.

## Step 2: Wrap the rows into an obs.v0.1 snapshot

`steampipe query --output json` emits an array of rows; wrap it in the
snapshot envelope with `jq`:

```bash
mkdir -p obs
steampipe query "$(cat s3-mapping.sql)" --output json \
  | jq '{schema_version:"obs.v0.1", captured_at:(now|todate), source:"steampipe", assets:.}' \
  > obs/s3.json
```

Validate the shape before evaluating (catches mapping mistakes early):

```bash
stave validate --in obs/s3.json --kind observation --strict
```

## Step 3: Evaluate

```bash
stave apply --observations ./obs/
```

Stave's built-in catalog supplies the invariants; your snapshot
supplies the observed state; the evaluation produces deterministic
verdicts. Exit `0` = clean, `3` = violations found.

## What just happened

```
Steampipe query (mapping)  →  the OBSERVATION   (obs.v0.1 snapshot)
Stave built-in catalog     →  the INVARIANTS    (what "unsafe" means)
stave apply                →  the VERDICTS       (deterministic, reproducible)
```

You own collection (Steampipe); Stave owns evaluation. The mapping is
the contract between them — versioned in your repo alongside the query.

---

**Next:**
- Read the result → [02-first-evaluation.md](./02-first-evaluation.md) (Step 2)
- Triage compound risks → [03-reading-chain-findings.md](./03-reading-chain-findings.md)
