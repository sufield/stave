# S3 Demo: Data Governance and Lifecycle


Backup bucket missing data classification, lifecycle rules, MFA delete, versioning, and Public Access Block -- a cascade of governance failures that compounds risk.

## Background

Data governance controls enforce organizational policies that prevent silent compliance drift. A bucket tagged `backup: true` and `data-retention: 7-years` declares its intent, but without the technical controls to match, the declaration is empty. Missing data classification means sensitivity-gated controls silently pass. Missing lifecycle rules mean data persists indefinitely. Missing MFA delete means any principal with delete permission can permanently destroy backup versions.

## Bucket

**`backup-compliance-archive`** -- tagged for backup and retention but missing every governance control. No data-classification tag, no versioning, no MFA delete, no lifecycle rules, and no Public Access Block.

## Triggered Controls

| Control | Description |
|---------|-------------|
| `CTL.S3.GOVERNANCE.001` | Data Classification Tag Required |
| `CTL.S3.VERSION.001` | Versioning Required |
| `CTL.S3.VERSION.002` | Backup Buckets Must Have MFA Delete |
| `CTL.S3.LIFECYCLE.001` | Retention-Tagged Buckets Must Have Lifecycle Rules |
| `CTL.S3.CONTROLS.001` | Public Access Block Must Be Enabled |

## Run

```bash
bash run.sh
```

Current expected output is in `expected/output.json`.

The runner uses the standard `stave apply` + encoding verification
pipeline. No Docker required — works in the Codespaces devcontainer
or any local checkout with stave built (`make build` in stave/).

## Try it yourself

Replace the JSON files in `fixtures/observations/` with your own
S3 observations and re-run. The bucket-name + property values
update; the schema and the controls do not.

## Provenance

Migrated from `docs-content/demo/scenarios/data-governance/`. The original
Docker entrypoint surface is deprecated — every scenario it
exposed is now a directory under `examples/demo-s3-*/` with a
runner that works in the unified Codespaces devcontainer.
