# S3 Demo: HIPAA Multi-Violation


PHI (Protected Health Information) bucket with multiple HIPAA compliance failures: no encryption at rest, no transport encryption, no KMS key management, no access logging, no versioning, no object lock, and no Public Access Block.

## Background

HIPAA requires technical safeguards for electronic PHI including encryption, audit logging, integrity controls, and access controls. A single S3 bucket tagged for PHI data can accumulate many compliance violations simultaneously. Stave evaluates all applicable controls and reports each gap independently, giving compliance teams a clear remediation checklist.

## Bucket

`patient-records-east` — PHI bucket tagged with `data-classification: phi` and `compliance: hipaa`. Every security control is missing or disabled.

## Triggered Controls

| Control | Description |
|---------|-------------|
| `CTL.S3.ENCRYPT.001` | Encryption at Rest Required |
| `CTL.S3.ENCRYPT.002` | Transport Encryption Required |
| `CTL.S3.ENCRYPT.003` | PHI Buckets Must Use SSE-KMS with Customer-Managed Key |
| `CTL.S3.ENCRYPT.004` | Sensitive Data Requires KMS Encryption |
| `CTL.S3.LOG.001` | Access Logging Required |
| `CTL.S3.VERSION.001` | Versioning Required |
| `CTL.S3.LOCK.001` | Compliance-Tagged Buckets Must Have Object Lock |
| `CTL.S3.CONTROLS.001` | Public Access Block Must Be Enabled |

## Expected Findings

8 violations on 1 resource.

---

## Run

```bash
bash run.sh
```

Expected: 15 findings on this fixture.

The runner uses the standard `stave apply` + encoding verification
pipeline. No Docker required — works in the Codespaces devcontainer
or any local checkout with stave built (`make build` in stave/).

## Try it yourself

Replace the JSON files in `fixtures/observations/` with your own
S3 observations and re-run. The bucket-name + property values
update; the schema and the controls do not.

## Provenance

Migrated from `docs-content/demo/scenarios/hipaa-compliance/`. The original
Docker entrypoint surface is deprecated — every scenario it
exposed is now a directory under `examples/demo-s3-*/` with a
runner that works in the unified Codespaces devcontainer.
