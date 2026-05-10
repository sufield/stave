# S3 Demo: Security Tool Bypass


Buckets that appear safe to tools relying on APIs the bucket policy denies, plus latent public read exposure masked only by Public Access Block.

## Background

When a bucket policy denies `s3:GetBucketPolicyStatus` or `s3:GetBucketAcl` to the scanning role, security tools cannot determine whether the bucket is safe. Most tools silently pass these buckets. Stave treats the gap as a finding via `CTL.S3.INCOMPLETE.001` — if safety cannot be proven, the bucket is flagged.

Separately, a bucket with Public Access Block enabled may have an underlying policy granting `Principal: "*"`. The bucket is not currently exposed, but removing PAB would immediately make it public. Stave flags this latent exposure.

## Buckets

**`infra-deploy-artifacts`** — bucket policy denies `GetBucketAcl`/`GetBucketPolicyStatus` to scanning roles. PAB is enabled, but safety is unprovable because the scanner cannot read the policy or ACL.

**`marketing-assets-cdn`** — PAB is enabled, but the underlying policy grants `Principal: "*"`. Currently safe only because PAB masks the exposure. One PAB change away from full public access.

## Triggered Controls

| Control | Resource | Description |
|---------|----------|-------------|
| `CTL.S3.INCOMPLETE.001` | infra-deploy-artifacts | Complete Data Required — zero-tolerance |
| `CTL.S3.PUBLIC.005` | marketing-assets-cdn | No Latent Public Read Exposure |

## Expected Findings

2 violations across 2 resources.

---

## Run

```bash
bash run.sh
```

Expected: 8 findings on this fixture.

The runner uses the standard `stave apply` + encoding verification
pipeline. No Docker required — works in the Codespaces devcontainer
or any local checkout with stave built (`make build` in stave/).

## Try it yourself

Replace the JSON files in `fixtures/observations/` with your own
S3 observations and re-run. The bucket-name + property values
update; the schema and the controls do not.

## Provenance

Migrated from `docs-content/demo/scenarios/tool-blind-spot/`. The original
Docker entrypoint surface is deprecated — every scenario it
exposed is now a directory under `examples/demo-s3-*/` with a
runner that works in the unified Codespaces devcontainer.
