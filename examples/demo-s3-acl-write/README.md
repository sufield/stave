# S3 Demo: ACL-Based Public Write


User upload bucket where ACL grants write to any authenticated AWS user. The bucket policy looks clean — policy-only scanners miss this entirely.

## Background

ACL-based access is a legacy S3 mechanism that many security tools overlook because they focus on bucket policies. When an ACL grants `WRITE` to `AuthenticatedUsers`, any AWS account holder can upload objects to the bucket, enabling data injection and content manipulation.

**Based on:** HackerOne reports #98819 (Shopify), #128088

## Bucket

`platform-user-uploads` — user upload bucket where ACL grants write access to all authenticated AWS users and read access to all authenticated AWS users, while the bucket policy appears clean.

## Triggered Controls

| Control | Description |
|---------|-------------|
| `CTL.S3.ACL.WRITE.001` | No Public Write via ACL |
| `CTL.S3.AUTH.READ.001` | No Authenticated-Users Read Access |
| `CTL.S3.CONTROLS.001` | Public Access Block Must Be Enabled |

## Expected Findings

3 violations on 1 resource.

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

Migrated from `docs-content/demo/scenarios/acl-write/`. The original
Docker entrypoint surface is deprecated — every scenario it
exposed is now a directory under `examples/demo-s3-*/` with a
runner that works in the unified Codespaces devcontainer.
