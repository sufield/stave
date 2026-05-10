# S3 Demo: Upload Policy Hardening


Signed upload policies that allow prefix-scoped keys or unrestricted content types, enabling object overwrite and stored XSS attacks.

## Background

Direct client-to-S3 uploads via presigned URLs are common for user-facing features like avatar uploads and document inboxes. Two common misconfigurations create exploitable gaps:

1. **Prefix-scoped keys:** A `starts-with` condition on the object key lets attackers write to any path under the prefix, enabling cross-tenant overwrites on shared buckets.
2. **Unrestricted content types:** Without a content-type condition, attackers can upload SVGs with embedded JavaScript or HTML files, causing stored XSS when served from the bucket's domain.

**Based on:** HackerOne presigned upload patterns documented in Intigriti S3 guide

## Resources

**`upload-api-user-avatars`** (s3_upload_policy) -- prefix-scoped key mode AND no content-type restriction. Both upload hardening controls fire.

**`upload-api-document-inbox`** (s3_upload_policy) -- exact key mode but no content-type restriction. Only the content-type control fires.

**`upload-api-profile-photos`** (s3_upload_policy) -- exact key mode with content-type restriction. Safe -- no controls fire.

## Triggered Controls

| Control | Resource | Description |
|---------|----------|-------------|
| `CTL.S3.WRITE.SCOPE.001` | upload-api-user-avatars | Signed Upload Must Bind To Exact Object Key |
| `CTL.S3.WRITE.CONTENT.001` | upload-api-user-avatars | Signed Upload Must Restrict Content Types |
| `CTL.S3.WRITE.CONTENT.001` | upload-api-document-inbox | Signed Upload Must Restrict Content Types |

## Expected Findings

3 violations across 2 resources.

---

## Run

```bash
bash run.sh
```

Expected: 6 findings on this fixture.

The runner uses the standard `stave apply` + encoding verification
pipeline. No Docker required — works in the Codespaces devcontainer
or any local checkout with stave built (`make build` in stave/).

## Try it yourself

Replace the JSON files in `fixtures/observations/` with your own
S3 observations and re-run. The bucket-name + property values
update; the schema and the controls do not.

## Provenance

Migrated from `docs-content/demo/scenarios/upload-hardening/`. The original
Docker entrypoint surface is deprecated — every scenario it
exposed is now a directory under `examples/demo-s3-*/` with a
runner that works in the unified Codespaces devcontainer.
