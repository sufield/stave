# S3 Demo: Public Read via Bucket Policy


Internal analytics data exposed to the internet via `Principal: "*"` bucket policy with Public Access Block disabled.

## Background

This is the most commonly reported S3 vulnerability class — 7 of 25 HackerOne reports in the Stave test suite involve public read access. Companies as large as Shopify, Uber, and Mapbox have had this exact issue disclosed through bug bounty programs.

**Based on:** HackerOne reports #94502 (Shopify), #361438 (Uber), #202725 (Mapbox), #819278 (Greenhouse), #1474017 (Omise)

## Bucket

`corp-analytics-exports` — internal analytics data exposed via bucket policy granting `Principal: "*"` read access, with ACL also granting public read.

## Triggered Controls

| Control | Description |
|---------|-------------|
| `CTL.S3.PUBLIC.001` | No Public S3 Buckets — public_read is true |
| `CTL.S3.PUBLIC.004` | No Public Read via ACL — zero-tolerance duration |
| `CTL.S3.CONTROLS.001` | Public Access Block Must Be Enabled |

## Expected Findings

3 violations on 1 resource.

---

## Run

```bash
bash run.sh
```

Expected: 9 findings on this fixture.

The runner uses the standard `stave apply` + encoding verification
pipeline. No Docker required — works in the Codespaces devcontainer
or any local checkout with stave built (`make build` in stave/).

## Try it yourself

Replace the JSON files in `fixtures/observations/` with your own
S3 observations and re-run. The bucket-name + property values
update; the schema and the controls do not.

## Provenance

Migrated from `docs-content/demo/scenarios/public-read/`. The original
Docker entrypoint surface is deprecated — every scenario it
exposed is now a directory under `examples/demo-s3-*/` with a
runner that works in the unified Codespaces devcontainer.
