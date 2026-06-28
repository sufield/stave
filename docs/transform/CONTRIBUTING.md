# Adding a Transform Filter

A transform filter is a single `.jq` file that converts raw AWS CLI JSON into
Stave's `obs.v0.1` observation format. **You write jq, not Go.** The Go scrubber
and the obs.v0.1 envelope are handled for you.

Filters live in `internal/adapters/aws/transform/filters/` and are embedded into
the binary at build time. The core is never touched — this is all adapter code.

## The output shape

Each filter emits **one object per resource** with the obs.v0.1 asset shape:

```jq
{ id, type, vendor, properties }
```

- `id` — the resource ARN (the obs.v0.1 id convention).
- `type` — e.g. `aws_kms_key`.
- `vendor` — `aws`.
- `properties` — a namespaced object holding the fields controls read.

(Note: this is the real obs.v0.1 asset shape — not `resource_type` / `resource_id`.)

## Steps

1. **Scaffold the filter:**

   ```bash
   stave transform --scaffold kms-keys
   # → internal/adapters/aws/transform/filters/kms-keys.jq
   ```

2. **Get a sample input** (the raw AWS CLI output your filter consumes):

   ```bash
   aws kms list-keys --output json > sample.json
   ```

3. **Write the mapping** in the scaffolded `.jq`. Emit one asset per resource:

   ```jq
   .Keys[] | {
     id: .KeyArn,
     type: "aws_kms_key",
     vendor: "aws",
     properties: { encryption: {
       kind: "kms_key",
       key_id: .KeyId
       # map the raw fields controls read here
     } }
   }
   ```

4. **Register the top-level key** so auto-detection finds the filter. In
   `internal/adapters/aws/transform/detect.go`, add to `topLevelKeyToFilter`:

   ```go
   "Keys": "kms-keys",
   ```

5. **Add a parity test against committed lab data.** Copy a real snapshot↔obs
   pair into `internal/adapters/aws/transform/testdata/` (the stave module syncs
   to the public repo without the repo-root `ctf/` tree, so tests use copies),
   then assert the filter output equals the committed observation asset. See
   `TestTransformFiles_NccgroupPasswordPolicy` for the pattern.

6. **Verify:**

   ```bash
   go test ./internal/adapters/aws/transform/   # parity + filter lint
   stave transform --lint                        # all filters compile + correct shape
   ```

   The end-to-end check is stronger than byte-equality: transform a lab's
   snapshots and confirm `stave apply` produces the **same findings** as
   evaluating the committed observations.

7. **Submit a PR** with the `.jq` file, the detection entry, and the test.

## Cross-call enrichment (data spread across API calls)

One AWS resource is often spread across several API calls (a bucket's
`list-buckets` entry + its `get-public-access-block`). Each filter emits an
object carrying the resource `id`; objects sharing an id are **deep-merged** into
one asset. A per-call enrichment input carries no resource name, so the join key
is supplied one of two ways:

- **Filename-derived key** (preferred for raw files) — name the file with the
  resource, e.g. `s3-pab-<bucket>.json`. The runner extracts the key and injects
  it, so the raw `get-public-access-block` output works unchanged. Add a pattern
  in `filenamekey.go`. Only valid when the captured key fully determines the
  asset id (S3 bucket name → ARN). IAM roles are not eligible — the id is the
  full role ARN, which a role name can't reconstruct — so role enrichment needs
  an explicit `RoleArn` annotation.
- **Content annotation** — `{"Bucket":"<name>", "PublicAccessBlockConfiguration":{...}}`.
  Content always wins over the filename.

See `s3-public-access-block.jq` and `filenamekey.go`.

## Rules

- **Never scrub in jq.** The Go scrubber hashes UserData, env values, and
  secret-keyed tags. Your filter just maps fields; emit policy documents,
  security-group rules, ARNs, names, and actions **unchanged** — controls read them.
- **No new dependency, no Go.** A filter is jq only.
- **Test against real lab data**, never synthetic fixtures, where a committed
  snapshot↔observation pair exists.

The contributor bar: know jq → write one `.jq` → test against lab data → PR.
