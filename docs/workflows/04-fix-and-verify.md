# Fix a Finding, Verify the Fix

The remediation loop: **explain → fix → re-snapshot → verify**. Each
step is deterministic, so "fixed" is a fact you can prove, not a claim.

## Step 1: Understand what to change

```bash
stave explain CTL.S3.PUBLIC.001
```

`explain` prints the exact fields the control reads, the operator/value
it expects, and a minimal `obs.v0.1` snippet — so you know precisely
which property must change and to what value:

```
Control: CTL.S3.PUBLIC.001
Name: No Public S3 Bucket Read
Matched fields:
  - properties.storage.access.public_read
```

(`stave explain <control-id>` is catalog-only — no observations or
credentials needed.)

## Step 2: Apply the fix in your infrastructure

Change the real resource. For the public-read example:

```hcl
# Terraform
resource "aws_s3_bucket_public_access_block" "this" {
  bucket                  = aws_s3_bucket.this.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
```

```bash
# Or directly
aws s3api put-public-access-block --bucket my-bucket \
  --public-access-block-configuration \
  BlockPublicAcls=true,BlockPublicPolicy=true,IgnorePublicAcls=true,RestrictPublicBuckets=true
```

## Step 3: Take a new snapshot

Re-collect the same way you collected the first one (keep the *before*
snapshot — you'll compare against it):

```bash
# however you produce obs.v0.1 — e.g. the Steampipe mapping in guide 01
#   obs-before/  ← the snapshot that fired the finding
#   obs-after/   ← the snapshot after your fix
```

## Step 4: Verify the remediation

`stave check` runs the controls against both snapshots and reports what
changed — **resolved**, still **remaining**, and any **newly
introduced** findings:

```bash
stave check --before ./obs-before --after ./obs-after
```

Exit `0` = everything resolved, nothing regressed; exit `3` = something
still failing or newly introduced. The fixed finding should appear as
*resolved*. `check` operates on observation directories and compares
*verdicts* — the right tool for confirming a remediation.

> One command for the whole loop: `stave ci fix-loop` runs
> apply-before / apply-after / verify together.

## Step 5: Keep the evidence

The before/after evaluation outputs **are** your remediation evidence —
deterministic and reproducible:

```bash
stave apply --observations ./obs-before --format json --now 2026-01-15T00:00:00Z > evidence/before.json
stave apply --observations ./obs-after  --format json --now 2026-01-20T00:00:00Z > evidence/after.json
```

Same inputs always produce the same output, so these files are a
verifiable record of the fix — not a screenshot someone has to trust.

---

**Next:**
- Turn this into auditor evidence → [05-compliance-evidence.md](./05-compliance-evidence.md)
- Make sure it never comes back → [06-ci-pipeline-gate.md](./06-ci-pipeline-gate.md)
