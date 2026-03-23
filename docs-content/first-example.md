# First Example: Detecting a Publicly Readable S3 Bucket

This walkthrough shows how to take real AWS CLI output, transform it into a
Stave observation with `jq`, and run `stave apply` to detect the
misconfiguration.

## The Scenario

A company stores customer documents in an S3 bucket called `company-docs`.
Someone accidentally set the bucket policy to allow public read access.
Anyone on the internet can now download `customers.csv` without logging in.

The problem is not theft by hacking. The problem is **accidental exposure
through configuration**.

## What AWS Says

AWS describes this exact failure mode in its own documentation:

> A misconfiguration that shares an Amazon S3 bucket publicly could cause
> an unintended information exposure.
> --- [AWS: What is a Vulnerability Assessment?](https://aws.amazon.com/what-is/vulnerability-assessment/)

AWS recommends enabling **Block Public Access** (all four settings) on every
bucket and account. When Block Public Access is off and a bucket policy grants
`Principal: "*"`, the bucket is publicly readable.

References:
- [Amazon S3 Block Public Access](https://aws.amazon.com/blogs/aws/amazon-s3-block-public-access-another-layer-of-protection-for-your-accounts-and-buckets/)
- [Blocking public access to your Amazon S3 storage](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html)
- [IAM Access Analyzer for S3](https://aws.amazon.com/blogs/storage/evaluating-public-and-cross-account-access-at-scale-with-iam-access-analyzer-for-amazon-s3/)
- [S3 compliance using AWS Config Auto Remediation](https://aws.amazon.com/blogs/mt/aws-config-auto-remediation-s3-compliance/)

## Before and After

| State  | Bucket Policy | Block Public Access | Result |
|--------|--------------|---------------------|--------|
| Before | `Principal: "*"` allows `s3:GetObject` | All four settings **off** | Anyone can read objects |
| After  | Principal restricted to a named IAM role | All four settings **on** | Public access blocked |

## Step 1: Simulate the AWS API Responses

In production, an extractor calls `aws s3api get-bucket-policy` to
retrieve the bucket policy. For this walkthrough we use `cat` so you
can run every step without AWS credentials.

The bucket policy grants `s3:GetObject` to `Principal: "*"` — anyone
on the internet can read objects:

```bash
cat > policy.json <<'EOF'
{
  "Policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"s3:GetObject\",\"Resource\":\"arn:aws:s3:::company-docs/*\"}]}"
}
EOF
```

## Step 2: Extract into a Stave Observation with jq

Stave evaluates **observations** — JSON snapshots of cloud resource state that
conform to the `obs.v0.1` schema. Each observation file captures the state at
one point in time.

The `jq` command below transforms the simulated API output into a valid Stave
observation. It extracts the policy document and derives whether the bucket
allows public read access.

```bash
jq -n \
  --argjson policy "$(cat policy.json)" \
'{
  schema_version: "obs.v0.1",
  generated_by: {
    source_type: "aws-s3-snapshot",
    tool: "aws-cli",
    tool_version: "2.x"
  },
  captured_at: "2026-03-20T00:00:00Z",
  assets: [
    {
      id: "company-docs",
      type: "aws_s3_bucket",
      vendor: "aws",
      properties: {
        storage: {
          kind: "bucket",
          name: "company-docs",
          access: {
            public_read: (
              ($policy.Policy | fromjson).Statement
              | any(.Principal == "*" and (.Action == "s3:GetObject" or .Action == "s3:*"))
            )
          }
        }
      }
    }
  ]
}'
```

In production you would replace `cat policy.json` with a real AWS CLI call:

```bash
POLICY=$(aws s3api get-bucket-policy --bucket company-docs 2>/dev/null \
  || echo '{"Policy":"{}"}')
```

The observation only includes the field that `CTL.S3.PUBLIC.001` checks:
`properties.storage.access.public_read`.

You do not need to populate fields that no control in your evaluation uses.

## Step 3: Initialize the Project

Before running evaluations, initialize a Stave project. This creates the
`controls/s3/` directory with the built-in S3 control definitions:

```bash
stave init --profile aws-s3
```

## Step 4: Create the Observation Files

For a complete evaluation, Stave needs at least two snapshots (two points in
time) to calculate how long a bucket has been in an unsafe state.

Save the **bad** snapshot as `observations/2026-03-20T000000Z.json`:

```json
{
  "schema_version": "obs.v0.1",
  "generated_by": {
    "source_type": "aws-s3-snapshot",
    "tool": "aws-cli",
    "tool_version": "2.x"
  },
  "captured_at": "2026-03-20T00:00:00Z",
  "assets": [
    {
      "id": "company-docs",
      "type": "aws_s3_bucket",
      "vendor": "aws",
      "properties": {
        "storage": {
          "kind": "bucket",
          "name": "company-docs",
          "access": {
            "public_read": true
          }
        }
      }
    }
  ]
}
```

Save a second snapshot one day later as `observations/2026-03-21T000000Z.json`
with the same content (the bucket is still public).

## Step 5: Run Stave

```bash
stave apply \
  --observations observations \
  --max-unsafe 12h \
  --now 2026-03-21T12:00:00Z
```

Stave evaluates the built-in S3 controls against both snapshots. Because the
bucket has been publicly readable for over 12 hours (the `--max-unsafe`
threshold), Stave reports a violation:

- **CTL.S3.PUBLIC.001** (critical): S3 bucket allows public read access

The exit code is **3** (violations found).

## Step 6: Fix and Verify Remediation

After fixing the bucket (enabling Block Public Access and removing the
`Principal: "*"` policy), capture a new snapshot.

Save the **good** snapshot in a separate directory, `observations-after/2026-03-22T000000Z.json`:

```json
{
  "schema_version": "obs.v0.1",
  "generated_by": {
    "source_type": "aws-s3-snapshot",
    "tool": "aws-cli",
    "tool_version": "2.x"
  },
  "captured_at": "2026-03-22T00:00:00Z",
  "assets": [
    {
      "id": "company-docs",
      "type": "aws_s3_bucket",
      "vendor": "aws",
      "properties": {
        "storage": {
          "kind": "bucket",
          "name": "company-docs",
          "access": {
            "public_read": false
          }
        }
      }
    }
  ]
}
```

Re-run `stave apply` against the fixed observations to confirm the violation
is resolved:

```bash
stave apply \
  --observations observations-after \
  --max-unsafe 12h \
  --now 2026-03-22T12:00:00Z
```

Exit code is **0** (no violations).

For a before/after comparison, `stave verify` can show which findings were
resolved, which remain, and which are new. It requires control definitions
on disk (not just the built-in pack), so it is covered separately in the
[verify guide](verify-guide.md).

## apply vs verify

`stave apply` and `stave verify` answer different questions.

**`stave apply`** answers: *"Is my infrastructure safe right now?"*
It takes one set of observations, evaluates every control, and reports all
current violations. Use it for ongoing monitoring, CI gates, and initial
detection.

**`stave verify`** answers: *"Did my fix actually work?"*
It takes two sets of observations (before and after a change), evaluates the
same controls against both, and reports a three-way diff:
- **Resolved** — findings that existed before but are gone after the fix.
- **Remaining** — findings that still exist in both.
- **New** — findings that did not exist before but appeared after the change.

The distinction matters because a fix can resolve one problem while
accidentally introducing another. `stave apply` on the after observations
alone would show the new problem but would not tell you it was caused by
the change. `stave verify` makes that relationship explicit.

| | `stave apply` | `stave verify` |
|-|--------------|---------------|
| Input | One observation set | Two observation sets (before + after) |
| Output | All current violations | Resolved, remaining, and new findings |
| Use case | Detection, CI gates | Remediation confirmation |
| Typical workflow | Run regularly | Run once after a fix |

## What the Control Checks

| Control | Severity | What It Checks | Field |
|---------|----------|---------------|-------|
| CTL.S3.PUBLIC.001 | Critical | Bucket allows anonymous read | `properties.storage.access.public_read` |

## What Changed Between Before and After

| Field | Before (bad) | After (good) |
|-------|-------------|-------------|
| `storage.access.public_read` | `true` | `false` |

## Summary

1. **Simulate** the AWS API responses (or call the real AWS CLI)
2. **Extract** into `obs.v0.1` format with `jq`
3. **Initialize** the project with `stave init --profile aws-s3`
4. **Save** at least two snapshots (two points in time)
5. **Run** `stave apply` to detect violations
6. **Fix** the bucket, capture a new snapshot, and re-run `stave apply` to confirm remediation
