---
title: "Run on Your Own AWS Account"
sidebar_label: "Quickstart — your own AWS account"
description: "Generate an obs.v0.1 snapshot from your AWS account using the bundled minimal collector, then evaluate it with stave."
---

# Run on Your Own AWS Account

The demo scripts under `examples/` work against bundled fixtures with
zero credentials. Once those convince you the engine works, this is the
fastest path from those demos to a finding on your own infrastructure.

## Prerequisites

- AWS CLI v2 configured with read-only credentials. The
  [`SecurityAudit`](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/SecurityAudit.html)
  AWS-managed policy is sufficient. No write permissions are required.
- `jq` on PATH.
- A built `stave` binary (`make build` in the repo root, or
  `go install github.com/sufield/stave@latest`).

## Collect a snapshot

```bash
bash scripts/aws-snapshot.sh ./my-snapshot
```

The script writes a single `snapshot-<timestamp>.json` file under
`./my-snapshot/`. It performs read-only AWS CLI calls only and never
sends data outside the local filesystem.

What gets collected:

| Service | Properties |
|---|---|
| S3 buckets | public-access-block settings, encryption-at-rest algorithm + KMS key, tags |
| IAM roles  | trust policy's trusted services, attached managed-policy ARNs, admin-equivalent heuristic, tags |

AWS service-linked roles (`AWSServiceRole*`) are skipped — their trust
policies are AWS-managed and don't produce actionable findings.

## Evaluate

```bash
stave apply --observations ./my-snapshot --allow-unknown-input
```

`--allow-unknown-input` is required because the snapshot's
`source_type` is `aws.cli` — descriptive but not in stave's built-in
connector manifest. The flag tells stave to evaluate the snapshot
anyway. You'll see the same warning that fires for any third-party
collector; it's not a sign of a problem.

For machine-readable output:

```bash
stave apply --observations ./my-snapshot --allow-unknown-input --format json \
    | jq '{summary, findings_count: (.findings | length), chains: .chains}'
```

## What kinds of findings to expect

With S3 + IAM only, the controls that fire most readily are:

- **`CTL.S3.PAB.*`** — seven controls that read
  `properties.storage.controls.public_access_block.*`. Any bucket
  missing one of the four block-flags produces a finding.
- **`CTL.S3.ENCRYPTION.*`** — controls that compare
  `properties.storage.encryption.algorithm` against the required
  algorithm. Buckets with `SSE-S3` (AES256) instead of `SSE-KMS`
  produce findings.
- **`CTL.IAM.ROLE.*`** — controls that read
  `properties.identity.is_admin_equivalent`,
  `properties.identity.attached_policy_arns`,
  `properties.identity.trusted_services`.

You will NOT see findings that require:

- Bucket-policy parsing (no public-read detection from policy text)
- Cross-account trust derivation (would require statement-level
  analysis of AssumeRolePolicyDocument)
- Ghost-reference detection (would require correlating IAM policies
  against the full asset inventory)

The minimal collector deliberately produces a partial snapshot. Once
the partial snapshot has shown you the kinds of findings stave
produces, the next step is the full extractor described in
[`docs/extractor-prompt.md`](extractor-prompt.md) — an LLM meta-prompt
that generates a complete extractor for the obs.v0.1 schema.

## Time budget

- Collect snapshot: **30 seconds** for an account with ~50 buckets and
  ~50 roles. Scales linearly with asset count.
- First evaluation: **5 seconds** for the assets above.

If either step takes substantially longer, suspect API rate limiting on
your AWS account (the collector does not parallelize) or that your
account has thousands of IAM roles.

## Trust posture

The collector script is auditable POSIX bash. It performs only the AWS
CLI calls enumerated above; no network calls outside `aws` invocations.
The resulting snapshot is local to your filesystem. Stave itself makes
no network calls.

`scripts/aws-snapshot.sh` is a convenience wrapper around AWS CLI — it
is not bundled into the `stave` binary. The binary stays air-gapped.

## Limitations

- The S3 collector calls `aws s3api list-buckets` which returns all
  buckets across all regions. The collector does not call
  `get-bucket-location` and does not filter by region.
- The IAM collector does not enumerate inline role policies or
  policy-statement-level analysis. Attached managed-policy ARNs only.
- The collector does not collect Cognito, Lambda, VPC, EC2, RDS, or
  any other AWS service. S3 + IAM is the minimum for an evaluation
  that produces meaningful findings; broader coverage is a follow-up.

## Going further

See [`docs/extractor-prompt.md`](extractor-prompt.md) for the
LLM-driven template that generates a complete extractor across all 74
service domains stave's catalog covers.
