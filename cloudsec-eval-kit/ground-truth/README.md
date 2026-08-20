# Ground Truth

This directory contains the authoritative list of misconfigurations
deployed in the SadCloud environment.

## Contents

- **atomic.yaml** — 30 individual misconfigurations across 8 AWS services
- **compound.yaml** — 5 multi-resource attack paths

## Selection Criteria

Every entry satisfies all four:

1. **Objectively wrong.** No threshold judgment. A security group open
   to 0.0.0.0/0 is wrong. A password policy with minimum length 6 is wrong.

2. **Any competent tool should find it.** Detectable from standard AWS
   API output (DescribeInstances, GetBucketAcl, GetPasswordPolicy, etc.).

3. **Fix is unambiguous.** One API call or Terraform change remediates it.

4. **Console-verifiable.** Each entry includes a verification path —
   click through the AWS console and see the problem.

## How to Read the YAML

Each atomic entry:

```yaml
- id: GT-S3-001              # Unique identifier for the scorecard
  service: S3                 # AWS service
  resource: sadcloud-bucket   # Resource name in the SadCloud deployment
  finding: Bucket versioning  # What's wrong (plain English)
  severity: MEDIUM            # CRITICAL / HIGH / MEDIUM
  stave_control: CTL.S3...    # Stave control ID (for reference only)
  verification: "Console →"  # How to verify manually
  sadcloud_module: s3         # Which Terraform module deploys this
```

Each compound entry:

```yaml
- id: CP-001
  name: Detection blindness
  path:                       # Ordered steps in the attack chain
    - step: entry             # Where the attacker enters
      gt_ref: GT-CT-003       # Links to atomic finding
    - step: amplifier         # What makes it worse
  impact: "..."               # What an attacker achieves
  compound_severity: CRITICAL
```

## Manual Verification

Every atomic entry includes a `verification` field with the console
path. To verify any entry:

1. Log into the AWS account where SadCloud is deployed
2. Follow the console path (e.g., "Console → S3 → bucket → Properties")
3. Confirm the misconfiguration exists as described

This is how you validate the ground truth independently, without
trusting any tool.

## Compound Paths

Compound paths require connecting findings across services. A tool
that finds the individual misconfigurations gets partial credit for
the atomic entries. A tool that identifies the connected path — "this
security group exposure PLUS this admin role EQUALS internet-to-admin
access" — gets full credit for the compound entry.

Most tools find individual findings. Few connect them into attack paths.
The compound section measures that gap.
