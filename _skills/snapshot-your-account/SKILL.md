---
name: stave-snapshot-your-account
description: Capture a read-only configuration snapshot of your real AWS account and evaluate it with Stave on a local, deterministic snapshot
triggers:
  - evaluate my account
  - scan my AWS
  - snapshot my environment
  - real environment findings
  - run Stave for real
requires:
  - a built stave binary (run stave-setup first)
  - AWS CLI with a READ-ONLY profile (SecurityAudit / ReadOnlyAccess)
---

# stave-snapshot-your-account

## What this skill does
Captures a point-in-time config snapshot of your AWS account and evaluates it.
This is the real thing — but Stave only ever reads a LOCAL snapshot; it never
connects to or writes to AWS.

**Time:** ~30 minutes. **Real AWS, read-only.**

## Prerequisites — read-only only
```
aws sts get-caller-identity --profile <your-readonly-profile>
```
The profile MUST be read-only (e.g. the AWS-managed `SecurityAudit` or
`ReadOnlyAccess` policy). Do NOT use admin/write credentials — capture needs
only reads.

## Steps

### 1. Confirm read-only access
Verify the caller's attached policies are read/audit only before proceeding.

### 2. Capture a snapshot
Pull the configuration you want to evaluate with read-only AWS CLI calls (e.g.
`aws iam list-users`, `list-attached-user-policies`, `get-policy-version`,
`aws s3api get-bucket-policy`, …) and save the raw JSON. This is the same
capture pattern used in the `lab-validation` skill — adapt the resource list and
naming to your account.

### 3. Build observations
Transform the captured config into `obs.v0.1` observation files:
- one or more snapshot files (≥ 2 timestamps if you want duration-based controls
  to evaluate dwell time),
- `schema_version: obs.v0.1`, `source: deployed`,
- per-asset `properties` populated with the exact fields the relevant controls
  read (find them with `./stave search` + the control's `observation_fields`,
  same as `lab-validation` step 4).
```
jq . <your-obs-dir>/*.json > /dev/null && echo "valid JSON"
```

### 4. Evaluate
```
./stave apply --observations <your-obs-dir>/ --now <RFC3339-now>
```

### 5. Review findings
Each finding is a property of YOUR environment, with evidence and remediation.
Triage by severity; the remediation field says what to change.

## Important
- Stave evaluates a LOCAL snapshot — it never calls AWS. Capture is the only AWS step, and it's read-only.
- A snapshot is point-in-time: findings reflect the captured moment, not live state.
- Deterministic: same snapshot + same `--now` → identical findings, always.

## Success
You've evaluated your real environment. Findings are specific to your
infrastructure, each with evidence and remediation guidance.
