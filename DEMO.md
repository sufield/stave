# Stave Tutorial Demo

44 interactive S3 security scenarios running in Docker. No AWS credentials required.

## What you will learn

Each scenario walks you through the complete Stave workflow for one real S3 misconfiguration:

- **The observation** — what the misconfigured bucket state looks like as JSON
- **The detection** — how `stave apply` evaluates the observation and reports the violation
- **The remediation** — what the fixed state looks like and how Stave confirms it

By the end of all 44 scenarios you will know how to:

- Structure observation JSON files in the `obs.v0.1` schema
- Map AWS S3 configuration to the fields each control checks
- Run `stave apply` to detect violations and verify fixes
- Read Stave output: findings, severity, evidence, remediation guidance
- Use `exclude_controls` to focus evaluation on specific controls

The scenarios are organized in three levels:

- **Beginner (1-8)** — One AWS CLI command, one observation field. Public access, encryption, logging, versioning, tagging.
- **Intermediate (9-29)** — Policy and ACL parsing. Multiple fields, cross-field conditions, latent exposure, cross-account access.
- **Advanced (30-43)** — Tag-conditional compliance, lifecycle retention, Object Lock modes, website hosting, VCS artifact exposure, signed upload restrictions, tenant isolation, bucket takeover, CDN origin hijacking.
- **Capstone (44)** — Full hardening audit of one bucket against all 43 controls in a single observation.

## Prerequisites

- Docker 20.10+

## Install

```bash
git clone https://github.com/sufield/stave.git
cd stave
docker build -f build/docker/demo/Dockerfile -t stave-tutorials ..
```

Or from the repository root:

```bash
docker build -f stave/build/docker/demo/Dockerfile -t stave-tutorials .
```

## Usage

### List all scenarios

```bash
docker run --rm stave-tutorials --list
```

### Run a scenario (bad configuration)

```bash
docker run --rm stave-tutorials --scenario 10
```

This shows:
1. The observation JSON (the misconfigured state)
2. The `stave apply` command
3. The evaluation output with the violation

Exit code 3 (violations found).

### Run the same scenario (fixed configuration)

```bash
docker run --rm stave-tutorials --scenario 10 --fixed
```

This shows:
1. The fixed observation JSON (the remediated state)
2. The same `stave apply` command
3. The evaluation output confirming zero violations

Exit code 0 (no violations).

### AWS Trusted Advisor blind spots

Three scenarios that demonstrate S3 risks Trusted Advisor cannot detect:

```bash
docker run --rm stave-tutorials --blind-spots
docker run --rm stave-tutorials --blind-spots --fixed
```

| # | Blind Spot | Control | What Trusted Advisor Does | What Stave Does |
|---|-----------|---------|--------------------------|-----------------|
| 8 | Policy-denied scanning | CTL.S3.INCOMPLETE.001 | Reports green — scanning role was denied access to bucket policy, ACL, and Public Access Block APIs. The bucket is fully public but the scanner cannot see it. | Flags missing data as unsafe. If required fields are absent from the observation, the bucket cannot be proven safe. |
| 23 | Latent exposure behind PAB | CTL.S3.PUBLIC.005 | Reports safe — Public Access Block is on. But the underlying policy grants `Principal: "*"`. Removing PAB (one toggle) makes the bucket instantly public. | Flags the underlying public policy as latent exposure even when PAB masks it. |
| 18 | ACL escalation (WRITE_ACP) | CTL.S3.ACL.ESCALATION.001 | Not checked. Trusted Advisor checks public read access but not whether the public can modify the ACL itself. | Flags WRITE_ACP grants to AllUsers. Anyone can call PutBucketAcl, grant themselves FULL_CONTROL, then read every object. |

References:
- [Fog Security: Mistrusted Advisor (Aug 2025)](https://www.fogsecurity.io/blog/mistrusted-advisor-public-s3-buckets)
- [SecurityWeek: AWS Trusted Advisor Tricked](https://www.securityweek.com/aws-trusted-advisor-tricked-into-showing-unprotected-s3-buckets-as-secure/)

### Pass-through to stave

```bash
docker run --rm stave-tutorials -- stave --version
docker run --rm stave-tutorials -- stave controls list --format json
```

## Scenarios

### Beginner (1-8)

One AWS CLI command per scenario. Direct field mapping.

| # | Control | Severity | Name |
|---|---------|----------|------|
| 1 | CTL.S3.PUBLIC.001 | critical | No Public S3 Bucket Read |
| 2 | CTL.S3.CONTROLS.001 | high | Public Access Block Must Be Enabled |
| 3 | CTL.S3.ENCRYPT.001 | high | Encryption at Rest Required |
| 4 | CTL.S3.LOG.001 | medium | Access Logging Required |
| 5 | CTL.S3.VERSION.001 | medium | Versioning Required |
| 6 | CTL.S3.VERSION.002 | medium | Backup Buckets Must Have MFA Delete Enabled |
| 7 | CTL.S3.GOVERNANCE.001 | low | Data Classification Tag Required |
| 8 | CTL.S3.INCOMPLETE.001 | low | Complete Data Required for Safety Assessment |

### Intermediate (9-29)

Policy and ACL parsing with conditional logic. Some scenarios combine two CLI outputs.

| # | Control | Severity | Name |
|---|---------|----------|------|
| 9 | CTL.S3.ENCRYPT.002 | high | Transport Encryption Required |
| 10 | CTL.S3.PUBLIC.007 | critical | No Public Read via Policy |
| 11 | CTL.S3.PUBLIC.003 | critical | No Public Write Access |
| 12 | CTL.S3.ACCESS.002 | high | No Wildcard Action Policies |
| 13 | CTL.S3.ACCESS.003 | high | No External Write Access |
| 14 | CTL.S3.NETWORK.001 | high | Public-Principal Policies Must Have Network Conditions |
| 15 | CTL.S3.PUBLIC.004 | medium | No Public Read via ACL |
| 16 | CTL.S3.ACL.FULLCONTROL.001 | critical | No FULL_CONTROL ACL Grants to Public |
| 17 | CTL.S3.ACL.RECON.001 | high | No Public ACL Readability |
| 18 | CTL.S3.ACL.ESCALATION.001 | high | No Public ACL Modification |
| 19 | CTL.S3.AUTH.READ.001 | high | No Authenticated-Users Read Access |
| 20 | CTL.S3.AUTH.WRITE.001 | high | No Authenticated-Users Write Access |
| 21 | CTL.S3.PUBLIC.LIST.001 | high | No Public S3 Bucket Listing |
| 22 | CTL.S3.PUBLIC.LIST.002 | high | Anonymous S3 Listing Must Be Explicitly Intended |
| 23 | CTL.S3.PUBLIC.005 | medium | No Latent Public Read Exposure |
| 24 | CTL.S3.PUBLIC.006 | critical | No Latent Public Bucket Listing |
| 25 | CTL.S3.ACCESS.001 | high | No Unauthorized Cross-Account Access |
| 26 | CTL.S3.PUBLIC.002 | critical | No Public S3 Buckets With Sensitive Data |
| 27 | CTL.S3.PUBLIC.PREFIX.001 | high | Protected Prefixes Must Not Be Publicly Readable |

### Advanced (30-43)

Tag-conditional evaluation, compliance controls, cross-service analysis.

| # | Control | Severity | Name |
|---|---------|----------|------|
| 28 | CTL.S3.ENCRYPT.003 | high | PHI Buckets Must Use SSE-KMS with Customer-Managed Key |
| 29 | CTL.S3.ENCRYPT.004 | high | Sensitive Data Requires KMS Encryption |
| 30 | CTL.S3.LIFECYCLE.001 | medium | Retention-Tagged Buckets Must Have Lifecycle Rules |
| 31 | CTL.S3.LIFECYCLE.002 | medium | PHI Buckets Must Not Expire Data Before Minimum Retention |
| 32 | CTL.S3.LOCK.001 | medium | Compliance-Tagged Buckets Must Have Object Lock Enabled |
| 33 | CTL.S3.LOCK.003 | medium | PHI Object Lock Retention Must Meet Minimum Period |
| 34 | CTL.S3.LOCK.002 | medium | PHI Buckets Must Use COMPLIANCE Mode Object Lock |
| 35 | CTL.S3.PUBLIC.008 | critical | No Public List via Policy |
| 36 | CTL.S3.WEBSITE.PUBLIC.001 | critical | No Public Website Hosting with Public Read |
| 37 | CTL.S3.REPO.ARTIFACT.001 | medium | Public Buckets Must Not Expose VCS Artifacts |
| 38 | CTL.S3.WRITE.SCOPE.001 | high | S3 Signed Upload Must Bind To Exact Object Key |
| 39 | CTL.S3.WRITE.CONTENT.001 | high | S3 Signed Upload Must Restrict Content Types |
| 40 | CTL.S3.TENANT.ISOLATION.001 | high | Shared-Bucket Tenant Isolation Must Enforce Prefix |
| 41 | CTL.S3.BUCKET.TAKEOVER.001 | critical | Referenced S3 Buckets Must Exist And Be Owned |
| 42 | CTL.S3.DANGLING.ORIGIN.001 | high | CDN S3 Origins Must Not Be Dangling |
| 43 | CTL.S3.ACL.WRITE.001 | critical | No Public Write via ACL |

### Capstone (44)

| # | Control | Severity | Name |
|---|---------|----------|------|
| 44 | All 43 controls | all | Full Hardening Audit |

## How it works

The demo uses one Stave project. Each scenario swaps the observation files in the `observations/` directory and runs `stave apply`. The `exclude_controls` setting in `stave.yaml` ensures only the target control is evaluated, so the output focuses on exactly one misconfiguration.

Each run shows three things:
1. **Observation JSON** — the exact input data Stave evaluates
2. **Command** — the `stave apply` command you would run
3. **Output** — the evaluation result with findings, evidence, and remediation guidance

Scenario 44 (capstone) removes all exclusions and runs every control against a single fully-populated observation.
