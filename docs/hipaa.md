# HIPAA S3 Compliance Evaluation

Stave evaluates S3 bucket configurations against HIPAA Security Rule
requirements using programmatic invariants, compound risk detection,
a compliance profile system, acknowledged exceptions with compensating
controls, and structured reporting with regulatory citations.

## Quick Start

```bash
# Evaluate a snapshot against the HIPAA profile
stave evaluate --snapshot observations/snap.json --profile hipaa

# JSON output for automation
stave evaluate --snapshot snap.json --profile hipaa --format json --output report.json
```

Exit codes:
- `0` — all CRITICAL invariants pass
- `1` — one or more CRITICAL invariants fail
- `2` — input or configuration error

## HIPAA Profile

The built-in HIPAA profile (`internal/profile/hipaa.go`) includes 11
invariants in priority order. Invariants not yet implemented are skipped
without error during evaluation.

### CRITICAL Priority

| ID | HIPAA Citation | Rationale |
|----|----------------|-----------|
| CONTROLS.001.STRICT | §164.312(a)(2)(iv) | CMK required for key revocation during breach response |
| CONTROLS.004 | §164.312(e)(2)(ii) | Encryption in transit — deny non-TLS access |
| AUDIT.001 | §164.312(b) | All PHI access must be logged — logs cannot be obtained retroactively |
| ACCESS.001 | §164.312(a)(1) | Block Public Access prevents public exposure of ePHI |

### HIGH Priority

| ID | HIPAA Citation | Rationale |
|----|----------------|-----------|
| AUDIT.002 | §164.312(b) | Object-level logging for PHI access audit trail |
| ACCESS.002 | §164.312(a)(2)(i) | Least privilege — no wildcard actions |
| GOVERNANCE.001 | §164.312(a)(1) | ACL control — disable legacy ACL grants |
| RETENTION.002 | §164.316(b)(2) | 6-year PHI retention via Object Lock |
| ACCESS.003 | §164.312(e)(1) | Transmission security — VPC endpoint or IP restriction |

### MEDIUM Priority

| ID | HIPAA Citation | Rationale |
|----|----------------|-----------|
| CONTROLS.002 | §164.312(c)(1) | Integrity — versioning protects against accidental deletion |
| ACCESS.009 | §164.312(a)(1) | Presigned URL restriction for PHI buckets |

## Invariant Reference

### ACCESS.001 — Block Public Access

- **Severity**: CRITICAL (downgrades to LOW with account-level BPA)
- **HIPAA**: §164.312(a)(1) — Access Control
- **Pass condition**: All four BPA flags enabled at bucket level
  (BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy,
  RestrictPublicBuckets)
- **Special case**: If account-level BPA is fully enabled and
  bucket-level is not set, severity downgrades to LOW with finding:
  "Account-level BPA active — bucket-level is defense in depth"

### ACCESS.002 — No Wildcard Allow

- **Severity**: HIGH
- **HIPAA**: §164.312(a)(2)(i) — Unique User Identification
- **Pass condition**: No bucket policy statement has `Effect=Allow` with
  `Action` containing `s3:*` or `*`
- **Remediation**: Includes minimum action set for common sync patterns:
  `s3:GetObject`, `s3:PutObject`, `s3:DeleteObject`, `s3:ListBucket`,
  `s3:GetBucketLocation`

### ACCESS.011 — No Public ListBucket

- **Severity**: HIGH
- **HIPAA**: §164.312(a)(1) — Access Control
- **Pass condition**: No bucket policy grants `s3:ListBucket` to
  `Principal *`
- **Finding note**: ListBucket enables full key enumeration defeating
  any object-key obscurity approach

### CONTROLS.001 — SSE Enabled

- **Severity**: HIGH
- **HIPAA**: §164.312(a)(2)(iv) — Encryption and Decryption
- **Pass condition**: `storage.encryption.at_rest_enabled` is true
- **Note**: Any SSE algorithm (AES-256 or aws:kms) satisfies this check

### CONTROLS.001.STRICT — SSE-KMS with CMK

- **Severity**: CRITICAL
- **HIPAA**: §164.312(a)(2)(iv) — Encryption and Decryption
- **Pass condition**: SSE algorithm is `aws:kms` AND `kms_master_key_id`
  is set AND not the AWS-managed key (`alias/aws/s3`)
- **Fails when**:
  - Encryption disabled
  - Algorithm is not `aws:kms` (e.g. AES-256/SSE-S3)
  - No KMS key ID specified (defaults to AWS-managed key)
  - KMS key is `alias/aws/s3`
- **Why CMK matters**: During a breach response, a customer-managed key
  can be immediately disabled or scheduled for deletion, rendering all
  encrypted objects unreadable. AWS-managed keys cannot be revoked by the
  customer, eliminating this containment option.
- **Relationship**: CONTROLS.001.STRICT implies CONTROLS.001. Registered
  separately so profiles can include one without the other.

### CONTROLS.002 — Versioning Enabled

- **Severity**: MEDIUM
- **HIPAA**: §164.312(c)(1) — Integrity
- **Pass condition**: `storage.versioning.enabled` is true
- **Remediation**: For HIPAA workloads, also enable MFA Delete to prevent
  unauthorized permanent deletion of objects

### CONTROLS.004 — Deny Non-TLS

- **Severity**: HIGH
- **HIPAA**: §164.312(e)(2)(ii) — Transmission Security
- **Pass condition**: Bucket policy contains a `Deny` statement with
  `Condition {"Bool": {"aws:SecureTransport": "false"}}`
- **Caveat**: S3 API endpoints enforce TLS 1.2 by default since February
  2024, but HTTP endpoint access via website hosting remains possible.
  The Deny non-TLS policy statement protects against this residual
  attack surface.

### AUDIT.001 — Server Access Logging

- **Severity**: CRITICAL
- **HIPAA**: §164.312(b) — Audit Controls
- **Pass condition**: `storage.logging.target_bucket` is set and
  not empty
- **Finding**: Logs cannot be obtained retroactively from AWS — if a
  security incident occurs without logging enabled, no forensic evidence
  exists

### GOVERNANCE.001 — ACLs Disabled

- **Severity**: HIGH
- **HIPAA**: §164.312(a)(1) — Access Control
- **Pass condition**: `storage.ownership_controls` is
  `BucketOwnerEnforced`
- **Known exception**: AWS Backup restore jobs require ACLs enabled on
  the destination bucket — document as an acknowledged exception if this
  bucket is an AWS Backup restore target

### RETENTION.002 — Object Lock Enabled

- **Severity**: Determined from snapshot (not hardcoded)
- **HIPAA**: §164.316(b)(2) — Retention (minimum 6 years)
- **Severity tiering**:
  - Not enabled → CRITICAL
  - Governance mode → HIGH (privileged override possible)
  - Compliance mode → PASS (strongest protection, no override)
- **Note**: Object Lock can only be enabled at bucket creation time

## Compound Risk Detection

After individual invariant evaluation, the compound risk detector
identifies known dangerous combinations that represent higher risk than
any individual finding alone. Compound findings are prepended to the
report before individual findings.

### COMPOUND.001 — Public Access + Overly Broad Policy

- **Triggers**: ACCESS.001 FAIL and ACCESS.002 FAIL simultaneously
- **Severity**: CRITICAL
- **Message**: Public access with overly broad IAM permissions — the
  S3 + IAM lateral movement pattern present in the majority of
  documented AWS breaches. Remediate both before addressing
  lower-severity findings.

### COMPOUND.002 — Encryption Pass but Access Fail

- **Triggers**: ACCESS.001 FAIL and CONTROLS.001 PASS simultaneously
- **Severity**: HIGH
- **Message**: Encryption at rest is configured but the bucket is
  publicly accessible. Encryption provides no confidentiality benefit
  while public access is enabled.

### COMPOUND.003 — VPC Endpoint Without Endpoint Policy

- **Triggers**: ACCESS.003 PASS and ACCESS.006 FAIL simultaneously
- **Severity**: HIGH
- **Message**: VPC endpoint restricts this bucket but the endpoint policy
  does not restrict which bucket ARNs are reachable. This creates a
  wormhole: any principal on the VPC can reach any S3 bucket in any
  account via the endpoint, bypassing firewall controls.

## Acknowledged Exceptions

Legitimate configurations that intentionally fail invariants can be
declared as acknowledged exceptions in a `stave.yaml` file co-located
with the snapshot.

### Exception Declaration

```yaml
exceptions:
  - invariant_id: ACCESS.001
    bucket: my-public-assets-bucket
    rationale: "CloudFront + OAI pattern — bucket is private to CloudFront"
    acknowledged_by: bala@example.com
    acknowledged_date: 2026-03-28
    requires_passing:
      - CONTROLS.001
      - CONTROLS.004
      - AUDIT.001
```

### Exception Semantics

- An acknowledged exception changes a FAIL to ACKNOWLEDGED with the
  rationale attached
- The `requires_passing` list is mandatory — every exception must
  specify compensating controls
- All compensating controls must pass for the exception to be valid
- If any compensating control fails, the original FAIL stands with
  an added note: "Exception declared but compensating control X is
  not passing"
- An exception with no `requires_passing` is rejected at load time
- If `stave.yaml` does not exist, evaluation proceeds with no
  exceptions (not an error)

### Exception Report Section

Valid exceptions appear in a dedicated "Acknowledged Exceptions" section
with rationale, acknowledger, and compensating control status:

```
── Acknowledged Exceptions ──

  [VALID] ACCESS.001 — my-public-assets-bucket
  Rationale: CloudFront + OAI pattern — bucket is private to CloudFront
  Acknowledged by: bala@example.com
```

## Invariant Incompatibility

Some invariants are mutually exclusive and cannot coexist in the same
profile. The profile validator checks for known incompatible pairs at
startup (not at runtime).

| Pair | Reason |
|------|--------|
| CONTROLS.003 + RETENTION.001 | MFA Delete prevents lifecycle rules from permanently deleting objects |

If both are present in a profile, `ValidateProfile()` returns an error
before any evaluation begins.

## Report Formats

### Text Format (default)

```
═══ HIPAA Security Rule ═══
Bucket:    phi-data-bucket
Account:   ********9012
Snapshot:  2026-01-15T00:00:00Z
Result:    FAIL

── COMPOUND RISKS ──

  [CRITICAL] COMPOUND.001 (triggers: ACCESS.001, ACCESS.002)
  Public access with overly broad IAM permissions...

── CRITICAL ──

  [FAIL] CONTROLS.001.STRICT — CRITICAL
  Compliance: §164.312(a)(2)(iv) — CMK required for key revocation
  Finding: Bucket phi-data-bucket: encryption algorithm is "AES256"...
  Remediation: Change the default encryption to SSE-KMS...

── Summary ──

  CRITICAL: 0/4 passed
  HIGH: 1/3 passed
  MEDIUM: 1/1 passed

Overall: FAIL

Stave evaluates technical controls only. A BAA with AWS is a contractual
prerequisite for HIPAA compliance that Stave cannot verify.
```

### JSON Format

```bash
stave evaluate --snapshot snap.json --profile hipaa --format json
```

Structured JSON matching the `ProfileReport` type with all fields
including `compound_findings`, `acknowledged`, `results`, `counts`,
`fail_counts`, metadata, and the BAA disclaimer.

## Severity Levels

| Level | Meaning | SLA |
|-------|---------|-----|
| CRITICAL | Immediate risk of ePHI exposure | Remediate before production use |
| HIGH | Significant compliance gap | Remediate within the current sprint |
| MEDIUM | Defense-in-depth gap | Remediate within the current quarter |
| LOW | Informational finding | Remediate when convenient |

Severity ordering: CRITICAL > HIGH > MEDIUM > LOW. The `Severity` type
provides a `Less(other)` method for comparison.

## Architecture

### Package Layout

```
internal/core/invariant/          Invariant interface, severity, registries
internal/core/invariant/compound/ Compound risk detection rules
internal/core/asset/s3props.go    Typed S3 property structs
internal/profile/                 Profile type, HIPAA profile, profile registry
internal/profile/exception/       Acknowledged exception mechanism
internal/profile/reporter/        Text and JSON report generators
cmd/evaluate/                     CLI command wiring
```

### Invariant Interface

```go
type Invariant interface {
    ID() string
    Description() string
    Severity() Severity
    ComplianceProfiles() []string
    Evaluate(snap asset.Snapshot) Result
}
```

### Result Struct

```go
type Result struct {
    Pass           bool              `json:"pass"`
    InvariantID    string            `json:"invariant_id"`
    Severity       Severity          `json:"severity"`
    Finding        string            `json:"finding,omitempty"`
    Remediation    string            `json:"remediation,omitempty"`
    ComplianceRefs map[string]string `json:"compliance_refs,omitempty"`
}
```

### Registries

Invariants are organized into five registries:
- `AccessRegistry` — ACCESS.* (public access, policy checks)
- `ControlsRegistry` — CONTROLS.* (encryption, versioning, TLS)
- `AuditRegistry` — AUDIT.* (logging)
- `GovernanceRegistry` — GOVERNANCE.* (ACL control)
- `RetentionRegistry` — RETENTION.* (object lock, retention)

### Evaluation Pipeline

```
Load snapshot → Validate schema → Load profile → Validate incompatible pairs
  → Evaluate invariants → Apply exceptions → Detect compound risks
  → Generate report → Write output → Exit code
```

### Functional Options for Invariant Construction

```go
inv := &myInvariant{
    Definition: invariant.Build(
        invariant.WithID("ACCESS.001"),
        invariant.WithSeverity(invariant.Critical),
        invariant.WithComplianceRef("hipaa", "§164.312(a)(1)"),
        invariant.WithComplianceProfiles("hipaa", "pci-dss"),
    ),
}
```

### Shared Helpers

- `policyhelper.go` — Parses bucket policy JSON into `PolicyStatement`
  structs with `HasWildcardPrincipal`, `HasWildcardAction`, `HasAction`,
  `IsAllow`, `IsDeny`, `IsDenyNonTLS`
- `prophelper.go` — Extracts `storage.*` sub-maps from asset properties
  (`storageMap`, `encryptionMap`, `versioningMap`, `loggingMap`,
  `objectLockMap`)
- No JSON traversal logic is duplicated across invariants

### Account ID Redaction

The text reporter redacts AWS account IDs showing only the last 4 digits:
`123456789012` → `********9012`. Implemented as a pure function with its
own unit test.

### Golden File Testing

The text reporter output is validated against a golden file at
`internal/profile/reporter/testdata/reports/hipaa_golden.txt`.
Regenerate with:

```bash
go test ./internal/profile/reporter/... -update
```

## BAA Disclaimer

Every report includes:

> Stave evaluates technical controls only. A BAA with AWS is a
> contractual prerequisite for HIPAA compliance that Stave cannot verify.

This appears in both text and JSON output formats.
