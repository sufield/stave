# Pending Items

Tracks unimplemented controls and features that are referenced in code,
tests, documentation, or compound rules but do not yet have
implementations.

---

## Current Status (2026-04-11)

**246 controls across 29 domains. All CSA P0, P1, P2 actionable features complete.**

### CSA Feature Completion

| Tier | Done | Partial | Out of Scope |
|------|------|---------|--------------|
| P0 (13) | 12 | 1 (IaC secrets — SAST) | 0 |
| P1 (14) | 10 | 0 | 4 (CORS, rate limit, CI/CD, deps) |
| P2 (7) | 7 | 0 | 0 |

### Remaining work

| Item | Type | Notes |
|------|------|-------|
| EFS encryption controls | New domain | Low priority — needs go:embed directive |
| 5 MVP 1.1+ feature slices | Engine (Go) | identity, drift, composition, rank, check |
| Service locator refactoring | Refactoring | Deferred — touches apply critical path |
| HIPAA.REVIEW.001 | Control | Out of scope — human process attestation |

### HIPAA backlog resolved

3 of 4 previously blocked HIPAA controls are now implemented:
- CTL.S3.ACCESS.PHI.001 (minimum necessary — §164.502(b))
- CTL.S3.MALWARE.001 (GuardDuty malware — §164.308(a)(5))
- CTL.S3.BREACH.DETECT.001 (detection infrastructure — §§164.400-414)

HIPAA.REVIEW.001 (log review process) remains out of scope — requires
human process attestation, not infrastructure configuration.

---

## Completed (2026-03-30)

All four previously pending HIPAA controls are now implemented:

| Control | File | Status |
|---|---|---|
| AUDIT.002 | `access_object_logging.go` | Implemented — reads `storage.logging.object_level_logging.enabled` |
| ACCESS.003 | `access_network_restriction.go` | Implemented — reads `storage.access.has_vpc_condition` / `has_ip_condition` |
| ACCESS.006 | `access_endpoint_policy.go` | Implemented — reads `storage.network.vpc_endpoint_policy` |
| ACCESS.009 | `access_presigned_url.go` | Implemented — parses `policy_json` for `s3:signatureAge` / `s3:authType` |

COMPOUND.003 (VPC endpoint without policy) is now functional — it fires
when ACCESS.003 passes and ACCESS.006 fails.

`WithProfileSeverityOverride` builder option has been restored to
`control.go`.

---

## Extractor Requirements

The new controls expect observation fields that the current S3-only
extractor may not populate. Extractors that produce these fields:

| Field | AWS CLI Source | Service |
|---|---|---|
| `storage.logging.object_level_logging` | `aws cloudtrail get-event-selectors` | CloudTrail |
| `storage.access.has_vpc_condition` | Already populated by S3 extractor | S3 |
| `storage.access.has_ip_condition` | Already populated by S3 extractor | S3 |
| `storage.network.vpc_endpoint_policy` | `aws ec2 describe-vpc-endpoints` | EC2/VPC |
| `policy_json` (for presigned URL conditions) | `aws s3api get-bucket-policy` | S3 |

Controls handle missing fields gracefully — they fail with a clear
message about what observation data is needed.

---

## Checklist for Implementing a New HIPAA Control

1. Create `internal/core/hipaa/<category>_<behavior>.go` with struct + `Evaluate()`
   - Use snake_case functional naming (e.g., `access_vpc_endpoint.go`)
   - Struct name matches file: `accessVpcEndpoint`
2. Add `init()` calling `ControlRegistry.MustRegister(...)` with:
   - `WithID("...")`
   - `WithDescription("...")`
   - `WithSeverity(...)`
   - `WithComplianceProfiles("hipaa")`
   - `WithComplianceRef("hipaa", "§...")`
   - `WithProfileRationale("hipaa", "...")`
   - `WithProfileSeverityOverride("hipaa", ...)` if severity differs from default
3. Create `internal/core/hipaa/<category>_<behavior>_test.go`
4. Run `go test ./internal/core/hipaa/... ./internal/profile/...`
5. No changes to `hipaa.go` or `profile.go` required — auto-discovery handles it
