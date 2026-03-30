# Pending Items

Tracks unimplemented controls and features that are referenced in code,
tests, documentation, or compound rules but do not yet have
implementations.

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
