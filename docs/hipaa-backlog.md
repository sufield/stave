# HIPAA Controls Backlog

Maps the HIPAA control spec from `stave-guide/hippa-table.md` to what
is implemented. The HIPAA pack uses two systems:
1. **YAML controls** (`stave apply`) — 47 CEL-evaluated S3 controls
2. **Go invariants** (`stave evaluate --profile hipaa`) — 14 programmatic checks

Updated: 2026-03-30

---

## Completed

All S3-testable HIPAA controls are implemented across both systems.

| HIPAA Control | YAML Controls | Go Invariants | System |
|---|---|---|---|
| HIPAA.ENCRYPT.001 | `CTL.S3.ENCRYPT.001` | `CONTROLS.001` | Both |
| HIPAA.ENCRYPT.002 | `CTL.S3.ENCRYPT.003` | `CONTROLS.001.STRICT` | Both |
| HIPAA.PUBLIC.001 | `CTL.S3.CONTROLS.001` | `ACCESS.001` | Both |
| HIPAA.TRANSPORT.001 | `CTL.S3.ENCRYPT.002` | `CONTROLS.004` | Both |
| HIPAA.AUDIT.001 | `CTL.S3.LOG.001` | `AUDIT.001` | Both |
| HIPAA.AUDIT.002 | `CTL.S3.AUDIT.OBJECTLEVEL.001` | `AUDIT.002` | Both |
| HIPAA.INTEGRITY.001 | `CTL.S3.VERSION.001` | `CONTROLS.002` | Both |
| HIPAA.INTEGRITY.002 | `CTL.S3.LOCK.001/002/003` | `RETENTION.002` | Both |
| HIPAA.ACCESS.001 | `CTL.S3.PUBLIC.001-008` + ACL controls | `ACCESS.001` | Both |
| (VPC/IP restriction) | `CTL.S3.NETWORK.VPC.001` | `ACCESS.003` | Both |
| (VPC endpoint policy) | `CTL.S3.NETWORK.POLICY.001` | `ACCESS.006` | Both |
| (Presigned URL) | `CTL.S3.PRESIGNED.001` | `ACCESS.009` | Both |

### Recently completed (2026-03-30)

Phase 1 YAML parity controls — 4 new `ctrl.v1` files created via TDD:

| YAML Control | Go Invariant | Test File |
|---|---|---|
| `CTL.S3.NETWORK.VPC.001` | `ACCESS.003` | `hipaa_controls_test.go` |
| `CTL.S3.NETWORK.POLICY.001` | `ACCESS.006` | `hipaa_controls_test.go` |
| `CTL.S3.PRESIGNED.001` | `ACCESS.009` | `hipaa_controls_test.go` |
| `CTL.S3.AUDIT.OBJECTLEVEL.001` | `AUDIT.002` | `hipaa_controls_test.go` |

All 4 controls are in the HIPAA pack (`index.yaml`) and the S3 pack.
Control reference docs regenerated (47 controls total).

---

## Pending: Evidence Source Expansion

These controls are implemented but depend on observation fields that
the current S3-only extractor may not populate. The controls handle
missing evidence gracefully with clear failure messages.

| Observation Field | AWS CLI Source | Used By |
|---|---|---|
| `storage.logging.object_level_logging` | `aws cloudtrail get-event-selectors` | `CTL.S3.AUDIT.OBJECTLEVEL.001`, `AUDIT.002` |
| `storage.network.vpc_endpoint_policy` | `aws ec2 describe-vpc-endpoints` | `CTL.S3.NETWORK.POLICY.001`, `ACCESS.006` |
| `storage.access.presigned_url_restricted` | Derived from `aws s3api get-bucket-policy` | `CTL.S3.PRESIGNED.001` |
| `storage.access.has_vpc_condition` | Already populated by S3 extractor | `CTL.S3.NETWORK.VPC.001`, `ACCESS.003` |
| `storage.access.has_ip_condition` | Already populated by S3 extractor | `CTL.S3.NETWORK.VPC.001`, `ACCESS.003` |

See `docs/hipaa-evidence-sources.md` for the full extractor contract.

---

## Pending: Blocked by Multi-Service Evidence (Future)

These HIPAA requirements cannot be implemented from S3 bucket config
alone. They require a separate "HIPAA Organizational Controls" pack.

| HIPAA Control | Blocked By | Evidence Needed |
|---|---|---|
| HIPAA.ACCESS.002 | IAM evidence | IAM role policies, caller identity paths, prefix scoping |
| HIPAA.REVIEW.001 | Process evidence | Log review procedures, attestations, workflow proof |
| HIPAA.MALWARE.001 | Service evidence | GuardDuty Malware Protection, Lambda scanning pipeline |
| HIPAA.BREACHSUPPORT.001 | Multi-service | GuardDuty, Config, CloudTrail, incident response workflow |

**These 4 controls are out of scope for the S3 config pack.** They need
new evidence sources and potentially new asset types.

---

## Summary

| Category | Count | Status |
|---|---|---|
| Implemented (both systems) | 12 | 47 YAML + 14 Go invariants |
| Pending evidence expansion | 3 | Controls exist; extractors need expansion |
| Blocked (multi-service) | 4 | Future — needs IAM/GuardDuty/process evidence |
| **Total** | **19** | **12 done, 3 need extractors, 4 blocked** |

The stave core (evaluator, CEL engine, profile system) requires **zero
changes**. Remaining work is additive at the evidence and extractor layers.
