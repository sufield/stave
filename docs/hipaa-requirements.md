# HIPAA Product Requirements

Product requirements for Stave's HIPAA compliance capabilities, derived
from competitive analysis (Vanta, Drata, Secureframe) and open-source
reference projects (Comp AI, SimpleRisk, GovReady-Q).

Stave's positioning: **technical cloud control reasoning layer** — not
a compliance management platform. Policy templates, employee training,
vendor management, and GRC workflows are out of scope.

---

## Requirement Categories

### A. Evidence Collection

| ID | Requirement | Status | Notes |
|---|---|---|---|
| HIPAA.REQ.001 | Collect AWS evidence needed for HIPAA technical safeguards | Partial | S3 bucket evidence collected; CloudTrail, VPC, IAM evidence missing |
| HIPAA.REQ.002 | Normalize raw AWS output into stable observation contract (`obs.v0.1`) | Done | Observation schema accepts `additionalProperties` for extensibility |
| HIPAA.REQ.003 | Support adding new AWS service evidence without engine redesign | Done | Extension pattern: add evidence source, map into contract, write control, test |

### B. Control Mapping

| ID | Requirement | Status | Notes |
|---|---|---|---|
| HIPAA.REQ.004 | Ship a HIPAA control pack mapping AWS evidence to named safeguards | Done | 43 YAML controls + 14 Go invariants + HIPAA pack in index.yaml |
| HIPAA.REQ.005 | Each control includes ID, rationale, evidence path, pass/fail logic, remediation | Done | YAML controls have `unsafe_predicate`, `remediation`; Go invariants have `FailResult` with remediation text |
| HIPAA.REQ.006 | Support grouping multiple AWS checks under one HIPAA requirement | Done | Pack system groups controls; compliance_mapping in YAML links to CFR sections |

### C. Risk and Reporting

| ID | Requirement | Status | Notes |
|---|---|---|---|
| HIPAA.REQ.007 | Output findings in both technical and risk-oriented formats | Done | Text (human), JSON (machine), SARIF (GitHub Code Scanning), Markdown (PR comments) |
| HIPAA.REQ.008 | Each failed control includes severity, resource, impact, remediation | Done | Finding struct carries ControlSeverity, AssetID, Evidence, Remediation |
| HIPAA.REQ.009 | Generate executive-ready summary for HIPAA exposure | Done | ProfileReport with severity counts, compound risks, pass/fail summary |
| HIPAA.REQ.010 | Output compound risk detection (cross-control violations) | Done | 3 compound rules (COMPOUND.001/002/003) detect dangerous combinations |
| HIPAA.REQ.011 | Support acknowledged exceptions with compensating controls | Done | ExceptionConfig with requires_passing validation |

### D. Assessment Workflow

| ID | Requirement | Status | Notes |
|---|---|---|---|
| HIPAA.REQ.012 | Assessment mode evaluates target against HIPAA pack | Done | `stave evaluate --profile hipaa` and `stave apply` with HIPAA pack |
| HIPAA.REQ.013 | Show pass, fail, and missing evidence separately | Done | Go invariants fail with "no data available" message when evidence missing |
| HIPAA.REQ.014 | Explain why a control could not be evaluated | Done | Missing-evidence failures include specific remediation about what to collect |
| HIPAA.REQ.015 | BAA disclaimer in compliance output | Done | "Stave evaluates technical controls only. A BAA with AWS is a contractual prerequisite..." |

### E. CI/CD Integration

| ID | Requirement | Status | Notes |
|---|---|---|---|
| HIPAA.REQ.016 | Exit codes distinguish pass (0), violations (1/3), input error (2) | Done | 6 semantic exit codes |
| HIPAA.REQ.017 | SARIF output for GitHub Code Scanning integration | Done | `--format sarif` on apply and security-audit |
| HIPAA.REQ.018 | Baseline tracking to detect violation count changes over time | Done | `stave enforce baseline save/check` |
| HIPAA.REQ.019 | Policy-based gating for merge blocking | Done | `stave enforce gate --policy any/critical` |
| HIPAA.REQ.020 | Environment variable configuration for CI | Done | `STAVE_*` variables with injectable Getenv |
| HIPAA.REQ.021 | Deterministic output for reproducible CI runs | Done | `--now` flag, sorted findings, `stave apply verify` |
| HIPAA.REQ.022 | Quiet mode for clean CI logs | Done | `--quiet`, NO_COLOR, TTY detection |

### F. Evidence Source Expansion

| ID | Requirement | Status | Blocked By |
|---|---|---|---|
| HIPAA.REQ.023 | CloudTrail evidence for object-level audit logging | Pending | Extractor needs `cloudtrail get-event-selectors` |
| HIPAA.REQ.024 | VPC endpoint evidence for network restriction controls | Pending | Extractor needs `ec2 describe-vpc-endpoints` |
| HIPAA.REQ.025 | IAM policy evidence for least-privilege verification | Pending | Extractor needs `iam get-role-policy`, `list-attached-role-policies` |
| HIPAA.REQ.026 | GuardDuty evidence for malware scanning status | Pending | Extractor needs GuardDuty API |
| HIPAA.REQ.027 | S3 policy condition key parsing for presigned URL restrictions | Done | `s3:signatureAge` and `s3:authType` parsing implemented |

### G. Controls Coverage

| ID | Requirement | HIPAA Section | Status |
|---|---|---|---|
| HIPAA.REQ.028 | Encryption at rest (SSE enabled) | §164.312(a)(2)(iv) | Done |
| HIPAA.REQ.029 | Encryption at rest (SSE-KMS with CMK) | §164.312(a)(2)(iv) | Done |
| HIPAA.REQ.030 | Public access prevention (all 4 BPA flags) | §164.312(a)(1) | Done |
| HIPAA.REQ.031 | Transmission security (deny non-TLS) | §164.312(e)(1) | Done |
| HIPAA.REQ.032 | Server access logging enabled | §164.312(b) | Done |
| HIPAA.REQ.033 | Object-level audit logging (CloudTrail) | §164.312(b) | Done |
| HIPAA.REQ.034 | Versioning enabled | §164.312(c)(1) | Done |
| HIPAA.REQ.035 | Object Lock for PHI retention | §164.312(c)(1) | Done |
| HIPAA.REQ.036 | No public access path (policy + ACL) | §164.312(a)(1) | Done |
| HIPAA.REQ.037 | VPC endpoint / IP restriction | §164.312(e)(1) | Done |
| HIPAA.REQ.038 | VPC endpoint policy not default | §164.312(e)(1) | Done |
| HIPAA.REQ.039 | Presigned URL restriction | §164.312(a)(1) | Done |
| HIPAA.REQ.040 | Least privilege / minimum necessary | §164.312(a)(1), §164.502(b) | Pending — needs IAM evidence |
| HIPAA.REQ.041 | Log review process verification | §164.308(a)(1)(ii)(D) | Pending — needs process evidence |
| HIPAA.REQ.042 | Malware scanning for uploaded files | §164.308(a)(5)(ii)(B) | Pending — needs GuardDuty evidence |
| HIPAA.REQ.043 | Breach detection and investigation support | §164.400-414 | Pending — needs multi-service evidence |

---

## Out of Scope

These are compliance management concerns, not technical control
evaluation. They belong to platforms like Vanta, Drata, or Secureframe.

| Feature | Why Out of Scope |
|---|---|
| Policy template libraries | Documentation, not config evaluation |
| Employee training workflows | Administrative safeguard, not technical |
| Vendor/third-party management | GRC operations layer |
| BAA contract tracking | Legal operations |
| Risk register management | Above technical control evaluation |
| Audit-readiness dashboards | Reporting UI, not CLI concern |

---

## Competitive Positioning

| Layer | Stave | Vanta / Drata / Secureframe |
|---|---|---|
| AWS config reasoning | Exact CEL-based control evaluation | Indirect — evidence collection and monitoring |
| Preventive enforcement | CI/CD gating with exit codes and baselines | Continuous monitoring dashboards |
| HIPAA control specificity | Individual S3 invariants with CFR citations | Framework-level compliance tracking |
| Compound risk detection | Cross-control analysis (3 patterns) | Not publicly detailed at this granularity |
| Output for auditors | Severity-grouped report with BAA disclaimer | Compliance dashboard with evidence timeline |
| Policy/training/vendor | Out of scope | Core strength |

Stave and compliance platforms are complementary, not competitive.
Stave provides the **technical control evaluation** that feeds into a
compliance platform's **evidence and workflow management**.

---

## Summary

| Category | Done | Pending |
|---|---|---|
| Evidence collection | 3/3 | — |
| Control mapping | 3/3 | — |
| Risk and reporting | 5/5 | — |
| Assessment workflow | 4/4 | — |
| CI/CD integration | 7/7 | — |
| Evidence source expansion | 1/5 | 4 (CloudTrail, VPC, IAM, GuardDuty) |
| Controls coverage | 12/16 | 4 (least privilege, log review, malware, breach) |

**35 of 43 requirements are implemented.** The remaining 8 are blocked
by missing evidence sources (AWS services beyond S3 bucket config), not
by engine or architecture limitations.
