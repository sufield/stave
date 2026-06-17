---
title: "Security and Trust"
sidebar_label: "Security and Trust"
sidebar_position: 2
description: "Overview of Stave's security design and trust model."
---

# Security and Trust

Stave is designed with a minimal attack surface and a verifiable release pipeline.

## Security Design

- **No network access** -- Stave makes zero network connections at runtime. It reads local files and writes to stdout/stderr.
- **No subprocess execution** -- Stave does not shell out to external tools.
- **No persistent state** -- No databases, caches, or config files are created.
- **Read-only inputs** -- Observation and control files are never modified.
- **Air-gapped compatible** -- The binary contains no networking code. See [Offline & Air-Gapped Operation](../offline-airgapped.md).

## Trust Documents

| Document | Covers |
|----------|--------|
| [Security Guarantees](./01-guarantees.md) | Full inventory of every guarantee: offline, no-creds, determinism, no-exec, filesystem safety, sanitization, supply chain |
| [Release Security](./02-release-security.md) | How releases are built, signed, and verified (checksums, Cosign, SBOM, provenance) |
| [Offline & Air-Gapped Operation](../offline-airgapped.md) | Network dependency inventory for build vs runtime |
| [Execution Safety](./execution-safety.md) | No-exec guarantees: no plugins, no templates, no interpreters, closed DSL |
| [Sharing Outputs Safely](../sanitization.md) | Sanitization and scrubbing for safe output sharing |
| [Data Flow and I/O](./data-flow-and-io.md) | Per-command I/O model, permission policy, overwrite protection, stdin convention |
| [Evaluation Engine Capabilities](../evaluation-engine-capabilities.md) | What the engine supports vs. what S3 controls use — MVP 1.0+ candidate code |

## What Stave Evaluates

Stave evaluates configuration snapshots against declarative safety controls. As of MVP 1.0, the evaluation engine supports these control types (`internal/core/controldef/control_type.go`):

| Control Type | Evaluation | Status |
|---------------|-----------|--------|
| `unsafe_state` | Resource currently unsafe | Supported |
| `unsafe_duration` | Resource unsafe longer than threshold | Supported |
| `unsafe_recurrence` | Resource toggling safe/unsafe repeatedly | Supported |
| `prefix_exposure` | Public access to non-approved S3 key prefixes | Supported |
| `marker` | Informational fact recorded for chain composition | Supported |

Controls in the "Defined, not yet evaluated" category are valid YAML definitions that load without error but are silently skipped during evaluation.

## What Stave Does Not Do

Scope clarity is critical for trust. Stave explicitly does **not**:

- **Connect to AWS, GCP, Azure, or any cloud provider.** Stave evaluates pre-exported configuration snapshots. It never calls cloud APIs. Data collection is a separate step performed by other tools (`aws s3api`, Terraform, or Stave's own `extract` command which itself only reads local files).
- **Scan running infrastructure.** Stave is not a vulnerability scanner, port scanner, or network scanner. It analyzes static configuration data.
- **Detect runtime threats.** Stave does not monitor for intrusions, anomalous API calls, or real-time attacks. It checks whether configurations meet safety properties.
- **Evaluate IAM policies for effective permissions.** Stave checks whether bucket policies grant public or cross-account access. It does not simulate the full IAM policy evaluation chain (SCPs, permission boundaries, session policies).
- **Evaluate non-S3 AWS services.** EC2, RDS, Lambda, DynamoDB, VPC, and other services are not covered. The control catalog focuses on S3 storage, exposure management, and third-party boundaries.
- **Guarantee completeness.** Stave can only evaluate what's in the observation snapshots. Missing data (incomplete exports, insufficient IAM permissions during collection) limits coverage. The `CTL.S3.INCOMPLETE.001` control detects this condition and raises a violation when safety cannot be proven.
- **Replace SIEM, CSPM, or CNAPP tools.** Stave is designed to complement existing security tooling by providing deterministic, auditable, offline evaluation of specific safety properties.

## False Negative Risk

A false negative occurs when Stave reports no violation but an unsafe condition exists. Known causes:

**1. Incomplete observation data.** If the AWS CLI export omits bucket policy or ACL data (due to insufficient IAM permissions), Stave cannot assess that bucket's safety. **Mitigation:** `CTL.S3.INCOMPLETE.001` explicitly flags buckets where `safety_provable` is `false`. This converts a silent false negative into an explicit violation.

**2. Insufficient observation coverage.** Duration-based controls require multiple snapshots spanning the `--max-unsafe` window. With a single snapshot or a span shorter than the threshold, Stave returns `INCONCLUSIVE` — not `PASS`. This prevents false confidence from being reported as a clean bill of health.

**3. Observation gaps.** If snapshots are more than 12 hours apart, Stave returns `INCONCLUSIVE` for duration-based controls. Confidence levels degrade based on gap size relative to the assessment window.

**4. Control coverage gaps.** Stave evaluates only the controls in the directory you specify. If no control checks for a specific misconfiguration, Stave will not detect it. The control catalog is published and version-controlled; review it to understand coverage boundaries.

**5. Open episodes at observation boundaries.** If a resource becomes unsafe in the final snapshot, the duration calculation depends on the `--now` parameter. An incorrect `--now` value can undercount duration. **Mitigation:** Always set `--now` to the current time in production or the latest snapshot time in CI.

## False Positive Risk

A false positive occurs when Stave reports a violation but the resource is actually safe. Known causes:

**1. Clock skew via `--now`.** If `--now` is set significantly after the latest snapshot, duration calculations may overcount. The `diagnose` command detects this condition.

**2. Stale observations.** If observation data is outdated and the resource was remediated after the last export, Stave evaluates the stale state. **Mitigation:** Re-export observations before evaluation.

**3. Intentional configurations flagged as unsafe.** Some environments intentionally use public S3 buckets (e.g., public datasets). **Mitigation:** Use `--ignore` with an ignore list YAML that documents the business justification, or use `scope.exclude` in control definitions to exclude specific resource patterns.

**4. Ignored resources are visible.** When resources are excluded via `--ignore`, they appear in the output's `skipped_resources` array with the matched pattern and reason. This ensures ignore rules are auditable and do not silently mask violations.

## Compliance Mapping

Stave's control catalog maps to specific regulatory requirements. The following mapping is based on the control definitions in the codebase:

| Requirement | Stave Coverage | Controls |
|-------------|---------------|----------|
| HIPAA 164.312(a)(1) — Access control | S3 bucket policy and ACL checks | `CTL.S3.ACCESS.*`, `CTL.S3.PUBLIC.*` |
| HIPAA 164.312(a)(2)(iv) — Encryption | Encryption-at-rest and in-transit | `CTL.S3.ENCRYPT.001-004` |
| HIPAA 164.312(b) — Audit controls | Access logging enabled | `CTL.S3.LOG.001` |
| HIPAA 164.312(c)(1) — Integrity | Versioning and Object Lock | `CTL.S3.VERSION.*`, `CTL.S3.LOCK.*` |
| HIPAA 164.530(j) — Retention | 6-year (2190-day) minimum retention | `CTL.S3.LIFECYCLE.002`, `CTL.S3.LOCK.003` |

**Assertion — not yet independently verified:** No third-party audit has validated these compliance mappings. The mappings are based on the Stave development team's interpretation of the regulatory text. Organizations should independently assess whether Stave's controls satisfy their specific compliance obligations.

## Audit Status

**Assertion — not yet independently verified:**

- Stave has not undergone a formal third-party security audit or penetration test.
- No SOC 2 Type II report, ISO 27001 certification, or FedRAMP authorization exists for Stave.
- The codebase is open for inspection. The claims in this document can be independently verified by reading the source files referenced in each section.

## Vulnerability Reporting

Report security vulnerabilities through [GitHub Security Advisories](https://github.com/sufield/stave/security/advisories/new). See [SECURITY.md](../../SECURITY.md) for the full policy.
