# SSRF → IMDS → S3 Credential-Theft Blast Radius — Stave Coverage Audit

**Date**: 2026-04-19

## The defensible claim

Stave makes one S3-layer assertion against the SSRF → IMDS → credential-theft
class of attack: **the S3 layer does not trust the network perimeter**. If an
attacker steals IAM credentials via SSRF+IMDS and attempts to use them from a
network path the bucket's policy does not authorize, S3 should reject the
request — and Stave's catalog flags every bucket whose policy fails to enforce
that rejection.

Stave makes no upstream claim. See "Explicit non-scope" below.

## Controls that deliver the claim

All six controls below are in the current catalog as of commit
`659d7a022`:

| control_id | gates_on (obs field + op) | severity | compliance |
|---|---|:---:|---|
| `CTL.S3.POLICY.SCOPING.001` | `policy_has_scoping_condition` present:true AND eq:false | medium | nist AC-3, hipaa 164.312(a)(1), soc2 CC6.1, ccm DSP-07/DSP-17/IAM-16 |
| `CTL.S3.NETWORK.VPC.001` | `has_vpc_condition` eq:false AND `has_ip_condition` eq:false | high | hipaa 164.312(e)(1), nist SC-7, ccm DCS-07/IVS-03 |
| `CTL.S3.NETWORK.001` | `effective_network_scope` eq:`"public"` | high | nist AC-3, ccm DCS-07/IVS-03 |
| `CTL.S3.ACCESS.002` | `has_wildcard_principal` eq:true (raw — Condition-agnostic) | high | nist AC-6, ccm DSP-17/IAM-16 |
| `CTL.S3.ACCESS.004` | `policy_is_effectively_public` eq:true (Condition-aware via AWS `PolicyStatus.IsPublic`) | high | nist AC-3, hipaa 164.312(a)(1), soc2 CC6.1, ccm DSP-07/DSP-17/IAM-16 |
| `CTL.S3.ENCRYPT.002` | `encryption.in_transit_enforced` eq:false (TLS via `aws:SecureTransport`) | high | — |

`CTL.S3.ACCESS.002` + `CTL.S3.ACCESS.004` work in tandem: .002 is the raw
"wildcard principal exists" signal; .004 is the Condition-aware
"effectively public" signal that flips to false when a restricting
Condition narrows the wildcard. Operators get a sharp distinction
between "wildcard principal present but scoped" (action required but
not urgent) and "wildcard principal effectively public" (urgent).

## Gaps

### Gap A — KMS join (the "stolen credentials get ciphertext" defense)

**Plain statement: Stave does NOT verify this defense today.**

The blog post's remediation #4 is KMS encryption with a key policy that
restricts Decrypt to roles separate from the compute role reachable via
IMDS. Verifying it requires three observations; Stave has only two:

| Required observation | In contract? | Evidence |
|---|---|---|
| Bucket default encryption with KMS key ARN | ✓ | `storage.encryption.kms_key_id` — `docs/contract/storage.md:66` |
| KMS key policy shape | ⚠ partial | `cryptography.policy.has_wildcard_principal` (aggregate bool; consumed by `CTL.KMS.POLICY.001`). No list of allowed principals, no per-action breakdown. |
| IAM principals that can Decrypt with those keys | ✗ | No field; no cross-resource derivation joins bucket → key → allowed-decrypt principal set |

Without the third observation, Stave cannot say "the EC2 instance role
reachable via IMDS is NOT in the KMS key's allowed-decrypt principal
list for this bucket's key". It can say the key has no wildcard
principals, which is one layer thinner than the claim needs.

Authoring the join derivation is out of scope for this audit (per
task non-goals).

### Gap B — contract documentation for `has_vpc_condition` / `has_ip_condition` — **CLOSED (2026-04-19)**

Originally flagged: `CTL.S3.NETWORK.VPC.001`'s predicate consumes
`storage.access.has_vpc_condition` and `has_ip_condition`. Both fields
were consumed by the shipping control, present in fixture observations,
and validated by the built-in HIPAA control tests
(`internal/adapters/controls/builtin/hipaa_controls_test.go:89-92`).
They were not in `docs/contract/storage.md`, so an extractor conforming
only to the documented contract would silently fail to emit them and
the control's `eq:false` clauses would no-fire (CEL's present-gate
short-circuits `eq` on missing fields to false).

Resolution: both fields are now documented in `docs/contract/storage.md`
alongside the existing network-Condition cluster
(`policy_has_scoping_condition`, `policy_is_effectively_public`,
`effective_network_scope`). The entries specify the policy shape that
produces each value (`aws:SourceVpc` / `aws:SourceVpce` for VPC,
`aws:SourceIp` with a fixed CIDR for IP), note that `false` covers both
"policy exists without the Condition" and "no policy at all", and
record the consumer control and the extractor-must-emit requirement.
No semantic change — the documentation describes behavior the predicate
and fixtures already relied on.

Documentation-only iteration. No control, fixture, or code changes.

### Gap C — no S3-catalog "instance-role has bucket-wide Allow" control

The blog post's remediation #1 is least-privilege on the EC2 instance
role. The IAM-side controls cover the role-shape (admin access,
service wildcards, escalation chains, etc.) but there is no S3-side
cross-resource control that flags "this compute role has broad
`s3:*` on a bucket containing PHI-classified data". The cross-resource
derivation is IAM-catalog scope, not S3-catalog scope, and the claim
framing does not require it. Noted, not flagged as in-scope to fix.

## Fixture evidence

New fixture `testdata/e2e/e2e-s3-credential-theft-blast-radius/`
exercises the four bucket states below with the six controls from the
"Controls that deliver the claim" table loaded.

| Bucket ID | Scenario | Findings fired | Findings count |
|---|---|---|:---:|
| `bucket-a-broad-allow-no-condition` | Non-wildcard cross-account Allow, no scoping Condition, PAB on | `SCOPING.001`, `NETWORK.VPC.001` | 2 |
| `bucket-b-ip-scoped` | Same policy shape, plus `aws:SourceIp` Condition | — | 0 |
| `bucket-c-narrow-allow-no-condition` | Single-principal, single-action, single-resource Allow; no Condition | `NETWORK.VPC.001` | 1 |
| `bucket-d-compound-ssrf-aftermath-worst-case` | Broad Allow + wildcard Principal + no Condition + PAB off + public_read | `SCOPING.001`, `NETWORK.VPC.001`, `NETWORK.001`, `ACCESS.002`, `ACCESS.004`, `CONTROLS.001` umbrella | 6 |

Totals: 4 assets, 3 exposed, 9 findings. `make test` exit 0;
`TestE2E/e2e-s3-credential-theft-blast-radius` passes. Zero deltas
between expected and observed.

**Note on bucket C**: `CTL.S3.NETWORK.VPC.001` fires even though the
Allow is narrow and carries no non-narrow principal. This is by design —
the control enforces network-scoping as a global defense-in-depth
requirement, independent of Allow breadth. `CTL.S3.POLICY.SCOPING.001`
correctly stays silent on bucket C because the `policy_has_scoping_condition`
field resolves to `null` (nothing non-narrow to scope) and the
present-gate short-circuits.

## Explicit non-scope

Stave **does NOT** detect:

- **App-layer SSRF vulnerabilities.** Source-code analysis for
  user-controlled URL fetches is SAST scope. No Stave control fires
  against a Java/Python/Go source tree with a naive HTTP-client SSRF.
- **IMDSv1 vs IMDSv2 on EC2 instances.** The `aws:MetadataHttpTokens`
  attribute on EC2 instances is an EC2-scope observation; not in the
  current Stave contract. A future iteration could add
  `compute.metadata_service.*` fields and a control, but that is a
  separate scope expansion.
- **Stolen-credentials-get-ciphertext via KMS boundary.** See Gap A.
  Partial coverage on KMS key-policy hygiene (`CTL.KMS.POLICY.001`,
  `CTL.KMS.CONCENTRATION.*`, `CTL.KMS.ISOLATION.001`) but no
  bucket→key→allowed-decrypt-principal join.

The narrow claim — "S3 bucket policy rejects requests the compromised
credentials try to make from an external network path" — is the claim
Stave can stand behind today. The six controls above, exercised by the
four-bucket fixture, deliver it end to end.
