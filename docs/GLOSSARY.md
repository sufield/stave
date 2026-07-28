# Stave Terminology Glossary

This glossary maps Stave's internal terminology to security industry standards
(NIST SP 800-53, CSA CCM, OSCAL) and defines concepts introduced by Stave.

## Core Terms

| Stave Term | Security Standard | Reference | Definition |
|---|---|---|---|
| **Control** (`CTL.`) | NIST AC-3, CSA CCM | SP 800-53 rev5, CCM v4 | A declarative YAML rule that defines a condition which should never be true. Evaluated by the CEL predicate engine. |
| **Asset** | NIST RA-2, CSA IVS-01 | SP 800-53 rev5 | An infrastructure resource being evaluated. Identified by `id`, `type`, and `vendor` fields. |
| **Finding** | NIST SP 800-53A | Assessment reports | A violation detected by a control. Includes evidence, remediation, and compliance references. |
| **Observation** | OSCAL `<observation>` | NIST OSCAL | A point-in-time snapshot of infrastructure state (`obs.v0.1` JSON). Raw data input to evaluation. |
| **Evidence** | NIST SP 800-53A | Assessment reports | Validated proof attached to a Finding: timestamps, misconfigurations, unsafe duration, temporal risk. |
| **Sanitize** | NIST MP-6 | SP 800-53 rev5 | Deterministic removal of infrastructure identifiers (account IDs, ARNs) from output. |

## Evaluation Terms

| Term | Definition |
|---|---|
| **Assessor** | The core evaluation engine (`internal/core/evaluation/engine/`). Evaluates controls against asset snapshots. Cloud-agnostic — knows nothing about AWS, GCP, or any specific service. |
| **Unsafe State** | A condition where an asset's configuration matches a control's `unsafe_predicate`. The most common control type. |
| **Unsafe Duration** | How long an asset has been in an unsafe state across snapshots. Compared against the SLA threshold (`--max-unsafe`). |
| **Exposure Window** | A continuous period during which an asset is in an unsafe state. Bounded by the first and last observation where the predicate matches. |
| **Exposure Lifecycle** | The full history of an asset's exposure windows across all snapshots. Used for recurrence detection. |
| **SLA Threshold** | The maximum allowed unsafe duration (`--max-unsafe`). Findings fire when the unsafe duration exceeds this threshold. |
| **Security State** | The overall evaluation result: `COMPLIANT`, `AT_RISK`, or `NON_COMPLIANT`. |
| **Verdict** | Per-control×asset evaluation result: `PASS`, `VIOLATION`, `SKIPPED`, `INCONCLUSIVE`, or `NOT_APPLICABLE`. |
| **Confidence** | How certain the engine is about a verdict: `HIGH`, `MEDIUM`, or `LOW`. Affected by observation coverage gaps. |

## Control Types

| Type | When it fires |
|---|---|
| `unsafe_state` | Predicate matches at evaluation time. Most common. |
| `unsafe_duration` | Asset has been unsafe longer than the SLA threshold. |
| `unsafe_recurrence` | Asset has been unsafe too many times within a window. |
| `prefix_exposure` | Protected S3 key prefixes are publicly readable. |
| `marker` | Informational fact recorded for chain composition; never a violation on its own. |

## Domain Terms

| Term | Definition |
|---|---|
| **Domain** | A grouping of controls by service area: `s3` (AWS S3 storage), `iam` (AWS IAM identity), `gcs` (GCP Cloud Storage), `dns` (DNS records). |
| **Property Namespace** | The `properties.*` path structure for a domain. S3 uses `properties.storage.*`, IAM uses `properties.identity.*`, DNS uses `properties.dns.*`. |
| **Kind** | A discriminator within a property namespace. `storage.kind: "bucket"`, `identity.kind: "user"`, `identity.kind: "account"`. |
| **Vendor** | The cloud provider or service hosting the asset. Open string — accepts `aws`, `gcp`, `azure`, `cloudflare`, `namecheap`, or any value. Controls never evaluate vendor. |
| **Observation Contract** | The specification (`docs/contract/README.md`) that tells extractor authors what properties to populate for each domain. Stave's multi-domain capability is this contract, not code. |
| **INCOMPLETE Control** | A control that fires when the extractor provides insufficient data. Prevents false compliant verdicts. Every domain must have one. |

## Logic Trace Terms

| Term | Definition |
|---|---|
| **Logic Trace** | A structured audit trail (`trace.v0.1` JSON) recording every decision the engine makes during evaluation. One assessment per control×asset pair. |
| **Proof of Pass** | Positive evidence that a control was evaluated and the asset was compliant — not just absence of a finding. Captured in the trace. |
| **Assessment** | A single control×asset evaluation record in the trace. Contains ordered steps with inputs and results. |
| **Step** | A decision point in the evaluation chain: `exemption_check`, `predicate_evaluation`, `threshold_check`, `coverage_check`, `verdict_decision`. |

## Compliance Terms

| Term | Definition |
|---|---|
| **Profile** | A named set of controls for a compliance framework: `aws-s3`, `aws-iam`, `gcp-gcs`, `hipaa`. |
| **Compound Risk** | A dangerous combination of individual control results (e.g., public access + wildcard actions = lateral movement). Detected after individual evaluation. |
| **Acknowledged Exception** | A declared, documented risk acceptance in `stave.yaml` with mandatory compensating controls. |
| **Compensating Control** | A control that must pass for an exception to be valid. If it fails, the original finding stands. |
| **Compliance Reference** | A mapping from a control to a regulatory section (e.g., `hipaa: "164.312(a)(1)"`). |

## Tooling Terms

| Term | Definition |
|---|---|
| **Policy Forge** | The `make gencontrol` tool that scaffolds new controls with validated YAML and pass/fail E2E test fixtures. |
| **Extractor** | An external program (any language) that produces `obs.v0.1` JSON from cloud infrastructure. Not part of Stave. |
| **Semantic Alias** | A named shorthand for a predicate (e.g., `s3.is_public_readable`). Resolved at control load time. |
| **Pack** | A named collection of controls (e.g., `s3`, `iam`, `gcs`, `dns`, `hipaa`). Registered in `index.yaml`. |
| **Policy Hash** | Deterministic SHA-256 of all embedded control YAML files. Printed by `stave version --verify`. |

## Architecture Terms

| Term | Definition |
|---|---|
| **Hexagonal Architecture** | The layering model: `core/` (domain, zero external imports) → `app/` (services) → `adapters/` (infrastructure) → `cmd/` (CLI). |
| **Port** | An interface defined in `app/contracts` or `core/ports` that adapters implement. |
| **Adapter** | An infrastructure implementation in `internal/adapters/` (YAML loader, JSON writer, filesystem). |
| **Formal Proof System** | Stave's identity: a policy evaluation engine for JSON-represented infrastructure. The engine is cloud-agnostic. Asset types and vendors are open strings. Adding a new cloud provider requires only YAML controls and a contract extension — zero engine changes. |

## Rejected Terms

These terms were used during development and have been replaced. Do not use them.

| Rejected Term | Canonical Term |
|---|---|
| invariant | **control** |
| inventory | **observation** / **snapshot** |
| resource | **asset** |
| issue, violation, result | **finding** |
| ignore, suppress, skip | **exemption** |
| redact, scrub | **sanitize** |
| delta, change | **drift** |
| Episode | **ExposureWindow** (renamed) |
| Timeline | **ExposureLifecycle** |
| Runner (engine) | **Assessor** |

## Design Notes

### AssetID vs AssetURN

`AssetID` is a local identifier within a single observation snapshot (e.g.,
`my-phi-bucket`). For globally unique identifiers, cloud-native URNs (ARN, GCP
resource name) appear in the observation's `id` field. The `AssetID` type
intentionally avoids prescribing a format — it accepts whatever the observation
source provides.

### Observation → Evidence Relationship

Observations are raw point-in-time snapshots (input). Evidence is the validated
proof attached to a specific Finding (output). The evaluation engine transforms
observation data into evidence by matching control predicates and computing
unsafe durations.

### Vendor-Agnostic DNS

DNS controls evaluate `properties.dns.*` regardless of DNS provider. The
`vendor` field (`route53`, `cloudflare`, `namecheap`) is extractor metadata —
controls never reference it. The same control evaluates identically for any
DNS hosting service.
