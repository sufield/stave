# Stave Terminology Glossary

This glossary maps Stave's internal terminology to security industry standards (NIST SP 800-53, CSA CCM, OSCAL).

## Active Terms

| Stave Term | Security Standard | Reference | Notes |
|---|---|---|---|
| **Control** (`CTL.`) | NIST AC-3 "Access Enforcement", CSA CCM | SP 800-53 rev5, CCM v4 | A declarative rule that defines a condition which should never be true. |
| **Asset** | NIST RA-2 "Security Categorization", CSA IVS-01 | SP 800-53 rev5 | An infrastructure resource being evaluated. |
| **Sanitize** | NIST MP-6 "Media Sanitization" | SP 800-53 rev5 | Deterministic sanitization of infrastructure identifiers from output. |
| **Finding** | NIST SP 800-53A | Assessment reports | A violation detected by a control. SARIF uses "results" but the concept maps directly. |
| **Observation** | OSCAL `<observation>` | NIST OSCAL | A point-in-time snapshot of infrastructure state. Raw data input to evaluation. |
| **Evidence** | NIST SP 800-53A | Assessment reports | Validated proof attached to a Finding. Observations are raw data points; Evidence is the subset that proves a specific violation (timestamps, misconfigurations, duration). |

## Design Notes

### AssetID vs AssetURN

`AssetID` is a local identifier within a single observation snapshot (e.g., `my-phi-bucket`). For globally unique identifiers, cloud-native URNs (ARN, GCP resource name) appear in the observation's `id` field. The `AssetID` type intentionally avoids prescribing a format — it accepts whatever the observation source provides.

### Observation → Evidence Relationship

Observations are raw point-in-time snapshots (input). Evidence is the validated proof attached to a specific Finding (output). The evaluation engine transforms observation data into evidence by matching control predicates and computing unsafe durations.
