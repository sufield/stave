# Stave — Cloud Security Intelligence Platform

## The Problem

Scanners produce disconnected lists: "this bucket is public, that
key is unrotated, logging is disabled." The auditor must reason about
how they combine. Stave automates that reasoning.

---

## What Stave Produces

**Compound attack paths, not finding lists.**
When a public S3 bucket, an unrotated KMS key, and disabled
CloudTrail co-fail, Stave detects the combination as a single
exfiltration path with a compound severity and blast radius — not
three separate findings. Fifty compound threat chains ship with
the catalog. Every finding that contributes to an active chain
carries an `[ATTACK PATH]` annotation in the output.

**Compliance evidence packages, not compliance scores.**
Stave maps every control to HIPAA, PCI-DSS, SOC2, FedRAMP, and CIS
citations. `stave export --compliance hipaa` produces a
machine-readable evidence package showing which controls passed,
which failed, the reasoning trace for each finding, and SLA
compliance rates per requirement. The same output that detects
misconfigurations produces the artifact an auditor reviews.

**Identity-centric risk rankings, not flat finding lists.**
`stave rank --identity` answers the question CISOs actually ask:
"If we can fix one thing this week, what protects the most?"
It resolves the full IAM policy graph — SCPs, permission boundaries,
resource policies, role chains — and ranks identities by the
transitive risk they carry. "Fix this one credential: protects 14
resources, reduces 68% of total portfolio risk."

**Dwell-time SLA enforcement, not point-in-time snapshots.**
Stave tracks how long each misconfiguration has been open and
enforces configurable remediation deadlines per control and
compliance profile. Critical findings approaching their SLA
window are escalated in rank output and flagged in CI/CD gates.

**Organization-wide posture, not per-account assessment.**
`stave consolidate` reads snapshots from multiple AWS accounts
simultaneously and surfaces cross-account attack paths — a
developer role in staging that can assume a production admin role
is invisible to per-account tools. Visible to Stave.

**Standards-based graph export, not proprietary formats.**
`stave graph export --format graph-json` produces a security graph
conforming to OCSF (findings), STIX 2.1 (threat chains and attack
patterns), MITRE ATT&CK (tactic IDs), and OSCAL (compliance
controls). Load it into Neo4j, Amazon Neptune, or any graph database.
Ask questions: "What is the minimum set of IAM changes that severs
all attack paths to production PHI?"

---

## How It Works

**Deterministic.** The same snapshot always produces the same
findings. Every conclusion is traceable to the specific observation
properties and policy documents that produced it. An auditor can
verify any finding by inspection — no black-box scoring.

**Air-gapped.** Stave evaluates local snapshot files. No cloud
credentials at assessment time. No live API calls during evaluation.
Snapshots can be collected by existing extractors, stored locally,
and assessed in any environment including air-gapped security
networks.

**Evidence-grade output.** Every finding carries a `finding_id`
— a stable fingerprint for cross-run correlation in external GRC
platforms, ticketing systems, and SIEM. Acknowledged findings carry
an audit trail: who accepted the risk, when, why, and which
compensating controls must remain passing.

**System Invariant as code.** Security policy is expressed as versioned
YAML invariant files in `controls/`. Custom controls take minutes
to write with `stave forge new` — browse available property paths
from a real snapshot, write a CEL predicate, see live evaluation
results before generating any file.

---

## What Stave Is Not

**Not a secret scanner.** Stave checks whether security mechanisms
are correctly configured — encryption enabled, access blocked, MFA
enforced. It does not pattern-match on credential values. GitGuardian
and Trufflehog do that better.

**Not a vulnerability scanner.** Stave detects infrastructure
misconfigurations. It does not scan package dependencies or container
images for CVEs. Syft, Grype, and Trivy do that better. The SBOM
integration in `docs/integrations/` shows how to join both.

**Not a live monitor.** Stave is a batch assessment engine. Run it
on a schedule, in CI/CD, or on demand. `stave trend` tracks posture
over time across assessment runs.

---

## The Single Line

Stave is a deterministic, air-gapped cloud security intelligence
engine that reasons over infrastructure snapshots to produce compound
attack path analysis, compliance evidence, and identity-centric risk
rankings — no cloud credentials required.
