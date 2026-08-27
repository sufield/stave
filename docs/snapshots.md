# Snapshot Model 

## The Problem

Cloud security tools query live APIs. This creates four problems:

1. **Non-reproducible** — run the same assessment twice, get
   different results. No auditor can independently verify.
2. **Credential scope** — the tool needs broad read access on the
   assessment host. In regulated environments, that's a liability.
3. **No history** — once the API returns current state, the
   previous state is gone.
4. **Network dependency** — air-gapped environments are excluded
   entirely.

## The Constraint

Stave was designed for classified networks, regulated healthcare
environments, and financial institutions with strict network
segmentation.

## The Design Decision

Separate collection from evaluation. The collector runs in the
environment with API access and produces a JSON file. The file
is transferred to the assessment host. The assessment engine
reads the file and never calls a cloud API.

This is the snapshot model. Every other property derives from it:

**Determinism.** Same files + same `--eval-time` → byte-identical
output. The verdict is evidence, not a claim.

**Time travel.** Snapshots committed to git are 
configuration history. `stave apply` against a 90-day-old
snapshot produces the exact assessment it would have produced
90 days ago. 

**Evidence archives.** Snapshots are immutable artifacts that can
be signed, bundled, and submitted to auditors. The assessment
is reproducible against the same artifact indefinitely.

**No credential management.** The assessment host never holds
cloud credentials. Collection happens elsewhere, by whatever
mechanism the organization already uses.

## The Trade-Off

Snapshots are point-in-time observations.
A daily snapshot does not capture a misconfiguration that existed
for 2 hours between snapshots.

Accepted in exchange for: offline evaluation, time travel,
determinism, evidence archives, no credential management.

## Why Attestation

The snapshot-as-evidence model requires an answer to "was this
snapshot tampered with after collection?"

Two integrity layers exist because they protect different things:

- **Manifest** (per-file SHA-256) — answers "are these the same
  files that were collected?" File-level, transport-oriented.
- **Inline attestation** (Ed25519 on the assets array) — answers
  "is this the same configuration state that was observed?"
  Content-level, evidence-oriented.

A manifest verifies file integrity even if the format changes. An
attestation verifies content even if the file is re-packaged,
split, or bundled. Coupling them would force every consumer to
understand both concerns.

## Why a Time-Series

A single snapshot answers "is this safe right now?" A directory
of snapshots answers "how long has this been unsafe?" 

The engine tracks per-asset state transitions via
`ExposureLifecycle`. Each unsafe span is an `ExposureWindow`.
This enables duration-based detection, drift detection, and SLA
escalation.

Semantic rules and why they exist:

- **Absence is not evidence of safety.** An asset missing from a
  snapshot stays in its previous state. Without this, a
  misconfigured resource that temporarily disappears from
  collection would look remediated.
- **Exposure windows close only on explicit evidence.** An
  observed unsafe→safe transition is required. Without this,
  a gap in collection would close every open window.
- **VIOLATION always beats INCONCLUSIVE.** Observation gaps affect
  certainty, never findings. Without this, intermittent
  collection would suppress real findings.

## Why Separate Collection from Evaluation

Collection is the hard, environment-specific part such as different IAM
roles, different networks, different providers. Evaluation is the
deterministic part.

Coupling them would force Stave to solve credential management,
network access, and provider versioning. The same problems the
snapshot model was designed to avoid. Separating them lets each
side evolve independently.

