# Architecture

The four-layer model and how it was discovered.

---

## The Layers Were Found, Not Designed

Stave was not designed top-down from an architecture diagram. It grew from a single capability — evaluating security predicates against JSON snapshots — and each layer emerged when the layer below became insufficient.

### Layer 1: Data (Observations + Controls)

The foundation. JSON snapshots describe infrastructure state. YAML controls define what must be true. The CEL evaluation engine connects them. This layer answers: "is this asset compliant with this control?"

This was Stave for the first several months. It worked. Then the question changed.

### Layer 2: Evaluation (Assessment Engine)

One control evaluating one asset is useful. Six hundred controls evaluating eight hundred assets across two time points requires an engine that handles lifecycle tracking, temporal reasoning, SLA annotation, and deterministic output.

This layer emerged because the data layer could not answer "how long has this asset been non-compliant?" or "did this violation exist yesterday?" These are temporal questions that require maintaining state across snapshots.

### Layer 3: Analytical (Risk Reasoning)

Individual findings are necessary but not sufficient. The question became "which of these 84 findings should we fix first?" and "do these three findings together create a worse situation than each alone?"

This layer added: posture scoring, compound chains, attack path graphs, blast radius computation, and remediation ranking. These are analytical operations on the evaluation layer's output — they do not evaluate predicates themselves.

### Layer 4: Executive (Reporting + Governance)

The analytical layer produces data. The executive layer produces documents — reports, plans, comparisons, trend analyses, and evidence archives. The audience is no longer a security engineer looking at findings. It is a CISO presenting to a board, a compliance officer preparing an audit package, or a team lead routing remediation work.

## The OSI Analogy

This layering resembles OSI — each layer consumes the layer below and provides abstractions for the layer above. The difference: the threat model is embedded in the architecture rather than threat-agnostic.

In OSI, Layer 3 (Network) routes packets without caring whether the payload is malicious. In Stave, Layer 3 (Analytical) computes risk *because* the evaluation layer identified violations. Each layer exists specifically to reason about security — there is no general-purpose data processing here.

## Why This Matters

The layering explains why Stave has 30+ commands that appear unrelated. They are not unrelated — they operate at different layers:

| Layer | Commands |
|-------|----------|
| Data | `apply`, `validate`, `diagnose` |
| Evaluation | `apply` (assessment mode), `bisect`, `forensics` |
| Analytical | `score`, `rank`, `map`, `path`, `coverage` |
| Executive | `report`, `plan`, `compare`, `trend`, `budget`, `monitor`, `verify` |
