# Scope and support

## In scope
- 2907 controls across 86 AWS/GCP/K8s/Azure service domains
- 622 compound chain definitions — multi-step attack paths
- Offline analysis of local configuration snapshots (obs.v0.1)
- Built-in snapshot→observation conversion (`stave transform`, jq filters) for common AWS resources; external extractors (Steampipe, CloudQuery, custom) still supported for broader coverage
- Deterministic findings and reports
- 10 compliance framework profiles: HIPAA, CIS AWS v3.0, SOC 2, PCI-DSS v4.0, NIST 800-53, FedRAMP, GDPR, FFIEC, ISO 27001, NIST CSF 2.0
- Three reasoning engines: CEL, Soufflé, Z3
- Go library API (`pkg/stave/`) for in-process evaluation

## Out of scope
- Runtime behavior monitoring or agents
- Application-specific logic (CMS, e-commerce, etc.)
- Organizational processes (training, incident response plans, vendor management)
- Live API call history or metric alarm trigger state
- Cloud credential management — Stave never touches your cloud directly

## Supported commands
- `stave apply` — control evaluation (default and profile modes)
- `stave transform` — convert raw AWS snapshots to obs.v0.1 (built-in jq filters)
- `stave validate` — input validation
- `stave diagnose` — per-control analysis
- `stave ci` — CI/CD baseline and gating
- `stave export-sir` — SIR fact export for external reasoning
- `stave fingerprint explain` — policy fingerprint diagnostic
- `stave score` — posture scoring
- `stave gate` — CI pass/fail policy
- Tests: `make test`, `make test-fast`, `make test-e2e`, `make lint`

## Source type validation

Stave validates the `generated_by.source_type` field in observations against a
built-in allowlist. Accepted source types do not imply cloud API access — all
inputs are local snapshot files. Source types that are not in the built-in
list (for example, a custom extractor) are accepted by default.

## Status definitions

- **Supported** — Controls exist, are tested (unit + E2E), and are recommended
  for production use.
- **Preview** — Accepted by the engine's input validation, but no shipped
  controls or extractors target it yet. Used for engine regression testing or
  reserved for future expansion.
