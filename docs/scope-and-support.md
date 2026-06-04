# Scope and support

## In scope
- 2673 controls across 74 AWS/GCP/K8s/Azure service domains
- 603 compound chain definitions — multi-step attack paths
- Offline analysis of local configuration snapshots (obs.v0.1)
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
- `stave validate` — input validation
- `stave diagnose` — per-control analysis
- `stave ci` — CI/CD baseline and gating
- `stave export-sir` — SIR fact export for external reasoning
- `stave fingerprint explain` — policy fingerprint diagnostic
- `stave score` — posture scoring
- `stave gate` — CI pass/fail policy
- Tests: `make test`, `make test-fast`, `make test-e2e`, `make lint`
