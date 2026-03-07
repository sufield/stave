# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `stave config delete <key>` — remove a project config key, reverting to default
- Severity levels populated on all 43 S3 controls (10 critical, 20 high, 11 medium, 2 low)
- Compliance metadata (`compliance` field) on control definitions — maps framework names to control IDs
- Compliance mappings on 8 key controls (CIS AWS v1.4.0, PCI DSS v3.2.1, SOC 2)
- `--min-severity` flag on `evaluate` — filter controls by minimum severity level
- `--control-id` flag on `evaluate` — run a single specific control
- `--exclude-control-id` flag on `evaluate` — exclude specific controls (repeatable)
- `--compliance` flag on `evaluate` — run only controls with a mapping for the given framework
- `stave report` severity breakdown section (findings by severity table)
- `stave report` compliance summary section (framework → findings count + controls)
- SEVERITY column in report TSV output
- `control_severity` and `control_compliance` fields in evaluation findings output

### Changed
- **Breaking:** Removed `--out` flag from `evaluate`, `check`, `verify`, `ci diff`,
  `ci baseline check`, `report`, `ci gate`, `snapshot diff`, `snapshot upcoming`,
  and `snapshot hygiene`. Use shell redirection (`> file`) instead. Commands that
  create files (`generate`, `ingest`, `ci baseline save`, `enforce`, `ci fix-loop`)
  keep `--out` unchanged.
- **Breaking:** Removed `--summary-out` flag from `snapshot upcoming`. Pipe output
  to capture: `stave snapshot upcoming > "$GITHUB_STEP_SUMMARY"`.
- **Breaking:** Removed `-O` shorthand from `ci gate`.
- **Breaking:** Removed `-o` shorthand from `--out` flag on enforce, fix-loop, verify,
  ci diff, generate, report, baseline, and ingest. `-o` now consistently means
  `--observations` across all commands.
- **Breaking:** Removed `-i` shorthand from `--input` on ingest. `-i` now consistently
  means `--controls`.
- **Breaking:** Removed `-s` shorthand from `--step` on template. `-s` now consistently
  means `--sort`.
- `stave report --format json` now includes `findings_by_severity` and `compliance_summary` aggregations
- S3 extractor functions now accept `context.Context` for cancellation support,
  consistent with observation and control loaders
- Enabled `goimports` formatter in golangci-lint configuration

## [0.0.1] - 2026-02-17

### Added
- Core evaluation engine with duration tracking and recurrence detection
- 40 S3 controls covering public exposure, ACL, encryption, versioning, access logging, lifecycle, object lock, tenant isolation, and write scope
- CLI commands: validate, evaluate, diagnose, ingest --profile aws-s3, evaluate --profile aws-s3, verify, enforce, report, counterfactual, capabilities, alias, trace
- `--template` flag on evaluate, diagnose, and validate for custom output formatting
- Command alias system (`stave alias set|list|delete`) with user config storage
- JSON and text output formats
- Observation schema (obs.v0.1) and control DSL (ctrl.v1)
- Terraform plan extraction for S3 assets
- Golden-file E2E test framework with 95+ test cases
- OpenSSF Scorecard, signed releases, SLSA provenance, SBOM
