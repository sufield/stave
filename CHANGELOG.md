# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Three per-service IAM privilege-escalation controls** grounded in
  three disclosed incidents. Each detects a distinct privesc path
  where a principal can invoke a service whose role exceeds the
  principal's effective permissions. Per-service framing was chosen
  over a generalized predicate so service-specific preconditions
  (`CAPABILITY_IAM` for CloudFormation, source-repo write for
  CodeBuild) can gate the finding and suppress the CI/CD-pipeline
  false-positive class.
  - `CTL.IAM.ESCALATE.PASSROLE.CREATESTACK.001` — `iam:PassRole`
    plus `cloudformation:CreateStack` without a `CAPABILITY_IAM`
    denial. Grounded in the Yani disclosure (Sep 2022).
    CCM: `CCC-04`, `IAM-05`, `IAM-16`.
  - `CTL.IAM.ESCALATE.PASSROLE.RUNINSTANCES.001` — `iam:PassRole`
    plus `ec2:RunInstances` on an instance-profile role whose
    permissions exceed the principal's. Grounded in the Security
    Shenanigans disclosure (Oct 2020). CCM: `IAM-05`, `IAM-16`.
  - `CTL.IAM.ESCALATE.STARTBUILD.001` — `codebuild:StartBuild`
    plus source-repo write on a project whose service role exceeds
    the principal's. Non-PassRole variant. Grounded in the HTB
    Business CTF disclosure (Jun 2025). CCM: `AIS-06`, `IAM-05`,
    `IAM-16`.
  Observation contract (consumed by the controls) extends
  `identity.escalation` with per-vector objects: `passrole_createstack`,
  `passrole_runinstances`, `startbuild_source_write`. Each carries
  `present`, `target_role`, `permission_delta`, and vector-specific
  fields (`via_capability_iam`, `target_project`, `source_type`).
  Extractor work to populate these fields lives outside this repo;
  fixtures carry the shape hand-authored.
- **CCM v4 mapping metadata on controls** — optional `compliance.ccm_v4`
  list on `ctrl.v1` accepting CSA CCM v4 control IDs in `DOMAIN-NN`
  form (e.g., `IAM-05`, `CCC-07`). Absence = not yet mapped; empty list
  = no CCM mapping applicable. 630 / 630 built-in controls back-filled
  via directory + function inference (100% coverage). Reference at
  `docs/reference/ccm-v4-controls.md`.
- **CCM v4 mappings propagate to evaluation findings** — additive
  `control_compliance_ccm_v4` field on each finding in `out.v0.1`
  output; no change to the existing `control_compliance` map or any
  other framework mappings (SOC 2, PCI, NIST, FedRAMP, ISO, HIPAA, CIS).
- **CCM v4 mappings carried in OCSF export** — populated into the
  OCSF 1.1 `compliance.requirements` array as `CCM:<ID>` strings so
  downstream SIEMs can filter by framework prefix. No change to other
  OCSF fields. Wire-format `schema_version` stays at `out.v0.1` since
  the change is additive under the 0.1.x contract.
- `stave config delete <key>` — remove a project config key, reverting to default
- Severity levels populated on all 43 S3 controls (10 critical, 20 high, 11 medium, 2 low)
- Compliance metadata (`compliance` field) on control definitions — maps framework names to control IDs
- Compliance mappings on 8 key controls (CIS AWS v1.4.0, PCI DSS v3.2.1, SOC 2)
- `--min-severity` flag on `apply` — filter controls by minimum severity level
- `--control-id` flag on `apply` — run a single specific control
- `--exclude-control-id` flag on `apply` — exclude specific controls (repeatable)
- `--compliance` flag on `apply` — run only controls with a mapping for the given framework
- `stave report` severity breakdown section (findings by severity table)
- `stave report` compliance summary section (framework → findings count + controls)
- SEVERITY column in report TSV output
- `control_severity` and `control_compliance` fields in evaluation findings output

### Changed
- **Breaking:** Removed `--out` flag from `apply`, `check`, `verify`, `ci diff`,
  `ci baseline check`, `report`, `ci gate`, `snapshot diff`, `snapshot upcoming`,
  and `snapshot status`/`snapshot risk` (formerly `snapshot hygiene`). Use shell redirection (`> file`) instead. Commands that
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
- CLI commands: validate, apply, diagnose, ingest --profile aws-s3, apply --profile aws-s3, verify, enforce, report, counterfactual, capabilities, alias, trace
- `--template` flag on apply, diagnose, and validate for custom output formatting
- Command alias system (`stave alias set|list|delete`) with user config storage
- JSON and text output formats
- Observation schema (obs.v0.1) and control DSL (ctrl.v1)
- Terraform plan extraction for S3 assets
- Golden-file E2E test framework with 95+ test cases
- OpenSSF Scorecard, signed releases, SLSA provenance, SBOM
