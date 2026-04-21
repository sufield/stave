# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Triage separation: `_triage/` directory with family templates and
  per-control overrides.** Security definitions (predicate,
  classification, severity) and troubleshooting context (defect,
  infection, failure) now live in separate files. 121 per-control
  overrides extracted from control YAMLs into
  `controls/_triage/overrides/`. 47 family-level templates authored
  in `controls/_triage/families/`, providing infection/failure prose
  for every control family. Engine joins both trees at runtime with
  per-field inheritance: override > family template > empty. Coverage:
  121 controls have full per-control triage (override); remaining
  554 inherit family-level infection/failure. The `_triage/` directory
  is `_`-prefixed so the control scanner skips it during YAML
  discovery.
- **Defect/infection/failure metadata on 40 IAM controls** —
  CRED (7), TRUST (6), ROLE (6), IDENTITY (6), ROOT (5), SCP (4),
  PASSWORD (4), ZT (2) sub-families authored. Covers credential
  lifecycle (rotation, expiry, dormancy, recurrence), trust policy
  hardening (confused deputy, OIDC scoping, source-ARN conditions,
  external ID), role hygiene (category mixing, intent tags, permission
  drift, break-glass TTL), blast radius analysis (resource threshold,
  cross-account, chain depth, sensitive resource concentration), root
  account hardening (MFA, access keys, usage), SCP guardrails
  (dangerous allows, OU coverage, identity creation), password policy,
  and zero trust principles. 0 flagged as ambiguous. 1 golden updated
  (e2e-hipaa-cross-domain, additive only — ROOT controls). Total
  authored: 121 of 675 controls (17.9%). Remaining IAM: 20 controls
  across smaller sub-families. Next iteration: complete remaining IAM
  (20 controls) then pivot to K8S (64 controls).
- **Defect/infection/failure metadata on 38 IAM controls** —
  IAM.ESCALATE (22) and IAM.POLICY (16) sub-families authored. Covers
  all Rhino Security Labs privilege-escalation techniques (PassRole
  chains, self-modification, credential manipulation, trust policy
  rewriting, group-hop escalation), plus policy hygiene controls
  (admin wildcard, NotAction shadow logic, separation of duties,
  ghost references, inline policies, MFA enforcement). 0 controls
  flagged as ambiguous. 0 goldens updated (IAM controls not exercised
  by existing fixtures). Total authored: 81 of 675 controls (12.0%).
  Next iteration: remaining IAM sub-families (62 controls) or pivot
  to K8S (64 controls).
- **Defect/infection/failure metadata on all 29 CTL.EC2 controls** —
  complete EC2 family authored in one iteration. Each control now carries
  `defect`, `infection`, and `failure` prose enabling adopters to triage
  findings without external reference. Covers: encryption (EBS volumes,
  snapshots, Nitro Enclaves), network exposure (public IPs, IMDSv2,
  security groups, VPC endpoints, subnets, default VPC), identity
  (instance profiles, IAM roles, user-data credentials), audit (detailed
  monitoring, SSM session logging), governance (launch templates, SSM
  management), resilience (ASG health checks, termination protection),
  and version currency (AMI age). Total authored: 43 of 675 controls
  (14 S3 + IAM + Lambda prior + 29 EC2 this iteration). No case
  programs affected (none exercise EC2 controls). 1 golden file updated
  (e2e-hipaa-cross-domain, additive only). Next iteration: IAM
  sub-families (ESCALATE + POLICY, ~38 controls).
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
