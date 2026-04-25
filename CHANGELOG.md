# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **VPC-7 — load balancer ghost references, DNS firewall, and
  Network ACL controls (9 controls, 3 chains).** Combines three
  smaller gap clusters from categories 2 (NACLs), 8 (DNS), and
  9 (ELB). ELB ghost family: `TARGET.GHOST` (deregistered or
  terminated targets remain registered, medium), `LISTENER.GHOST`
  (listener rule forwards to a deleted target group — silent
  502/503, high), `CERT.GHOST` (expired or deleted ACM cert on
  HTTPS listener — public TLS failure, high), `SG.GHOST` (LB
  references a deleted security group — inconsistent firewall
  state, high). DNS firewall: `DNSFIREWALL.ENABLED` (no Route53
  Resolver DNS Firewall rule group on VPC, medium),
  `DNSFIREWALL.MANAGEDLISTS` (DNS Firewall present but no AWS
  managed threat-intel lists, medium). NACL: `DEFAULT.INUSE`
  (subnet uses default allow-all NACL — no subnet-level
  defense-in-depth, medium), `RULE.ORDER` (deny rules ordered
  after matching allow rules — never evaluate, medium),
  `UNRESTRICTED` (custom NACL allows all traffic — defense-in-
  depth theater, medium). Chains: `elb_ghost_cascade`
  (multiple LB ghost references — systematic decommissioning
  failure), `vpc_dns_exfiltration` (no DNS firewall + unrestricted
  DNS egress or no flow logs), `vpc_nacl_false_confidence`
  (ineffective deny rules OR allow-all custom NACL — appears
  filtered, isn't). 20 e2e fixtures (18 base + 2 worst-case
  variants: target-ghost-total with every target a ghost and
  cert-ghost-deleted distinguished from merely expired).
  9 triage overrides. Docs and README regenerated (1378 controls).
- **VPC-6 — flow log deepening and VPC endpoint coverage (9 controls,
  3 chains).** Closes the category-7 flow-log cluster and the
  category-6 endpoint cluster. Prompt spec asked for 10 controls;
  `MISSING.S3` was a duplicate of the existing
  `CTL.VPC.ENDPOINT.S3.001`, so shipped 9. Flow-log additions:
  `SUBNET` (sensitive subnet with no coverage at either subnet or
  VPC scope, medium), `STATUS` (flow log configured but not ACTIVE —
  the "everything appears to work" pattern, high), `FORMAT` (default
  format omits pkt-srcaddr/tcp-flags/etc. needed for forensics,
  medium), `DESTINATION.SECURE` (public/unencrypted/deletable/low-
  retention destination, high, OR predicate across four dimensions),
  `BIDIRECTIONAL` (TrafficType is ACCEPT or REJECT only — half the
  record missing, medium). Endpoint additions:
  `MISSING.CRITICAL` (missing interface endpoint for one or more of
  KMS/Secrets Manager/STS/SSM/CloudWatch Logs/ECR, medium),
  `SG.BROAD` (endpoint SG permits full VPC CIDR rather than specific
  workload SGs, medium), `DNS` (Private DNS disabled — endpoint
  bypassed because standard service DNS routes to public IP, low).
  Chains: `vpc_flow_visibility_gap` (flow logs not active + partial
  capture or insecure destination), `vpc_endpoint_bypass` (no
  Private DNS + broad SG or anonymous policy), `vpc_private_subnet_leakage`
  (missing S3 gateway or critical interface endpoints + unrestricted
  egress). 18 e2e fixtures (16 base + 2 worst-case variants:
  status-deliver-error with ACTIVE status but ERROR delivery, and
  endpoint-many-missing with all six critical endpoints absent).
  8 triage overrides. Docs and README regenerated (1369 controls).
- **VPC-5 — AWS Network Firewall deepening (5 controls, 3 chains).**
  Closes the Network Firewall gap cluster in category 10. Prompt
  spec asked for 8 controls; three turned out to duplicate existing
  ones (`CTL.VPC.NETWORK.FIREWALL.001` covered ENABLED,
  `CTL.NETFIREWALL.MULTIAZ.001` covered SINGLEAZ, `CTL.NETFIREWALL.LOG.001`
  covered LOGGING), so shipped 5 distinct additions. New controls:
  `ROUTING` (firewall deployed but route tables bypass it — the
  "smoke detector not connected to power" pattern, critical),
  `RULES.STATEFUL` (no stateful rule groups — packet filter, not
  connection-aware firewall, high), `RULES.PERMISSIVE` (allow-any
  rule inside a rule group short-circuits inspection, high),
  `MODE` (stateful default is ALERT — detection without
  prevention, high), `TLS` (no TLS inspection — HTTPS content
  bypass, medium). Chains: `netfirewall_ineffective`
  (routing-bypass + alert-mode or no-logging — security theater),
  `netfirewall_content_blind` (no TLS + no stateful = blind to
  both content and context), `vpc_no_inspection` (no firewall +
  no flow logs or unrestricted egress). 12 e2e fixtures (10 base
  + two worst-case variants: routing-silent with configured-looking
  rules, mode-suricata with 1247 stateful rules still in alert).
  5 triage overrides. Docs and README regenerated (1361 controls).
- **VPC-4 — internet connectivity and subnet architecture controls
  (10 controls, 3 chains).** Closes the category-4 internet-connectivity
  gaps and subnet-architecture gaps from category 3. Covers the
  "public-by-default" failure mode (main route table with IGW route +
  subnet `MapPublicIpOnLaunch`) and the database-in-public-subnet
  pattern. New controls: `IGW.UNNECESSARY` (latent IGW attachment,
  medium), `NAT.SINGLEAZ` (single-AZ egress bottleneck, medium),
  `NAT.LOGGING` (egress choke-point unlogged, medium), `EIP.ORPHANED`
  (unassociated Elastic IP, low), `EIP.EXCESSIVE` (multiple EIPs on
  one instance, medium), `SUBNET.AUTOPUBLIC` (`MapPublicIpOnLaunch`
  subnet default, high), `SUBNET.PRIVATEDB` (database subnet has IGW
  route, high), `ROUTETABLE.MAIN.PUBLIC` (main route table has IGW
  route, high), `ROUTETABLE.ORPHANED` (unassociated route table,
  low), `DEFAULT.RESOURCES` (workloads in default VPC, high). Chains:
  `vpc_default_exposure` (resources in default VPC + auto-public-IP
  or default SG in use), `vpc_public_by_default` (main-RT IGW route +
  subnet auto-public), `vpc_database_exposure` (database in public
  subnet OR `CTL.RDS.PUBLIC.001`). 20 e2e fixtures, 10 triage
  overrides, docs and README regenerated (1356 controls).
- **VPC-3 — VPN, Client VPN, and Direct Connect controls (8 controls, 3
  chains).** Closes the hybrid-connectivity gap cluster in the VPC
  taxonomy. Site-to-site VPN: `ENCRYPTION.WEAK` (sub-AES-256 cipher
  suites, high), `TUNNEL.DOWN` (redundancy loss or connectivity outage,
  high), `PSK` (shared-secret peer authentication, medium), `LOGGING`
  (tunnel event log disabled, medium). Client VPN: `AUTH` (all-traffic
  allow with no authorization rules, high), `LOGGING` (connection log
  disabled, high), `SPLITTUNNEL` (client bridges VPC and internet,
  medium). Direct Connect: `ENCRYPTION` (no VPN overlay and no MACsec,
  high). Chains: `vpc_vpn_compromise` (weak cipher + no log or PSK),
  `vpc_clientvpn_exposure` (all-traffic + no log or split tunnel),
  `vpc_hybrid_unencrypted` (any unencrypted hybrid path). 18 e2e
  fixtures, 8 triage overrides, docs and README regenerated
  (1346 controls).
- **VPC-2 — peering and Transit Gateway controls (9 controls, 3 chains).**
  Closes the largest remaining cluster in the VPC taxonomy: cross-VPC
  connectivity. Peering coverage adds `CROSSACCOUNT` (peer outside the
  organization, high), `BIDIRECTIONAL` (return routes not required by the
  use case, medium), `PENDING` (stale pending-acceptance request, medium),
  and `DNS` (resolution disabled, low). Transit Gateway coverage adds
  `ROUTING.ALLTOALL` (segmentation collapse, high), `FLOWLOGS` (central
  hub unlogged, high), `PROPAGATION` (VPN/DX route injection risk,
  medium), `BLACKHOLE` (silent traffic loss, medium), and
  `ATTACHMENT.ISOLATED` (isolated VPC attached to a shared hub, medium).
  Chains: `vpc_peering_exposure` (cross-account peer + broad routing),
  `vpc_tgw_segmentation_failure` (all-to-all + unlogged or isolated
  attachment), `vpc_transit_ghost` (blackhole routes + endpoint ghost
  refs). Skipped `PEERING.ROUTING.BROAD` — duplicates the existing
  `CTL.VPC.PEERING.ROUTES.001` (same field, same check). 18 e2e fixtures,
  9 triage overrides, docs and README regenerated (1337 controls).
- **DELTA section on findings.** Mechanically derived fix paths computed
  from the predicate and observed values. Each DeltaPath shows the
  property label (from registry), current observed value, and the fix
  action (operator inversion). For AND predicates, independent fix paths
  shown with "any ONE eliminates this finding" header. Uses the same
  property registry as defect derivation. Coverage: 672/675 controls.
  Counterfactual verified: applying the delta's suggested change
  eliminates the finding. Renders in both text and JSON output.
- **Predicate-derived defect descriptions.** Controls without per-control
  defect overrides now get mechanically generated DEFECT text from their
  predicate tree. A property-path registry maps observation fields to
  domain-meaningful labels (150+ overrides, algorithmic fallback for the
  rest). Combined with operator-phrase mapping, the derivation produces
  accurate sentences like "EBS volume encryption is not enabled" or
  "S3 BlockPublicAcls setting is not enabled." Coverage: 672 of 675
  controls (99.6%) now have defect descriptions — 121 from per-control
  overrides, 551 from derivation, 3 not derivable (complex predicates).
  Per-control overrides still take precedence. Derivation runs in shared
  core, used by both CLI and library.
- **Family template inheritance verified end-to-end.** Targeted test
  (`TestApply_FamilyTemplateInheritance`) confirms 42 of 54 findings
  inherit family-level infection/failure from the builtin catalog, 12
  retain per-control overrides. Inheritance works through the embedded
  `_triage/` tree loaded by the builtin ControlStore. File-based loader
  applies triage when `_triage/` exists in the controls directory;
  self-contained fixtures without `_triage/` fall back to inline fields
  (backward compatible).
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
