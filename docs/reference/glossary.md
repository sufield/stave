# Glossary

Terms specific to Stave or used differently from industry convention.

---

**Assessment**
The output of running `stave apply` against a snapshot. Contains findings, chain activations, posture score, and evidence metadata. Distinct from a [snapshot](#snapshot) (the input) and a report (the aggregated executive output). Schema: `out.v0.1`.

**Asset**
A single configurable infrastructure resource with an identifier, type, vendor, and properties map. The unit of evaluation. An observation snapshot contains N assets. Equivalent to a "resource" in AWS terminology, a "node" in Kubernetes, or a "managed object" in vSphere.

**Attack Stage**
A MITRE ATT&CK tactic mapped to a [control](#control) via the `attack_stage` parameter. Determines which tactic the control detects conditions for. Valid values: `initial_access`, `execution`, `credential_access`, `persistence`, `privilege_escalation`, `lateral_movement`, `discovery`, `collection`, `exfiltration`, `detection_evasion`, `impact`, `resilience`. See [attack-stages.md](attack-stages.md).

**Blast Radius**
The count of downstream assets reachable from a compromised asset via the infrastructure graph. Used by `stave rank` as a priority multiplier. A finding with blast radius 47 means 47 other assets could be affected if the violating asset is compromised.

**Capability**
A string from the closed vocabulary used in chain `preconditions:` and `postconditions:` fields. Enables `stave path` to derive attack path edges between chains. Examples: `internet_access`, `iam_credential_theft`, `rds_data_access`. See [capability-vocabulary.md](capability-vocabulary.md).

**CEL Predicate**
A Common Expression Language expression in a control's `unsafe_predicate:` field, compiled and evaluated against an asset's properties map. Returns unsafe=true ([VIOLATION](#verdict)), unsafe=false ([PASS](#verdict)), or an error ([INCONCLUSIVE](#verdict)). See [cel-predicates.md](cel-predicates.md).

**Chain**
A compound risk definition (YAML file in `chains/`) that activates when multiple controls fail simultaneously. Chains express multi-hop attack paths that individual controls cannot capture. Each chain has an `escalation_threshold` — the minimum number of member controls that must fail for activation. See [compound-chains.md](../explanation/compound-chains.md).

**Control**
A YAML file (schema `ctrl.v1`) defining a single [System Invariant](#system-invariant): a property of an asset type that must always be true. The unit of the control catalog. Each control has an ID (e.g., `CTL.S3.PUBLIC.001`), a severity, an `unsafe_predicate`, and optional compliance citations.

**Finding**
A specific control violation on a specific asset at a specific time. Carries: control ID, asset ID, verdict, severity, dwell time, blast radius, SLA status, and compliance citations. The primary unit of assessment output.

**History Directory**
A directory of assessment JSON files, one per run. The input to `stave trend`, `stave score`, `stave budget`, `stave bisect`, `stave forensics`, and `stave monitor`.

**INCONCLUSIVE**
A [verdict](#verdict) produced when a control cannot evaluate an asset because a required property is absent from the observation or a CEL runtime error occurred. Distinct from PASS (property present and satisfies the invariant) and VIOLATION (property present and violates the invariant). INCONCLUSIVE preserves the SLA clock without changing exposure state.

**System Invariant**
A property of deployed infrastructure that must hold across all observable states. Not a code-level invariant (Dijkstra, Hoare logic) — a System Invariant describes a property of infrastructure configuration, not program execution. Example: "PHI data must be private and encrypted" must hold in every account, every region, at every point in time. The absence of a violation is positive evidence that the System Invariant holds. The conceptual foundation of the control catalog. See [system-invariants.md](../explanation/system-invariants.md).

**Observation**
A single asset's configuration properties at a specific point in time. The atomic unit of a [snapshot](#snapshot). Contains the asset's ID, type, vendor, and a `properties` map of arbitrary depth.

**Observation Contract**
The schema defining what properties are available for each asset type. Controls reference properties via dot notation in predicates. Extractors must emit conforming JSON. Documented per service in `docs/contracts/`. See [contract/README.md](../explanation/contract/README.md).

**Posture Score**
A 0-100 composite metric computed from four weighted dimensions: severity distribution (45%), SLA compliance (25%), chain activity (20%), and coverage (10%). See [posture-score.md](../explanation/posture-score.md).

**Profile**
A named set of controls representing a compliance framework or organizational policy. Built-in profiles include `hipaa`, `fedramp`, `soc2`, `pci-dss-v4.0`, `cis-aws-v3.0`. Custom profiles are YAML files loaded with `--profile-file`. Domain profiles like `aws-s3` and `aws-efs` scope evaluation to a single service.

**Recurrence**
A pattern where a control violation appears, resolves, and reappears on the same asset. Measured by `stave forensics` and expressed as a recurrence score 0-10. High recurrence indicates either attacker activity or deployment-introduced regression.

**Snapshot**
A JSON file (schema `obs.v0.1`) containing an array of asset observations captured at a specific point in time. The input to `stave apply`. Snapshots are files — they go in git. This is the foundation of time travel evaluation.

**Vendor**
The infrastructure provider for an asset. Examples: `aws`, `kubernetes`, `microsoft`, `vmware`, `cisco`. Used by controls via `scope_tags` to scope evaluation to the correct asset type.

**Verdict**
The outcome of evaluating a control against an asset. One of: **PASS** (asset satisfies the invariant), **VIOLATION** (asset violates the invariant), or **INCONCLUSIVE** (evaluation could not complete).
