# Compound Risk Detection Audit

**Date**: 2026-04-20

## Summary

Stave has **rich compound-detection machinery** and a
**deliberate design boundary around graph algorithms**.
A chain engine (`risk.DetectChains`) matches failing
control IDs against 70+ authored `ChainDefinition` YAML
files in `stave/chains/`, emits top-level
`CompoundFinding` records with narrative/severity/attack-
stage, and annotates per-finding `ChainMembership` back
— bidirectional linkage that survives native CLI output
(`out.v0.1`). A `stave path` command exports graph data
(nodes + edges) in JSON/DOT/CSV-edges formats for
external graph-analysis tools.

Path-finding, centrality, and choke-point computation
are **explicitly out of Stave's scope by design**
(`docs/explanation/compound-chains.md:31`,
`cmd/path/cmd.go:43-45`): "This is not a graph
algorithm — it is a double loop over active chains
performing set intersection. The graph structure is
data, not computation. External tools (NetworkX, Neo4j)
perform path finding, centrality analysis, and
visualization." Stave produces graph data; external
tools compute paths and centrality.

The only existing centrality-like metric is `ChainBonus`
(`internal/core/evaluation/risk/exposure_rank.go:49-58`):
findings participating in 2+ chains get a 2.0×
ExposureScore multiplier, 1-chain get 1.5×, 0-chain get
1.0×. This is per-finding weighting along the
finding→chain bipartite dimension, not full graph
centrality.

**The compound surface is invisible at the `pkg/stave`
library boundary.** `pkg/stave.Assessment` has no
`ChainFindings` field; `pkg/stave.Finding` deliberately
omits `ChainMembership` (`pkg/stave/finding.go:9-13`);
`pkg/stave.Apply` passes no `ChainDefs` to the workflow
so `DetectChains` never runs on the library path. All
18 case programs in `stave-hackerone-tests` see
Assessments with zero compound information.

## Part 1: Individual control detection

### 1. Evaluation path from observation to Finding

1. **Observation load**:
   `internal/adapters/observations/loader_core.go:66-107`'s
   `LoadSnapshots` reads each `.json` file in
   `SnapshotsDir` into an `asset.Snapshot`.
2. **Predicate evaluation**:
   `internal/core/evaluation/engine/finding_builder.go:35`
   evaluates the control's `UnsafePredicate` against the
   snapshot. Predicates are `any:`/`all:` trees of
   `field + op + value` leaves
   (`internal/adapters/controls/yaml/dto.go:42-57`).
   CEL-based evaluator (`internal/cel/`).
3. **Misconfiguration emission**: matched leaves become
   `policy.Misconfiguration` records.
4. **Finding construction**:
   `finding_builder.go:27` calls
   `evaluation.ReasoningTraceFromMisconfigurations`
   (`internal/core/evaluation/finding.go:90-108`) to
   convert matched leaves into `[]MatchedClause`.
5. **FindingID**: `StableFindingID(ctl.ID, t.ID)` — a
   SHA256 over `(ControlID, AssetID)`.

**One-control, one-asset, one-finding** at this layer.

### 2. Cross-asset / cross-observation controls

**Predicates do not traverse relationships between
assets.** The `field:` selector targets one asset's
`properties` tree; no selector syntax references another
asset.

**Apparent cross-asset reasoning is collector-side field
derivation.** `CTL.LAMBDA.ROLE.LEASTPRIV.001` gates on
`compute.execution_role.is_overprivileged` — the
boolean is pre-computed by the collection tool joining
the Lambda's execution-role ARN to the IAM role's
policy evaluation. Engine reads one field on one asset.
Same for `CTL.IAM.NEP.ESCALATION.001` (gates on
`identity.nep.has_escalation_path`) and
`CTL.IAM.NEP.ADMIN.001` (`identity.nep.is_admin`).
Graph walking is **collector responsibility** per
`docs/contract/README.md:207-217`.

**Temporal evaluation across snapshots exists but is
scalar per-asset.** `type: unsafe_duration` controls
consult multiple snapshots to compute "how long has
this asset been unsafe." No cross-asset temporal
reasoning.

## Part 2: Issue consolidation

### 3. Consolidation mechanics

`evaluation.BuildIssues`
(`internal/core/evaluation/issue.go:160-185`):

1. Partitions findings by `AssetID`
   (`issue.go:167-169`).
2. For each asset, runs pairwise union-find
   (`issue.go:188-220`) on reasoning-trace observation
   keys. Overlap test at `issue.go:222-233`.
3. `rootCauseKeys` (`issue.go:95-108`) projects each
   `MatchedClause.ObservationKey` into a dedup-key
   set, excluding discriminator keys
   (`issue.go:76-83`) and including parent namespaces
   with ≥2 segments.
4. Each cluster → `Issue` with `MemberFindingIDs`,
   `HeadlineFindingID`, `SharedKeys`.

**Signal**: shared observation-field consumption.

### 4. Is consolidation compound reasoning?

**No — surface-grouping, not causal-chain detection.**

1. **Asset-bounded**: partition by `AssetID` precedes
   clustering (`issue.go:167-169`). No Issue ever
   crosses assets.
2. **Key-surface-driven**: overlap check
   (`issue.go:222-233`) reads whether two findings
   consult overlapping fields, not whether one caused
   another.
3. **Issue metadata is shape, not causality**
   (`issue.go:24-65`): `IssueID`, `AssetID`,
   `SharedKeys`, `MemberFindingIDs`,
   `HeadlineFindingID`, `ConsolidatedScore`,
   `ConsolidatedBlastRadius`. No chain ID, no
   narrative, no attack-stage, no causal ordering.

Design comment at `issue.go:14-23` uses "root-cause
signal" but implements surface-intersection. An Issue
says "these findings look at overlapping asset state,"
not "these findings participate in one attack path."

## Part 3: Cross-finding compound detection

### 5. Compound mechanisms that span findings

**Chain engine**:
`internal/core/evaluation/risk/chain_engine.go:31-99`'s
`DetectChains`.

Inputs: `failingIDs map[kernel.ControlID]bool`,
`chains []policy.ChainDefinition`, `controlLookup`.

Output: `[]risk.CompoundFinding` — one per chain whose
failing-member count meets `EscalationThreshold`.

Each `CompoundFinding` (`chain_engine.go:13-22`)
carries: `ChainID`, `Description`, `ControlsFailing`,
`MissingSafeguards` (chain members that did NOT fire),
`CompoundScore`, `Severity`, `Narrative`,
`AttackStages`.

**Chain catalog**: 70+ YAML files at
`stave/chains/*.yaml` covering
`privilege_escalation_path`, `lateral_movement_path`,
`data_exfiltration_path`, `lambda_total_compromise`,
`supply_chain_code_injection`, K8s, networking,
supply chain, and more.

**Related compound views**:

- `AttackStageSummary` at
  `internal/app/eval/workflow.go:183`:
  `risk.BuildAttackStageSummary(failingIDs, controlLookup)`
  — aggregates per-finding attack stages.
- `Finding.PostureDrift`
  (`evaluation/finding.go:32`): newly-unsafe vs. prior
  snapshot.
- `Finding.Reachability`
  (`evaluation/finding.go:55-56`): IAM reachability
  from pre-computed collection data.

**Chain evaluation entry point**
(`internal/app/eval/workflow.go:177-180`):

```go
if len(chainDefs) > 0 {
    report.ChainFindings = risk.DetectChains(failingIDs, chainDefs, controlLookup)
    annotateChainMembership(report)
}
```

Guarded on non-empty `chainDefs`. CLI loads them
(`cmd/apply/deps.go:118` does
`ctlyaml.LoadChains("chains")`); library path does
not — see Part 6.

### 6. Form of compound output

**Top-level `ComplianceReport.ChainFindings`**
(`internal/core/evaluation/audit.go:255`):

```go
ChainFindings []risk.CompoundFinding `json:"chain_findings,omitempty"`
```

Distinct from per-control `Findings`.

**Per-finding `evaluation.Finding.ChainMembership`**
(`internal/core/evaluation/finding.go:38-40`):

```go
ChainMembership []ChainMembershipEntry `json:"chain_membership,omitempty"`
```

Each entry (`finding.go:161-180`) carries `ChainID`,
chain severity, attack-stage span, narrative.

**Bidirectional linkage verified** (prior audit at
`docs/design-notes/compound-risk-output-audit.md:36-40`,
fixture
`testdata/e2e/graph-ontology/experiment-02-active-chain/`).
Wiring at `workflow.go:227-265`
(`annotateChainMembership`).

## Part 4: CloudFront case analysis

### 7. How Stave represents the cloudfront-2805173 chain today

**It doesn't.** Running the case (`stave-hackerone-tests/cmd/aws-cloudfront-2805173`)
produces 9 findings across 8 Issues with zero chain
output.

**(a) Library-path elides chain detection.**
`pkg/stave.Apply` at `pkg/stave/apply.go:80-132`
builds `appeval.AssessmentConfig` without
`WithChainDefs(...)`. `workflow.go:177`'s guard skips
`DetectChains`.

**(b) No authored chain matches this fixture's control
set anyway.** Cloudfront fires
`CTL.LAMBDA.ROLE.LEASTPRIV.001` (×6),
`CTL.IAM.NEP.ESCALATION.001` (×2),
`CTL.IAM.NEP.ADMIN.001` (×1). Of 70+ chains:

- `privilege_escalation_path.yaml` uses
  `CTL.IAM.ESCALATE.CHAIN.001`,
  `CTL.IAM.POLICY.ESCALATION.001`,
  `CTL.IAM.POLICY.PASSROLE.001`,
  `CTL.IAM.POLICY.SOD.001` — none of the fired
  controls.
- `lambda_total_compromise.yaml` uses
  `CTL.LAMBDA.URL.AUTH.001`,
  `CTL.LAMBDA.ROLE.LEASTPRIV.001`,
  `CTL.LAMBDA.ENV.SECRETS.001`. Only LEASTPRIV fires
  → `escalation_threshold: 2` not met.
- `lambda_shadow_admin.yaml` uses
  `CTL.LAMBDA.PASSROLE.001`,
  `CTL.LAMBDA.UPDATECODE.SCOPE.001` — neither fires.

Cloudfront's `expected.out.json` has no
`chain_findings[]` and no `chain_membership[]`. Each
`score_breakdown.chain_bonus: 1` is the default
multiplier — chain scoring ran, nothing matched.

The H1 report IS a privilege-escalation chain class.
Stave's NEP family resolves the escalation graph
inside the collector and exposes a per-role boolean;
the catalog's escalation chain expects the decomposed
`CTL.IAM.POLICY.*` family.

### Representation if the chain were made explicit

Two independent changes:

**(i) Catalog-level**: author a chain including
`CTL.IAM.NEP.ESCALATION.001` +
`CTL.LAMBDA.ROLE.LEASTPRIV.001` with
`escalation_threshold: 2`. Or re-author
`privilege_escalation_path.yaml` to reference NEP. Once
matched, CLI output gains `chain_findings[]` + each
member gets `chain_membership[]`.

**(ii) Library-surface**: expose `ChainFindings` on
`pkg/stave.Assessment`, `ChainMembership` on
`pkg/stave.Finding`, thread `ChainDefs` through
`pkg/stave.Apply`. Without this, library-path adopters
still see no chain output even after (i).

Neither is in the per-finding metadata iteration's
scope.

## Part 5: Engine architecture

### 8. Graph / relationship / pathfinding structures

**Chain engine**: set-matching against authored graph
templates (`chain_engine.go:31-99`). Given "failing
set" + "chain template," check intersection size
against threshold. Declared at
`docs/explanation/compound-chains.md:31` as "not a
graph algorithm."

**AttackStageSummary** (`workflow.go:183`): aggregation
across per-finding attack stages.

**Graph data builder**: `internal/graph/builder.go`
constructs `GraphData { Nodes, Edges }`
(`builder.go:14-22`) for the `stave path` command. 8
node types (Finding, Resource, Control,
ComplianceRequirement, TenantScope, RemediationAction,
ThreatChain, AttackerCapability) and 6 edge types
(TARGETS, MAPS_TO, VIOLATES, BELONGS_TO_SCOPE,
PRODUCES, MEMBER_OF). Constructed **after evaluation**
from existing `ComplianceReport + ChainFindings +
control metadata`. Rendering transform, not evaluation
mechanism.

**Reachability**: `Finding.Reachability`
(`finding.go:55-56`) carries pre-computed IAM
reachability facts. Populated by collection pipeline's
IAM walker, not computed in the evaluation engine.

**Relationship maps at evaluation time**: none. Engine
evaluates one asset's predicate at a time. Collection
tool does graph work; engine evaluates pre-computed
derived booleans.

### 9. Design intent

**Compound detection is first-class and deliberate**:

- 70+ authored chain YAML files.
- Closed vocabulary of 19 `ValidCapabilities`
  (`controldef/chain.go:53-73`):
  `iam_credential_theft`, `k8s_cluster_admin`,
  `ec2_code_execution`, `data_destruction`, etc.
  Chains' preconditions/postconditions must validate
  against this closed set (`chain.go:39-48`).
- `CompoundFinding` and `ChainMembership` are
  full-featured (narrative, severity, attack-stage,
  blast-radius).
- `ScoreBreakdown.ChainBonus` propagates chain
  membership into priority scoring.

**Design boundary on algorithms is equally
deliberate**:

- `docs/explanation/compound-chains.md:31`: "This is
  not a graph algorithm — it is a double loop over
  active chains performing set intersection. The graph
  structure is data, not computation. External tools
  (NetworkX, Neo4j) perform path finding, centrality
  analysis, and visualization."
- `cmd/path/cmd.go:43-45`: "An external program
  performs path finding — BFS, DFS, shortest path,
  centrality analysis, or any other graph algorithm.
  Stave does not implement graph algorithms."

The design is **compound-aware, algorithm-minimal**:
Stave detects compound patterns via set intersection,
emits graph-data in standard formats, and delegates
algorithmic analysis to specialized tools.

## Part 6: Output structure

### 10. Fields on Assessment / Finding / Issue

**Internal types carry compound data in full**:

- `internal/core/evaluation/audit.go:255` —
  `ComplianceReport.ChainFindings []risk.CompoundFinding`.
- `internal/core/evaluation/finding.go:38-40` —
  `Finding.ChainMembership []ChainMembershipEntry`.
- `internal/core/evaluation/finding.go:66` —
  `Finding.ScoreBreakdown.ChainBonus float64`.
- `internal/core/evaluation/finding.go:55-56` —
  `Finding.Reachability *ReachabilityContext`.
- `internal/core/evaluation/audit.go:261-263` —
  `ComplianceReport.AttackStageSummary`,
  `ComplianceReport.ControlsFailing`.

**Library types (`pkg/stave`) carry none of it**:

- `pkg/stave/assessment.go:13-42` — `Assessment` has
  `SchemaVersion`, `Status`, `Run`, `Summary`,
  `Findings`, `Issues`, `Coverage`. No
  `ChainFindings`, no `AttackStageSummary`.
- `pkg/stave/finding.go:14-78` — `Finding` has 14
  fields (including 2026-04-20 additions `Defect`,
  `Infection`, `Failure`). Comment at
  `pkg/stave/finding.go:9-13`: "Fields that are
  CLI-adapter-specific ... **chain membership
  annotations**, reachability context ... are
  omitted. Add them here when a consumer demonstrates
  a concrete need."
- `pkg/stave/issue.go:13` — `Issue = evaluation.Issue`
  alias. No chain reference.

**Library-path chain engine skip**:
`pkg/stave/apply.go:100-132` constructs
`appeval.AssessmentConfig` without `WithChainDefs(...)`.
`workflow.go:177` guard short-circuits `DetectChains`.
Chain engine **never runs** on the library path.

**Observed behavior verification**: ran
cloudfront-2805173: 9 findings, 8 Issues, no chain
output. Cross-referenced `expected.out.json`: no
`chain_findings[]`, no `chain_membership[]`.

## Part 7: Graph and path computation

### 11. Graph structure built during evaluation

**Stave builds graph data on-demand via `stave path`,
not during `stave apply`.** Call path:

1. `stave apply` emits `ComplianceReport` with
   `Findings` and `ChainFindings`. No graph
   constructed.
2. `stave path --output <assessment.json>`
   (`cmd/path/cmd.go`) reads the assessment JSON and
   calls `graph.Build` (`internal/graph/builder.go:65`).
3. `graph.Build` produces `GraphData { Nodes, Edges }`
   by walking findings and chain findings. Output
   format: JSON (default), DOT (Graphviz), CSV-edges
   (for NetworkX/pandas).

**Node types** (`builder.go:79-214`): Finding,
Resource, Control, ComplianceRequirement, TenantScope,
RemediationAction, ThreatChain, AttackerCapability.

**Edge types** (`builder.go:138-279`): TARGETS
(Finding → Resource), MAPS_TO (Control →
ComplianceRequirement), VIOLATES (Finding →
ComplianceRequirement), BELONGS_TO_SCOPE (Resource →
TenantScope), PRODUCES (ThreatChain →
AttackerCapability), MEMBER_OF (Finding →
ThreatChain).

**Chain-to-chain edges** (postcondition matches
precondition): computed by
`internal/app/attackpath/` (referenced at
`cmd/path/cmd.go:16`) via set intersection on the
capability vocabulary. The "double loop over active
chains" described in
`docs/explanation/compound-chains.md:31`.

### 12. Path computation — does it exist

**No.** Every reference in code and docs consistently
says path computation is outside Stave's scope:

- `docs/explanation/compound-chains.md:31`: "This is
  not a graph algorithm — it is a double loop over
  active chains performing set intersection."
- `cmd/path/cmd.go:43-45`: "An external program
  performs path finding — BFS, DFS, shortest path,
  centrality analysis, or any other graph algorithm.
  Stave does not implement graph algorithms."
- Examples at `cmd/path/cmd.go:60-67` demonstrate
  the expected workflow: `stave path ... >
  attack-graph.json` → NetworkX / Graphviz / Neo4j.

**No BFS, DFS, shortest-path, or reachability
computation over the graph exists**. Grep for
`centrality`, `betweenness`, `fan_in`, `fan_out`,
`path_count`, `shortestPath`, `choke` across
non-test, non-doc Go returns zero functional hits.

Design boundary is architectural: Stave's
responsibility ends at "produce correct, structured
graph data." Graph analysis is external-tool
responsibility.

### 13. Work to expose paths

**If the design boundary were revised to include path
computation**: substantial work.

- Go graph library (`gonum.org/v1/gonum/graph` has
  BFS/DFS/centrality) or hand-rolled BFS.
- Path-enumeration policy: simple paths, shortest
  paths to goal nodes (e.g., any `AttackerCapability`),
  cutoff depth.
- Output-surface decisions: new format in `stave
  path`? New command? New fields on `CompoundFinding`?
- Scale handling: path enumeration is exponential.

**If the goal is surfacing the existing graph to Go
library consumers (not computing paths)**: small
change. Expose `ChainFindings` on
`pkg/stave.Assessment` and `ChainMembership` on
`pkg/stave.Finding`. Data is already produced in
internal types; the gap is the trimming at the
library boundary (Part 6).

## Part 8: Choke-point identification

### 14. Centrality-like ranking today

**One proto-centrality metric exists**:
`risk.ChainBonus`
(`internal/core/evaluation/risk/exposure_rank.go:49-58`):

```go
func ChainBonus(chainCount int) float64 {
    switch {
    case chainCount >= 2:
        return 2.0
    case chainCount == 1:
        return 1.5
    default:
        return 1.0
    }
}
```

Findings on 2+ fired chains get 2.0× ExposureScore,
1-chain get 1.5×, 0-chain get 1.0×. **Chain-
membership counting, not full graph centrality.** It
weights findings-that-enable-multiple-chains higher —
a weak choke-point signal on the finding→chain
bipartite dimension. Surfaced per-finding via
`ScoreBreakdown.ChainBonus`
(`risk/exposure_rank.go:19-32`).

**No other centrality/path-count signal exists**.
Neither:
- Count of Issues a finding is in (always 1 — per-
  asset clusters).
- Count of Resources a finding targets (always 1 —
  per-(control, asset)).
- Out/in degree per node in graph export.
- Betweenness over the chain→capability graph
  (`cmd/path/` CSV-edges format assumes consumer
  computes this).

### 15. Existing structures that could hold choke-point data

**Finding-level**: `ScoreBreakdown` already has
`ChainBonus`. Adding `PathCentrality float64` or
`ChokePointRank int` is mechanical. `pkg/stave.Finding`
doesn't currently expose `ScoreBreakdown` (same
trimming policy as ChainMembership); surfacing it is
a separate change.

**Issue-level**: no existing field. Adding one would
work syntactically but conflicts with the per-asset-
surface design of Issues (Part 2). Choke points are
cross-asset; Issues aren't.

**Top-level `ComplianceReport`**: no centrality
summary today. A `ComplianceReport.ChokePoints
[]ChokePointRank` field could land here — top-N
findings/nodes by a chosen metric. New field, not a
retrofit.

**Graph-export-level**: `GraphData.Metadata`
(`builder.go:32-37`) carries `NodeCount`,
`EdgeCount`, `NodeTypes`, `EdgeTypes`. Could host
centrality rankings per node — but that contradicts
the "external tools do analysis" boundary.

### 16. Plausible metrics for choke-point identification

- **ChainMembership count per finding** — already
  powered by `ChainBonus`. A finding on N chains is N×
  "central" to the compound detection surface.
- **Severity-weighted chain count** —
  `ChainMembershipEntry.ChainSeverity` is per-chain;
  summing or max-ing gives severity-weighted score.
- **Blast-radius-weighted** — `risk.scopeAdjustedBlast`
  (`chain_engine.go:62`) computes blast multiplier per
  control from `blast_scope` (account/network/resource).
  Centrality weighted by blast multiplier ranks wider-
  blast positions higher.
- **Path-through count (true betweenness)** — requires
  path enumeration (Part 7.13). Out of scope without
  algorithm work.
- **Fan-out in capability DAG** — a chain whose
  postconditions unlock many other chains'
  preconditions is a chain-level choke point.
  Computable from chain YAML alone.
  `internal/app/attackpath/` may already compute
  this; not verified in this audit.

**Existing weighting the engine already does**:

- `ExposureScore` (`risk/exposure_rank.go:68-82`)'s
  `DurationFactor`: weights by how long unsafe.
- `SeverityToWeight` (`exposure_rank.go:86-99`):
  severity → base score.
- `exposureMultiplier`
  (`exposure_rank.go:103-109`): public-internet
  adjustment.
- `ChainBonus` (already covered).

Per-finding score composition already reflects several
axes. A choke-point view would compose these with
cross-finding graph-structure data — the missing
piece.

## Implications for next iteration

The audit reveals three facts that jointly constrain
the next iteration's scope:

### What Stave already has

1. **Compound detection is complete and shipped** —
   70+ chain definitions, `DetectChains` engine,
   `CompoundFinding` + `ChainMembership` types,
   bidirectional linkage, `stave path` export command
   producing NetworkX/Graphviz/Neo4j-consumable graph
   data. The compound pipeline is not missing; it's
   built.
2. **A form of choke-point weighting exists**:
   `ChainBonus` weights per-finding scores by chain-
   membership count (1.0× / 1.5× / 2.0×). Per-finding
   `ExposureScore` is already choke-point-aware on
   this one axis.
3. **The library boundary is the biggest gap** —
   `pkg/stave` exposes zero compound data. Every
   case program in `stave-hackerone-tests` sees
   Assessments that look like Stave doesn't detect
   compound at all. Gap is deliberate trimming
   (`pkg/stave/finding.go:9-13`) plus omitted
   `ChainDefs` threading in `pkg/stave.Apply`.

### What's deliberately out of scope

- **Path-finding, centrality, betweenness, BFS/DFS,
  shortest-path** — architecturally delegated to
  external tools
  (`docs/explanation/compound-chains.md:31`,
  `cmd/path/cmd.go:43-45`). Building them internally
  contradicts the shipped design choice. Reversing
  that choice is a standalone strategic decision, not
  an incremental feature.

### Candidate iterations

**Candidate A: Per-finding defect/infection/failure
metadata cascade** (Zeller-style local reasoning).
The 2026-04-20 iteration shipped this on 3 controls.
Scaling to 675+ is mechanical-but-substantial.
Improves every finding's context; does NOT address
the compound-view gap; per-finding prose stays
per-finding. Adopter value: better linear triage.
Does not change triage ordering or reduce finding
count.

**Candidate B: Compound-chain surfacing on
`pkg/stave`**. Add `ChainFindings` to
`pkg/stave.Assessment`, `ChainMembership` to
`pkg/stave.Finding`, thread `ChainDefs` through
`pkg/stave.Apply`. Engineering: small (trim policy
reversal + one plumbing change). Chain detection
already runs on the CLI path.

- Adopter value: library-using adopters (all 18 case
  programs, bucket-intent, stave-explorer) gain
  visibility into the compound structure Stave
  already computes. They see *which findings are on
  chains and how severe those chains are*. Real
  triage-time reduction: adopters iterate
  `findings where len(ChainMembership) > 0` to find
  chain-members. With `ChainBonus` already in
  `ExposureScore`, the natural sort order already
  surfaces these findings first once visible.
- Secondary benefit: case programs become the
  evidence surface for the chain engine. CloudFront's
  missing-chain catalog gap (Part 4) becomes visible
  and drives the next catalog iteration as a side
  effect.

**Candidate C: Choke-point ranking (centrality
computation)**. Requires reversing the explicit
"Stave doesn't implement graph algorithms" design
boundary. Needs a graph library, metric choice
(betweenness vs. degree-centrality vs. severity-
weighted chain-count), output surface decisions, and
scale work. `ChainBonus` is already degree-centrality-
in-the-chain-dimension; other dimensions need
algorithms Stave explicitly declines.

- Adopter value: "fix these three to eliminate 80%
  of compound risk" — high-leverage triage. But
  reverses a shipped design boundary. Not
  incremental.
- Today's workaround: adopters use `stave path`
  with NetworkX/Graphviz. Real path for operators
  willing to adopt the tooling, not theoretical.

**Candidate D: Graph construction from scratch**.
Not applicable. Graph exists
(`internal/graph/builder.go:65`).

### Recommendation

**Candidate B (Compound-chain surfacing on
`pkg/stave`) is the highest-leverage next iteration.**

Reasoning:

- The compound pipeline is complete; the only gap is
  library-surface exposure. Adopters using
  `pkg/stave` (every case program, bucket-intent,
  stave-explorer) gain the compound view for small
  library-side engineering cost.
- `ChainBonus` already provides chain-membership-
  weighted ordering; exposing `ChainMembership` at
  the library surface makes this weighting visible
  and explicable.
- Does not reverse the "external tools do graph
  algorithms" design boundary — fully compatible with
  shipped architecture.
- Drives the catalog work (cloudfront's missing-chain
  gap surfaces) and the `ExposureScore` library
  exposure (currently trimmed in `pkg/stave.Finding`).

**Deferred intentionally**:

- **Candidate A** (per-finding metadata cascade) is
  orthogonal. Per-finding prose improves per-finding
  context; doesn't address the compound-view gap. Can
  run in parallel; the two don't conflict.
- **Candidate C** (choke-point ranking via centrality
  computation) requires a design-boundary reversal.
  Strategic iteration, not a surface-change. `stave
  path` + NetworkX is the current answer for adopters
  wanting centrality today.

The audit's net synthesis: **Stave computes more
compound signal than its Go library exposes. The next
iteration is making what's already computed
accessible to library adopters, not computing more.**

The choke-point framing that motivated this audit
("fix these three to eliminate 80% of compound risk")
has two distinct paths:

- **Within Stave's shipped design**: expose
  `ChainMembership` at the library surface (Candidate
  B). Adopters ordering by `ExposureScore` already
  see chain-weighted prioritization; making chain
  membership visible lets adopters explicitly filter
  on "findings on critical chains" as their
  first-pass triage.
- **Beyond Stave's shipped design**: use `stave path`
  to export graph data and run NetworkX/Graphviz
  centrality analysis. Real workflow for operators
  today.

Both serve the 80/20 triage goal; neither requires
Stave to build graph algorithms. Candidate B is the
recommended next iteration because it's the one
that's bounded engineering inside Stave's design
boundary.
