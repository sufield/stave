# Stave Output-Model Metrics

## Preamble

Stave optimizes for six metrics. Every feature proposal
runs through this document. A proposal names which metrics the work
improves and which metrics it risks deteriorating; proposals that
improve nothing are out of scope unless they close a drift or
documentation gap, and proposals that deteriorate a metric require
explicit justification before they ship.

The Amazon parallel frames the intent. Amazon optimizes for fast
shipping as the north-star property that organizes every operational
decision — warehouse placement, packaging, fulfillment routing,
inventory strategy all derive from it. Stave optimizes for these six
metrics as the north-star set that organizes every feature, every
control, every output change. The metrics are the constraint; the
iterations are subordinate to them.

## Scope constraints

- Stave is a deterministic detection tool. No AI inference anywhere
  internally. Predicate evaluation is pure CEL against observation
  JSON.
- Stave produces findings. Remediation execution happens outside
  Stave. The boundary is the data in the finding, not the change in
  the cloud account.
- Stave's output is designed to be consumed by downstream tooling,
  including AI prompts, CI/CD pipelines, ticket systems, and humans.
  The structured fields in the finding exist so downstream tools do
  not have to parse prose.
- Stave does not track authorship of code or configuration. Security
  state is independent of who or what produced it. Human-authored and
  AI-authored misconfigurations get the same treatment — the finding
  stands on the observation, not on the provenance of the source.
- Stave plays well with other tools. The consolidated-view claim
  (metric 6) is about output quality, not vendor lock-in. Users
  running Prowler or ScoutSuite alongside Stave should see Stave
  consolidate rather than duplicate.
- This document defines output-model metrics. Catalog coverage,
  observation contract design, and extractor conformance are separate
  concerns governed by their own documents (`docs/contract/`,
  `docs/methodology-coverage-*.md`).

## The six metrics

### Metric 1: Prioritization

**Definition.** Findings are ordered by actionable priority. Priority
is a score that combines: (1) base severity from the control's
`severity:` field, mapped via `SeverityToWeight` or overridden by the
control's `base_impact:` param; (2) a stepped duration factor keyed
on days-blind (`DurationFactor` — 1.0 at ≤30d, 1.5 at 30d+, 2.0 at
90d+, 3.0 at 365d+, 5.0 at 1643d+/4.5-year "silent killer"
threshold); (3) a blast multiplier from the control's
`blast_multiplier:` param; (4) an exposure multiplier derived from
the control's `exposure:` block, not a single `IsPublic` bool;
(5) a chain-membership bonus when the finding participates in one or
more fired chains, proportional to the chain's `compound_score` and
the finding's role (member vs missing-safeguard). The default sort
order of `findings[]` is score descending; the score and its
factor-by-factor breakdown are emitted on every finding so the order
is inspectable, not oracular.

**Why it matters.** The Aikido 2026 survey reports that **98% of
organizations report false positives** from their security tools.
False positives are the output-side manifestation of absent
prioritization: every finding carries equal weight, users triage
sequentially, noise and signal arrive in the same queue. Teams stop
reading output after the third irrelevant finding. Prioritization
turns the queue into a ranking the user can scan top-down and stop
when they hit diminishing returns.

**Baseline.** PARTIAL. `risk.RankExposures` at
`internal/core/evaluation/risk/exposure_rank.go` computes an
exposure score with factor breakdown (`base × durationFactor × blast
× exposureMult × chainBonus`) and emits a sorted `top_exposures[]`
view. The main `findings[]` array is sorted by `ExposureScore`
descending via `SortFindings` at
`internal/core/evaluation/finding.go` with alphabetical tiebreaker
on `ControlID` + `AssetID` (commit `5462430d5`'s follow-up iteration).
Chain membership feeds into per-finding scores through
`ChainMembershipCount` on `RankInput` and the `ChainBonus` factor
(1.0× / 1.5× / 2.0× for zero / one / two-or-more chains).
Exploitability remains binary via `exposureMultiplier` reading
`Exposure.IsPublic` — broadening to the `exposure.type` enum and
principal-scope value is the remaining improvement to close out this
metric. Each finding carries its `exposure_score` and
`score_breakdown` inline; the `top_exposures[]` parallel view is
retained as the summary "Critical-Path Exposures" surface in text
output.

**Target.** Broaden exploitability beyond binary `IsPublic` — the
exposure multiplier reads the `exposure.type` enum
(`public_internet` vs `cross_account` vs `same_account_privileged`)
and scores each distinctly. The default sort and chain-bonus
factors landed; the exposure-model widening is the remaining work
for this metric to reach full coverage.

**Improvement signal.**
- Default `findings[]` sort matches `top_exposures[]` ordering.
- Chain membership demonstrably changes an individual finding's
  rank — fixture with a chain fires and the member findings rank
  above non-member peers with the same base severity.
- A finding's score and breakdown are emitted on every finding, not
  only on the top-N slice.
- Exploitability distinguishes `public_internet` from
  `cross_account`, `cross_account` from `same_account_privileged`,
  and scores each distinctly.
- The score is deterministic and reproducible — two runs against
  identical observations produce identical ranks.

**Deterioration signal.**
- A proposal introduces ranking that is non-deterministic or depends
  on wall-clock time.
- A proposal hides the score or the breakdown — users can see the
  rank but cannot see why.
- A proposal reintroduces alphabetical as default sort for
  `findings[]` under any format.
- A proposal adds a factor without documenting it in this metric's
  Definition section and in `exposure_rank.go`.
- A proposal makes the score dependent on per-tenant configuration
  that varies across runs — scores must be comparable across runs on
  the same catalog.

### Metric 2: Deduplication

**Definition.** Findings that share a root cause are consolidated
into a single issue. Root cause is the shared predicate-consumed
observation field: two findings share a root cause when their control
predicates consume the same observation field (or set of fields) and
those fields have the same triggering value on the same asset.
Example: `CTL.S3.CONTROLS.001` (PAB umbrella) and the four
`CTL.S3.PAB.*` sub-flag controls all read
`storage.controls.public_access_block.*` on the same bucket — one
root cause. The dedup output is an `issues[]` view parallel to
`findings[]`, where each issue carries the root-cause field set, the
asset, and the list of contributing findings. `findings[]` remains
the full per-control emission; downstream tools choose which view
they consume.

**Why it matters.** The same Aikido 2026 finding (**98% false
positives**) applies. Noise manifests not only as unranked findings
but as repeated findings: a single misconfiguration that five
controls each detect produces five triage tickets. Users stop
believing output that repeats. Dedup by root cause collapses the
PAB-umbrella-plus-four-sub-flags case to one issue with five
contributing signals, not five distinct problems.

**Baseline.** PARTIAL. Root-cause dedup via
`evaluation.BuildIssues` at
`internal/core/evaluation/issue.go` now emits `issues[]` alongside
`findings[]` in `out.v0.1` JSON output; a new Issues section leads
the text report; SARIF results carry
`partialFingerprints.stave/issue_id` for post-processing
reconstruction. The dedup rule is shared
predicate-consumed observation fields per asset, union-find with
transitive closure, derived from each finding's `ReasoningTrace` as
shipped in the traceability iteration. Two refinements to the
literal intersection rule ship with this baseline: (1) kind-
discriminator fields (`storage.kind`, `compute.kind`,
`identity.kind`, `cryptography.kind`, `container.kind`,
`backup.kind`) are excluded from the dedup key set to prevent every
co-asset finding collapsing into one Issue; (2) each ObservationKey
contributes both itself and its parent namespace (all but last
segment, with ≥2-segment parents) so sibling sub-field findings
under the same namespace merge. `remediation.BuildGroups` continues
as a distinct secondary view of the same findings set by
remediation-action equality.

Known limitations:

- The PAB umbrella + sub-flag case partially consolidates: 4
  sub-flag findings merge via their shared `storage.public_access_block`
  namespace, but the umbrella (`storage.public_access_fully_blocked`)
  remains a separate Issue because its path has no ≥2-segment shared
  prefix with the sub-flags. Semantic grouping across derived-field
  boundaries is future work.
- Coincidental namespace overlap is not yet distinguished from
  meaningful overlap. If two unrelated controls on the same asset
  both read fields under a common namespace, they merge. No evidence
  yet that this surfaces in practice; will flag if it does.
- Discriminator exclusion is a hardcoded list; future iteration may
  drive it from control metadata.

**Target.** Remaining work for this metric:

- Cross-derived-field consolidation (PAB umbrella + sub-flags merge
  into one Issue). Requires either semantic annotation on controls
  that share a root cause expressed via different observation fields,
  or a contract-level derivation layer linking related fields.
- Driving discriminator exclusion from control metadata rather than
  a hardcoded list.
- Issue-level remediation consolidation — currently each member
  carries its own remediation; an Issue-level unified remediation
  summary is an open design question.

**Improvement signal.**
- PAB-umbrella + 4 sub-flags on the same bucket produces 1 issue
  with 5 contributing findings, not 5 issues.
- The root-cause field set is exposed on each issue; users can read
  which observation fields triggered the bundle.
- A control-side annotation convention exists; new controls declare
  their root-cause fields explicitly rather than relying on predicate
  AST inference.
- Dedup is lossless — each contributing finding is reachable from the
  issue record (by `finding_id` reference), so downstream tools that
  want per-finding remediation data retain access.
- Action-fingerprint grouping remains intact as a separate view for
  the "these findings have the same fix" use case.

**Deterioration signal.**
- A proposal adds a dedup path that hides contributing findings
  (lossy dedup — users can see the issue but not the underlying
  findings).
- A proposal dedups across asset boundaries (two findings on
  different assets collapse into one issue) without explicit
  cross-asset-root-cause semantics.
- A proposal dedups across control boundaries without a shared
  root-cause field set — arbitrary merging by severity or attack
  stage alone.
- A proposal replaces `BuildGroups` with the root-cause dedup path —
  both views coexist; they answer different questions.
- A proposal introduces dedup that depends on runtime configuration
  that varies across runs — dedup behavior must be reproducible.

### Metric 3: Traceability

**Definition.** Every finding includes a reasoning-chain summary
inline in the default output. The summary lists the predicate
clauses that matched (the ones that pushed the overall predicate to
true) together with the observed value each clause saw. Example, for
`CTL.S3.NETWORK.VPC.001` firing on a bucket: `matched_clauses: [
  {field: "storage.kind", op: "eq", value: "bucket",
  observed: "bucket"}, {field: "storage.access.has_vpc_condition",
  op: "eq", value: false, observed: false},
  {field: "storage.access.has_ip_condition", op: "eq", value: false,
  observed: false} ]`. This is "matched clauses + observed values"
(option (b) from the survey's traceability-shape gap). Full
step-by-step trace (every predicate evaluation, intermediate result,
decision point) stays opt-in behind `--trace` as today.

**Why it matters.** The Aikido 2026 survey identifies that developers
and security engineers lose trust in tools whose verdicts cannot be
inspected. A finding that says "this bucket is unsafe" without
showing why is indistinguishable from noise; one that shows the
three observation values that tripped the predicate is falsifiable
and, when wrong, actionable. Traceability is what converts a finding
from an assertion into evidence.

**Baseline.** PARTIAL. Every finding now carries a `reasoning_trace`
field inline in the default output — a list of `MatchedClause`
records, each pairing the clause's authored predicate expression,
observation key, operator, expected value, and the value observed
from the snapshot. The list is populated by
`ReasoningTraceFromMisconfigurations` at
`internal/core/evaluation/finding.go` and wired into finding
construction in `internal/core/evaluation/engine/finding_gen.go` and
`finding_builder.go`. DTO surface (`FindingDTO.ReasoningTrace`), text
output (per-finding "Reasoning:" block), and SARIF output
(`properties.reasoning_trace` bag) all emit the trace. Full
`LogicTrace` (`internal/core/trace/trace.go`, schema `trace.v0.1`)
remains opt-in behind `--trace path.json` and is a strict superset —
whole-predicate aggregate `Step`s plus any instrumentation a future
iteration adds. `Evidence.Misconfigurations[]` continues to emit
alongside `reasoning_trace` (duplicate-looking but different framing:
violations list vs predicate-match record); consolidating the two is
future work.

Known limitation: for the ~15 of 675 controls using `any:` at the
predicate root, the reasoning trace includes every leaf clause the
engine considered, not only the clause that satisfied the `any`.
Readers compare `observed_value` to `expected_value` inline to infer
which clause actually matched. Per-clause match resolution for `any`
predicates is a future refinement; the dominant `all:` case (660/675)
emits the exact matched set.

**Target.** The default-inline compact trace landed in the prior
iteration. Remaining work on this metric:

- Per-clause match resolution for `any:` predicates — the 15 of 675
  controls where the current trace over-reports (shows all leaf
  clauses the engine considered, not just the matched one). Requires
  a per-op clause-level evaluator.
- Prose rendering in text mode driven by the self-explaining
  translator (metric 5) — today's text output shows the clause's
  authored form (`storage.access.has_wildcard_principal eq true`),
  which leaks predicate-DSL vocabulary. Plain-language translation is
  Metric 5's work; once landed, it consumes the reasoning_trace
  structure.
- Consolidation of `Evidence.Misconfigurations[]` and
  `reasoning_trace` into a single structured surface — they currently
  emit side-by-side with overlapping content.
- Open design question: should full `--trace` output become the
  default for specific finding categories (e.g., critical-severity,
  chain-member, silent-killer)? Compact trace is sufficient for the
  dominant case; full trace shines during post-incident deep-dive.
  Not committed work; flagged for discussion.

**Improvement signal.**
- Every finding in `apply` JSON output carries a `reasoning` field
  listing matched clauses + observed values.
- The `reasoning` shape is stable and documented — downstream tools
  can rely on it.
- Text-mode output renders `reasoning` in a readable form without
  requiring users to cross-reference control YAML or contract docs.
- `--trace` remains supported and is strictly a superset of inline
  reasoning (everything inline is also in the trace; trace adds
  per-step timing and skipped clauses).
- Fixtures confirm `reasoning` accuracy — a fixture-level test
  asserts that the reasoning emitted matches the predicate's
  actually-evaluated clauses.

**Deterioration signal.**
- A proposal embeds reasoning only in JSON and not in text — text
  mode remains unreasoned.
- A proposal emits reasoning that references predicate AST
  implementation details (CEL expression strings, raw operator
  enums) rather than the clause-level structure.
- A proposal omits observed values from the inline reasoning —
  clauses without values are opaque.
- A proposal truncates reasoning on large predicates without a
  documented truncation convention.
- A proposal makes inline reasoning dependent on `--trace` being
  enabled — breaking the "default-on, no-flag" target.

### Metric 4: Remediation data quality

**Definition.** Each finding carries structured, complete, reliable
data describing what needs to change. "Structured" means machine-
consumable fields, not prose-only descriptions. "Complete" means the
data is sufficient for downstream tools (AI prompts, CI/CD
pipelines, ticket systems, humans) to act without needing to go back
to Stave for more information. "Reliable" means the data matches the
actual remediation — the CLI command runs, the property change
closes the specific door. Concrete remediation is a runnable CLI
string with asset-parameterized substitutions where the asset
identity permits. When `HasSafeDefault=false`, the
`PropertyChange.RequiredValue` field is empty and the record
documents that the required value is context-dependent; downstream
tools handle the prompt for user input. Stave produces the data;
Stave does not execute the fix. No auto-fix, ever — that boundary
is a hard scope constraint.

**Why it matters.** The Aikido 2026 survey identifies that
remediation handoff is where security tooling breaks down — the
finding names a problem, the developer has to translate it into a
change. AI-assisted development amplifies the gap because AI
assistants need structured input to produce reliable changes. A
finding whose remediation is prose ("enable Block Public Access")
requires the AI or human to research what specifically to enable on
which flag. A finding whose remediation carries a runnable CLI
parameterized to the asset is directly consumable.

**Baseline.** PARTIAL. Four deliverables landed:

1. **Asset-parameterized CLI commands.** `FormatRemediationAction`
   at `internal/core/evaluation/remediation/formatter.go`
   substitutes placeholder tokens (`<id>`, `<name>`,
   `<bucket-name>`, `<role-arn>`, `<cluster>`, `<region>`,
   `<account>`, etc.) in the `RemediationSpec.Action` template
   with the specific asset's identifiers at enrichment time. The
   result is stored on a new `RemediationPlan.Command` field.
   `<current>` markers in multi-flag PAB commands are preserved
   verbatim (they mean "keep the existing value"). Unknown tokens
   pass through. 8 unit tests cover substitution, ARN parsing,
   type-mismatch, unknown-token, and `<current>`-preservation
   cases.
2. **RequiredValuePrompt.** `PropertyChange` gains a
   `RequiredValuePrompt` field (propagated from the control's
   `RemediationSpec.RequiredValuePrompt` when `HasSafeDefault=false`).
   Control authors add a single prompt per control in YAML; the
   prompt attaches to every HasSafeDefault=false change derived
   from that control's violations.
3. **Structured export (remediation_context).** Every finding in
   JSON output now carries `remediation_context`: an asset-identity
   block (id, type, vendor, ARN, region), a violation block
   (control_id, control_name, severity, reasoning[] with
   plain-English clause + observation_key + observed_value),
   structured changes[], and the parameterized command. Shape is
   direct-consumable by AI prompt templates.
4. **Hard scope boundary reinforced.** `./stave apply --help` now
   includes an explicit "Remediation scope" block stating Stave
   produces data, not changes; pipe output to downstream tooling
   for fix generation; no auto-fix flag exists and none is planned.

SARIF output gains parameterized command in result fixes —
preferring `RemediationPlan.Command` over the raw template when
available. Text output is unchanged (the existing remediation
section carries prose description + action; adding structured
changes would bloat human-oriented output).

Known limitations:

- Placeholder vocabulary covers the shipped catalog's common
  patterns (~20 tokens). New controls with new token conventions
  fall through unchanged until the formatter extends.
- `RequiredValuePrompt` is authored per-control (not per-change).
  A given control with multiple HasSafeDefault=false changes emits
  the same prompt on each; granular per-property prompts are
  future work.
- Prompts are sparsely populated across shipped controls (the
  iteration shipped infrastructure + limited author examples).
  Bulk prompt authoring is follow-up work.
- CLI-only remediation (no per-IaC-stack rendering). Terraform /
  CloudFormation / CDK snippet generation is orthogonal future
  work; the parameterized CLI remains the lowest-common-denominator.

**Target.** Remaining work for this metric:

- Extend placeholder vocabulary as new controls ship with new
  token conventions.
- Bulk-author `RequiredValuePrompt` for the HasSafeDefault=false
  catalog (time-box: 50 prompts per iteration until coverage
  stabilizes).
- Consider per-IaC-stack rendering as a separate output mode
  (e.g., `--format terraform`) if user demand surfaces.
- SARIF fix-object completeness — not every finding has a fix
  populated initially; ongoing as the catalog-side remediation
  data extends.

**Improvement signal.**
- CLI `Action` strings are parameterized to the specific asset in
  fixture outputs — no `<placeholder>` tokens remain where the asset
  identity resolves them.
- Every `HasSafeDefault=false` finding carries structured prompt
  text for the required value.
- The export-for-AI-prompt shape is documented in `docs/contract/`
  or an equivalent product-level location and downstream consumers
  can rely on it.
- A fixture-level test confirms the CLI string produced is runnable
  (syntactically valid; parameters resolved).
- Per-IaC-stack rendering, if added, is additive — the CLI remains
  the default.

**Deterioration signal.**
- A proposal adds auto-fix execution, directly or transitively
  (CLI flag, API, watch mode, CI-hook-triggered mutation).
- A proposal makes remediation data AI-inferred rather than
  deterministic — the structured fields stop being reliable.
- A proposal removes the structured fields in favor of prose-only
  descriptions.
- A proposal varies remediation shape across output formats — AI
  prompts get one shape, text another, SARIF a third.
- A proposal ships remediation for a control without a fixture-
  level test confirming the remediation actually closes the
  detection.

### Metric 5: Self-explaining output

**Definition.** Output is legible without Stave fluency. Predicate-
DSL vocabulary is translated to plain language. Control IDs are
paired with one-line summaries. Evidence fields surface the observed
state in terms a target reader recognizes — AWS-level vocabulary
(`bucket policy`, `principal`, `Condition`), not Stave-level
vocabulary (`policy_has_scoping_condition`, `unsafe_value`). The
target persona is a cloud-security-fluent engineer encountering
Stave for the first time: they know what a bucket policy is, what
`aws:SourceIp` means, what a Condition does. They do not know
Stave's control IDs, predicate operator enum values, or contract
field names. The output meets them where they are.

**Why it matters.** The Aikido 2026 survey identifies that security
tooling with high adoption friction gets bypassed. Friction comes
from output that requires tool-specific fluency before the first
finding is actionable. A first-time reader who sees
`unsafe_value: true, operator: eq, property:
policy_has_scoping_condition` has to look up what
`policy_has_scoping_condition` means, what `eq` means in this
context, and what `unsafe_value: true` means when combined. A reader
who sees "the bucket policy has at least one Allow statement with a
wildcard principal and no restricting Condition — the statement
effectively allows any AWS caller unless narrowed" starts acting.

**Baseline.** PARTIAL. Plain-language translation landed via the
`internal/core/translation` package — `RenderClause(Clause,
FieldRegistry) string` composes the field's prose (from
`DefaultFieldRegistry`), the operator's verb phrase (from
`operatorProse`), and the expected/observed values into one line
per clause. Text output's per-finding "Reasoning:" block now
renders each `ReasoningTrace` entry through the translator; JSON
and SARIF retain the raw DSL shape for downstream tooling (per the
metric's rule that structured output stays structured). Control IDs
continue to appear as identifiers paired with their `ControlName`
one-liner at the finding header.

Registry coverage: hand-maintained map at
`internal/core/translation/fields.go` covering the 111 distinct
non-discriminator `ObservationKey` paths actually emitted into
`ReasoningTrace` output across shipped fixtures. Long-tail paths
(out of the full ~713-path contract surface) fall back to raw DSL
rendering until the registry extends.

Known limitations:

- Prose template reads awkwardly when the predicate's `value:` is
  the unsafe value (e.g., `has_wildcard_principal eq true`) —
  renders as "… must equal true, but is true". The template is
  correct for clauses where `value:` is the safe value (e.g., PAB
  `block_public_acls eq false` where BlockPublicAcls being enabled
  means true); the other pattern reads as contradiction. Refining
  the template to branch on safe-vs-unsafe expected values is
  future work and requires contract-level annotation.
- Registry is hand-maintained in Go. A distributed
  contract-markdown parser (one Translation: line per field in
  `docs/contract/*.md`, code-gen at build time) is the long-term
  direction but deferred for scope.
- Control IDs pair with `ControlName` (one-line summary), not with
  `ControlDescription` (canonical prose). A scan-optimized
  one-liner glossary distinct from ControlName is a future
  refinement.

**Target.** Remaining work for this metric:

- Refine the prose template to handle safe-vs-unsafe expected
  values (requires adding a safe-value annotation to controls or
  the observation contract).
- Extend the registry toward the full 713-path contract surface —
  the long-tail coverage.
- Optionally introduce a distributed contract-markdown parser with
  build-time codegen so contract authors maintain translations
  adjacent to field definitions.
- Optionally add a `--trace-raw` or similar flag to render the
  original DSL form in text output for users who prefer it.

**Improvement signal.**
- Text-mode output renders predicate-DSL misconfigurations as prose
  in AWS vocabulary.
- Every control ID that appears in text output is paired with a
  one-line summary on first appearance.
- Structured JSON fields are unchanged — the translator is a text-
  rendering concern, not a data model change.
- A fixture-level test asserts that text output for a named control
  contains the expected plain-language rendering.
- Readings by a first-time reader (unit-test-style or reviewer-
  feedback-driven) confirm legibility without catalog reference.

**Deterioration signal.**
- A proposal removes the structured DSL fields from JSON to make
  text output cleaner — the translator's job is to layer, not
  replace.
- A proposal introduces translator vocabulary that assumes Stave-
  specific concepts (profile names, scope_tags, CEL syntax) instead
  of cloud-provider vocabulary.
- A proposal targets a persona other than the cloud-security-fluent
  engineer without updating this document first.
- A proposal renders different translations across output formats
  for the same finding — JSON's "the bucket policy" must not
  disagree with text's rendering.
- A proposal ships a control whose YAML description is written for
  Stave insiders rather than the target persona.

### Metric 6: Single source of truth / cross-tool posture

**Definition.** Output is designed as the consolidated security
view. Two output surfaces deliver this: (1) every control carries
optional `equivalents:` metadata mapping it to parallel checks in
Prowler (primary yardstick), ScoutSuite (secondary), and manual-
pentest playbooks (Rhino Security IAM cluster, S3 pentest
checklist). Findings emit `equivalent_signals: [...]` listing what
other tools call the same detection. (2) `apply` output includes an
optional "coverage posture" section summarizing Stave's coverage
against Prowler checks in the scanned resource set — pulling the
data from `docs/methodology-coverage-*-prowler.md` into runtime
visibility. Equivalence bar is intent-overlap (the two checks detect
the same class of misconfiguration) not exact-check match (they
flag the same bit, same threshold, same message). Commercial tools
(Wiz, Orca, Lacework) are out of scope — their catalogs are opaque,
no reliable equivalence data exists.

**Why it matters.** The Aikido 2026 survey identifies tool sprawl
as a material operational cost — teams run three to seven security
tools in parallel, each producing a partial view, with dedup
happening manually or not at all. A tool that presents itself as
"one more signal" joins the pile. A tool that presents itself as
the consolidation layer, with explicit cross-references to the
tools already in place, displaces the pile. The "single source of
truth" claim is not about exclusivity; it is about designing the
output to consolidate against known parallel sources.

**Baseline.** ABSENT. No cross-tool equivalence metadata in control
YAML. No `equivalent_signals` field on findings. `apply` output
contains no coverage posture section. Methodology coverage exists
at `docs/methodology-coverage-s3-prowler.md` and
`docs/methodology-coverage-iam-prowler.md` as repo docs only — a
user reading `apply` output cannot see Stave's coverage posture
against Prowler's IAM or S3 checks without reading separate
markdown files.

**Target.** Control-level `equivalents:` metadata populated for
every control that has a plausible equivalent (the coverage-
markdown already contains the mapping; moving it into control YAML
makes it machine-addressable). Finding-level `equivalent_signals:`
emitted when equivalents exist. `apply` output grows a coverage-
posture section summarizing, for the scanned resource set, how many
Prowler IAM checks and Prowler S3 checks Stave covers and how many
of those actually ran against the observations in this invocation.
Surface stays opt-in for users who want the slim finding list —
default text output includes it; `--format json` includes it
structurally; a `--no-coverage-posture` flag suppresses it. Manual-
pentest playbook references ride the same `equivalents:` annotation
with a playbook-section identifier.

**Improvement signal.**
- New controls land with `equivalents:` populated where an
  equivalent exists in Prowler or ScoutSuite.
- Existing coverage-markdown content migrates into control YAML
  (one-time backfill; subsequent edits live in YAML only, markdown
  regenerates).
- `apply` output shows Prowler-coverage posture for the scanned
  resource set by default in text mode.
- Users running Stave alongside Prowler can dedup against a known
  machine-readable mapping.
- Commercial-tool equivalence stays explicitly out of scope in
  this document — no drift into catalogs Stave cannot verify.

**Deterioration signal.**
- A proposal adds equivalence data for a commercial tool without
  attested reference to the tool's public catalog.
- A proposal inflates equivalence bar to "exact-check match",
  producing false-negative gaps where intent-overlap would hold.
- A proposal removes methodology-coverage markdown in favor of
  code-only generation — the markdown is the human-reviewable
  source during the backfill window.
- A proposal makes coverage-posture a hard dependency (fails
  `apply` when Prowler data is unavailable) rather than a best-
  effort surface.
- A proposal vendors another tool's output format (emits SARIF
  shaped like Prowler's output) — Stave stays itself and points to
  parallels; it does not masquerade.

## Enforcement

Every iteration prompt that proposes new work references this
document. The proposal names which metrics the work improves and
which metrics it risks deteriorating. A proposal that cannot
identify at least one metric it improves is out of scope unless it
closes a drift or documentation gap — those are a separate category
tracked in `docs/audits/` and the drift-cleanup summaries, and they
do not require a metric claim.

A proposal that deteriorates any metric requires explicit
justification. The justification names the specific deterioration
signal tripped, states why the deterioration is acceptable in this
case, names the metric gain or external constraint that outweighs
it, and schedules the future work that reverses the deterioration.
Proposals that trip a deterioration signal without justification do
not ship — they get redesigned or dropped.

Baselines in the Baseline sections update as work lands. When a
metric moves from PARTIAL to PRESENT, the iteration that moved it
updates the Baseline paragraph and removes the improvement signals
that have been delivered. Target sections update when the "direction
of improvement" has been achieved — the Target reorients to the next
level of ambition or the metric's section notes "Target achieved;
preserve." Improvement-signal and deterioration-signal bullets stay
stable across minor work; changes to those bullets require explicit
metric-scope iteration of their own.

New metrics may be added to this document. Adding a metric follows
the same section structure (Definition, Why it matters, Baseline,
Target, Improvement signal, Deterioration signal) and requires a
separate iteration with its own scope. Informal additions to the
metric set — mentioned in commit messages, slacked around, assumed
in subsequent proposals — do not bind. The authoritative set is what
appears under "The six metrics" (or the next numeric expansion) in
this file.

## Relationship to other documents

- `docs/contract/` defines the observation contract — the shape of
  JSON the extractors emit and the predicate engine consumes. The
  metrics document does not constrain contract design; the contract
  is upstream of output. A finding's content depends on what the
  observation says.
- `docs/methodology-coverage-s3-prowler.md` and
  `docs/methodology-coverage-iam-prowler.md` document catalog
  coverage against external methodologies. Metric 6 uses these as
  the source of truth for equivalence mapping; the coverage
  documents themselves do not optimize for metrics — they report
  per-check coverage status.
- `docs/audits/` contains incident-replay audits that demonstrate
  Stave's coverage against specific named attack classes (e.g.,
  `2026-04-ssrf-imds-s3-coverage.md`). The audits are evidence;
  the metrics document is the target. An audit that shows a gap
  may feed into a future metrics-improving iteration, but the
  audit itself is scoped to its attack-class question.
- `docs/fixture-drift-cleanup-*.md` documents mechanical cleanup
  iterations. These close drift gaps and are explicitly outside
  the metrics-improvement category; they exist to keep the catalog
  and fixtures honest, not to move metrics.
- This document's place: the output-model constraint that every
  feature proposal runs through. When the six metrics and the
  enforcement rules contradict an adjacent document, the adjacent
  document wins for its domain (contract shapes, coverage methodology,
  audit scope) and this document yields. When the adjacent document
  is silent, this document is authoritative.

---

*Footnote on source citation.* The Aikido "State of AI in Security &
Development 2026" report is referenced by specific finding
(e.g., "98% of organizations report false positives"). Where a
metric's "Why it matters" section references the report thematically
without a specific percentage, the report's framing on tool sprawl,
remediation handoff, developer trust, or adoption friction applies;
the metric's direction is grounded in the report's qualitative
signals even when the specific percentage is not quoted. Future
updates to this document should add verbatim percentages as
specific findings are matched to metrics.
