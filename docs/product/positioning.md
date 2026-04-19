# Stave Positioning

## Preamble

Stave targets the security-engineer persona. The Aikido "State of AI
in Security & Development 2026" survey validated that persona's pain
points — false positives, alert fatigue, tool sprawl, slow
remediation — with specific percentages that the output-model metrics
in `metrics.md` respond to directly. Every optimization target in
`metrics.md` traces to a practitioner pain the Aikido survey
measured; positioning and metrics share the same evidence base.

This document is the positioning constraint. Every feature proposal
runs through positioning and metrics together. A proposal that serves
the target persona and improves a metric is in scope; a proposal that
serves a different persona requires validated market evidence before
it ships. The constraint prevents future feature additions from
diluting Stave's focus on the persona whose pain the evidence
supports.

## The target persona

**The cloud-security-fluent engineer working in AWS environments.**
Concretely:

- Operates day-to-day on detecting and remediating cloud
  misconfigurations. Reads findings in JSON, text, or SARIF; consumes
  Stave output directly in the terminal and via downstream tooling
  (AI prompts, CI/CD pipelines, ticket systems).
- Fluent in AWS vocabulary: bucket policies, IAM roles, KMS keys,
  CloudTrail trails, VPC Flow Logs, `aws:SourceIp`, `aws:PrincipalOrgID`,
  the PAB four-flag matrix. Does not need Stave to explain what a
  wildcard principal is; does need Stave to explain why this specific
  finding fires on this specific bucket.
- Values **deterministic detection** — the same observation produces
  the same finding every time, with no stochastic inference in the
  detection path.
- Values **inspectable reasoning** — finding output exposes the
  predicate clauses that matched and the observation values that
  triggered them, so verdicts are falsifiable and, when wrong,
  actionable.
- Values **actionable remediation data** — structured fields a
  downstream tool or human can consume without interpretation:
  asset-parameterized CLI commands, property-level change lists, and
  context blocks shaped for AI-prompt consumption.

Pain points validated by the Aikido 2026 survey (same citations as
`metrics.md`): 98% of organizations report false positives from their
security tools; 4.8 hours/week wasted on triage, rising to 6.4
hours/week for teams running 5+ tools; 65% of developers bypass
security checks due to alert fatigue; 79% use AI autofix tools but
need reliable structured input to trust the output; teams with
tool-sprawl average 7.8 days to remediate critical vulnerabilities.
Each output-model metric in `metrics.md` responds to one or more of
these measured pains.

Personas explicitly **not** targeted by current Stave development:

- **CISO / security executive.** Consumes compliance dashboards,
  executive summaries, and cross-portfolio posture reports. Features
  serving this persona exist in the codebase from earlier iterations
  but are not the development priority.
- **Junior developer without cloud-security fluency.** Would benefit
  from more tutorial-level output and catalog-aware remediation
  scaffolding. Stave's output assumes cloud-security fluency; users
  learning cloud security alongside Stave are not the persona the
  output is calibrated for.
- **Compliance auditor.** Consumes framework-mapping reports and
  audit evidence packages. Stave carries compliance-tag metadata on
  controls (and audit-evidence infrastructure lives in the codebase),
  but compliance-first workflows are not the development priority.

Features for non-primary personas are preserved (see Feature
classification) but do not receive new investment absent validated
evidence (see Scope-expansion rule).

## Feature classification

Three categories. The categories are the framework; specific features
get classified in a separate audit iteration if one happens. This
document defines the framework, not the inventory.

### Core

Features that serve the security-engineer persona and are aligned
with the output-model metrics. This is where development effort goes.
A feature is core when:

- It improves at least one metric in `metrics.md` for the target
  persona.
- Its existence is justified by the Aikido survey's validated pain
  points, an incident-replay audit in `docs/audits/`, or a
  pentest-methodology coverage gap in
  `docs/methodology-coverage-*.md`.
- Its maintenance cost is proportional to the value it delivers to
  the target persona.

### Latent

Features that exist in the codebase and are accessible to users who
discover them but are not the primary focus. Characteristics:

- Maintained at steady-state: bug fixes land, but no new investment
  absent the feature also improving a core metric.
- Not emphasized in CLI help, README, marketing, or positioning
  materials.
- Preserved because the compositional cost of removal exceeds the
  optionality value of keeping them. The iteration that added them
  lives in the git history; future market signal may promote them to
  core.
- Typical origin: LLM-suggested ideation, analogy-to-competitor
  feature additions, or features added before the positioning
  constraint was codified. None of these are disqualifying — but none
  of them justify new investment absent the scope-expansion rule's
  evidence.

### Deprecated

Features that neither serve the target persona nor carry latent
optionality value. Removed when maintenance cost exceeds optionality
value. Removal requires the same deliberation shape as addition: a
proposal, review, and a commit that states the rationale.

No existing features are pre-classified into this category by this
document. Classification decisions happen iteration-by-iteration; the
deprecated category is the exit path when the cost-benefit shifts.

## Scope-expansion rule

Feature additions for personas other than the validated target
require **validated market evidence** before they ship. What counts:

- A practitioner survey with a methodology, sample size, and
  percentage-backed findings. The Aikido 2026 survey is the reference
  shape.
- Real prospect conversations logged with context, specific requests,
  and attribution. One conversation is anecdote; a pattern across
  multiple conversations from the same persona is evidence.
- Demonstrated traction from users in the non-primary persona —
  engagement telemetry, commit activity from persona-specific
  contributors, or attested use of existing latent features
  warranting upgrade to core.

What does **not** count:

- LLM-suggested ideation. Models generate plausible feature
  suggestions because plausible is what they optimize for; plausible
  is not validated.
- Competitor-analogy reasoning. "Tool X has feature Y" is not
  evidence Stave should have it.
- Speculative feature additions — "engineers might want this" without
  an engineer having said it.
- Sunk-cost arguments. A feature already exists is not evidence it
  should be expanded.
- Elegance arguments. "This would be a clean extension of the
  codebase" is not evidence the persona needs it.

This rule prevents reverse-engineering justification for existing
features. It does not disparage features that exist pre-rule; it
prevents new additions without the evidence the rule demands.

The evidence burden is on the proposer. Iterations that expand scope
include, as a deliverable, the evidence statement — what was
measured, by whom, how. An iteration that names positioning expansion
without the evidence paragraph is out of scope regardless of merit.

## Relationship to metrics.md

- `metrics.md` defines what good output looks like for the target
  persona — the six optimization targets every feature runs through.
- `positioning.md` (this document) defines who the target persona is
  and what triggers a change in target.
- Both constraints apply to every feature proposal. A proposal that
  improves a metric for the target persona is in scope. A proposal
  that improves a metric but for a different persona requires
  positioning-level evidence (per the scope-expansion rule) before
  shipping.
- The two documents share an evidence base: the Aikido 2026 survey
  grounds both the persona selection (positioning) and the
  optimization targets (metrics). If the survey's finding set is
  superseded by a later validated survey, both documents update
  together.
- `docs/product/architecture.md` defines what belongs in Stave
  core versus in Stave apps. Positioning governs which persona
  core's output targets in the first instance; architecture
  governs whether persona-specific features ship in core (no —
  core is persona-agnostic) or in apps (yes — apps own
  persona-specific composition). A proposal serving the target
  persona is in scope per positioning; whether it ships as a
  core primitive or as app-shaped composition is the
  architectural question architecture.md answers.

Minor overlap: `metrics.md`'s "Scope constraints" section names the
target persona in a single bullet ("cloud-security-fluent engineer
encountering Stave for the first time" appears in Metric 5's
Definition). This document elaborates that persona in full.
Consolidating the overlap is plausibly future work — flagged, not
done here. For now, the bullet in `metrics.md` stays as a pointer and
this document is the authoritative persona definition.

## Enforcement

Every iteration prompt that proposes new work references both
`metrics.md` and `positioning.md`. The proposal names the persona the
work serves. If the answer is the target persona and the work
improves at least one metric, the proposal is in scope. If the answer
is a different persona, the proposal requires evidence per the
scope-expansion rule — stated up front, not retrofitted after
pushback.

A proposal that serves another persona and has no validated evidence
is out of scope. This applies regardless of implementation cost,
sunk-cost arguments, or elegance. The cost of adding a feature is
paid indefinitely; the cost of declining one is a single iteration
skipped.

The document is living. Validated evidence can shift the target
persona, add a secondary persona, or reclassify features between
core, latent, and deprecated. The process is the same as any
scope-expansion: an iteration with the evidence as a deliverable,
followed by updates to `positioning.md` and `metrics.md` together.
Informal additions to the persona set — mentioned in commits, slacked
around, assumed in subsequent proposals — do not bind.
