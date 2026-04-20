# Stave Architecture

## Preamble

Stave is a platform. Stave core provides primitives for observing
and evaluating cloud configuration; Stave apps compose those
primitives into persona-specific answers. The CLI is the first app
— an experimental harness that verifies primitives compose cleanly
into real answers and surfaces gaps before they reach users
through other apps.

This document is the architectural constraint. Every feature
proposal runs through three questions: which metric does it
improve (`metrics.md`), which persona does it serve
(`positioning.md`), is it core or app (this document). The
constraint prevents core from accumulating persona-specific or
app-shaped functionality that pollutes the primitives layer, and
prevents apps from reinventing logic that should be shared in
core.

## The platform split

**Stave core.** Persona-agnostic primitives:

- **Observation contract** — the JSON shape extractors emit and
  the predicate engine consumes. Defines what is observable about
  cloud configuration. Source: `docs/contract/`,
  `internal/contracts/schema/embedded/observation/`.
- **Control catalog** — invariants Stave evaluates. Authored as
  YAML, validated against `ctrl.v1` schema. Source:
  `controls/`, `internal/contracts/schema/embedded/control/`.
- **Evaluation engine** — predicate evaluation, reasoning trace
  emission, scoring, deduplication into Issues, chain detection,
  duration tracking. Source: `internal/core/evaluation/`,
  `internal/core/evaluation/engine/`,
  `internal/core/evaluation/risk/`.
- **Output ontology** — the data structures that describe an
  evaluation outcome: findings, Issues, coverage posture,
  alternatives, reasoning traces, remediation context, score
  breakdowns. Source: `internal/core/evaluation/finding.go`,
  `internal/core/report/models.go`,
  `internal/core/evaluation/coverage/`.
- **Structured exports** — JSON envelope (`out.v0.1` schema),
  SARIF (with properties-bag extensions), human-readable text.
  Source: `internal/adapters/output/{dto,json,sarif,text}/`,
  `schemas/output/v1/output.schema.json`.
- **Extended ontology mechanism** — how apps extend the ontology
  when core's primitives don't suffice. Today this is the
  alternatives-block pattern (control YAMLs declare
  `alternatives:` entries, an inventory file declares the
  external tool's checks, core aggregates without knowing the
  tool). Source: `data/alternatives/`,
  `internal/adapters/coverage/inventory_loader.go`.

**Stave apps.** External consumers that compose core's primitives
into answers:

- The CLI (`cmd/stave/`) — first app; experimental harness.
- Future dashboards — CISO-facing, compliance-facing,
  developer-facing. Not in core. Not yet built.
- AI-prompt workflows — consume `remediation_context` from JSON
  exports; not in core.
- CI/CD integrations — consume findings, apply gates. The
  `enforce gate` subcommand's gating behavior is app-shaped;
  it lives in the CLI today (`cmd/enforce/gate/`). Not in core.
- Reports — persona-specific composition of core output. Not in
  core.
- Third-party apps — anything users build on Stave's structured
  exports. By definition not in core.

**What is never in core.**

- Persona-specific logic (CISO views, developer views, auditor
  views — apps own persona).
- Domain-specific business logic beyond invariant evaluation.
- Report composition. Structured exports are primitives;
  reports composed from them are app-shaped.
- Answers to market questions. Core provides primitives; apps
  compose answers.

## Primitive shapes

The primitives core exposes today, each with a one-line
description and a source reference. New primitives extend this
enumeration; removals require justification against apps that
depend on them.

- **Findings** — per-`(control, asset)` evaluation results
  carrying evidence, reasoning trace, scoring, remediation
  metadata, and (when applicable) alternative-tool annotations.
  Source: `internal/core/evaluation/finding.go`.
- **Issues** — consolidated findings sharing a root-cause
  signal per asset. The triage-reduction primitive. Source:
  `internal/core/evaluation/issue.go`.
- **Coverage posture** — per-tool / per-domain coverage
  aggregation derived from each control's `alternatives:`
  annotations and the corresponding inventory file. Source:
  `internal/core/evaluation/coverage/coverage.go`.
- **Alternatives** — per-control mappings to external-tool
  equivalents (`tool` / `check_id` / `coverage` / `note`). Tool
  identifiers are opaque strings; core never pattern-matches on
  them. Source: control YAML `alternatives:` blocks;
  `internal/core/controldef/alternatives.go`.
- **Reasoning trace** — the predicate clauses the engine
  evaluated to produce a finding, paired with observed values.
  Source: `ReasoningTrace` field on `Finding`
  (`internal/core/evaluation/finding.go`).
- **Classification** — the control's semantic evaluation role
  (`state_assertion` | `parameterized_check` | `absence_check`
  | `aggregate_check`), required at the catalog layer and
  propagated to every finding. Distinct from `type` (engine
  mechanism) and `domain` (asset class); lets downstream
  consumers filter by what the control actually checks
  ("show me unsafe-state findings" vs "show me missing-evidence
  findings") without re-deriving from `control_id` substring
  heuristics. Source: `Classification` type at
  `internal/core/controldef/classification.go`; required field
  on every control YAML; propagated through
  `Finding.Classification`.
- **Scope tags** — the control's authoring-metadata tags
  (`[aws, s3]`, `[aws, iam]`, `[gcp, gcs]`, etc.) propagated
  to every finding. Used by apps that filter findings by
  vendor or service domain. Source: `ScopeTags` on
  `ControlDefinition` (declared in control YAML);
  propagated through `Finding.ScopeTags` to JSON's
  `findings[].scope_tags` and SARIF's
  `properties.stave/scope_tags`. Orthogonal to
  Classification: combining them lets consumers compose
  filters on both axes (e.g., "state_assertion findings
  tagged `s3`").
- **Score breakdown** — the multiplicative factors that
  produced a finding's exposure score (`base × duration ×
  blast × exposure × chain`). Source: `ScoreBreakdown` field on
  `Finding`; risk package at
  `internal/core/evaluation/risk/`.
- **Remediation context** — structured per-finding data
  (asset identity, violation reasoning, property changes,
  command) shaped for downstream consumption. Source:
  `RemediationContextDTO` in
  `internal/adapters/output/dto/types_finding.go`.
- **Chain findings** — compound findings that fire when
  multiple controls miss along a known attack chain. Source:
  `internal/core/evaluation/risk/chain_engine.go`.
- **Structured exports** — the wire formats apps consume:
  JSON (`out.v0.1`), SARIF, human-readable text. Source:
  `internal/adapters/output/{dto,json,sarif,text}/`,
  `schemas/output/v1/output.schema.json`.

The list is descriptive, not prescriptive. It documents what
core exposes today. Iterations that add primitives extend the
list; iterations that remove them require justification.

## Market-validated primitives

A primitive belongs in core if apps building on top need it to
answer a validated market problem. The Aikido 2026 survey is the
in-repo anchor evidence (cited by `positioning.md` and
`metrics.md`). A consolidated multi-source analysis covering
adjacent published research (Mandiant, Verizon DBIR, IBM, CSA,
Wiz, Snyk and others) is not currently captured as a single repo
document — see *Caveat on consolidated evidence* below. The
top-four validated market problems framing is taken from that
broader (uncaptured) consolidation; the anchor evidence in repo
remains the Aikido survey.

For each top-four problem, the core primitives that serve it:

1. **Tool sprawl and fragmented visibility.**
   - *Alternatives* let apps surface overlap with other tools
     without core knowing the tools' shapes.
   - *Coverage posture* aggregates the overlap into per-tool /
     per-domain counts.
   - *Structured exports* (SARIF, JSON envelope) let apps
     integrate Stave output into existing pipelines without
     bespoke parsers.

2. **Cloud as top attack surface.**
   - *Findings* surface per-asset configuration issues.
   - *Issues* consolidate findings by asset so attack-surface
     shape is visible per resource rather than per control.
   - *Score breakdown* and chain findings quantify exposure
     and compound risk.

3. **Credential theft in cloud.**
   - The IAM control catalog (under `controls/iam/`) detects
     credential-exposure patterns: privilege-escalation chains,
     unused credentials, root-account misuse, MFA gaps.
   - *Alternatives* on those controls map to Prowler's
     credential-related checks for cross-tool dedup.
   - *Remediation context* structures the fix path for
     downstream consumption.

4. **Misconfiguration as leading breach cause.**
   - *Findings* with reasoning traces explain why an asset is
     misconfigured.
   - *Self-explaining output* (the translation layer rendering
     predicate clauses as English) makes findings legible
     without Stave fluency.
   - *Remediation context* carries property-level change data
     consumers can act on.

A proposal for a new primitive cites which validated problem it
serves. If the answer is "none of the top four," the proposal
cites a validated secondary problem from the broader analysis or
is out of scope.

**Caveat on consolidated evidence.** The "six-report consolidated
analysis" referenced in iteration prompts is not yet captured as
a stable repo document. `positioning.md` and `metrics.md` cite
the Aikido 2026 survey directly; the broader multi-source
analysis lives outside the repo. A future iteration capturing
that analysis as `docs/product/market-evidence.md` (or similar)
is the right home for the consolidated framing this section and
the *Architectural decisions* section below rely on. Until then,
both sections cite specific statistics from the outside-repo
sources (Sygnia, THA, SPL, Aikido) inline and remain anchored on
the Aikido evidence captured in the repo.

## Architectural decisions

Some market problems are solved at the architecture layer, not
the feature layer. The decisions below shape how Stave operates
across every primitive and every app; each cites the market
problem it addresses and the source. Proposals that conflict
with these decisions require explicit justification against the
architectural commitment — not just feature rationale.

- **Vendor-agnostic core.** Stave runs against any cloud
  configuration snapshot regardless of provider. Addresses
  Sygnia's 79% finding ("non-vendor-agnostic IR providers leave
  critical risks unaddressed") at the structural level. A
  cloud-provider-specific optimization that breaks vendor-
  agnosticism violates this commitment.

- **Standard export formats.** Stave speaks JSON schema
  (`out.v0.1`), SARIF, and OCSF-compatible shapes. Enables
  Stave to integrate into existing pipelines rather than become
  another isolated tool contributing to sprawl. Part of the
  tool-sprawl architectural answer (see below).

- **Alternatives annotations and coverage posture.** Stave
  surfaces overlap with tools users already run. The coverage
  posture output makes consolidation decisions visible — a user
  sees "Stave covers 20/21 Prowler S3 checks, 44/47 IAM checks"
  and can decide whether Prowler remains necessary. Addresses
  tool sprawl at both the purchasing layer (duplicated tool
  spend) and the operational layer (tools that don't talk).

- **Tool-sprawl architectural answer (combined).** Tool sprawl
  is the rank-1 market problem (6 of 6 sources in the
  consolidated analysis). Two failure modes: duplicated
  purchases (77% have 5+ data-protection tools per THA) and
  siloed tools (79% swivel-chair syndrome per SPL). Stave's
  architectural answer addresses both through the combination
  of vendor-agnostic core, standard export formats, alternatives
  annotations, and coverage posture. Together they mean
  adopting Stave does not add to sprawl and actively helps
  users consolidate.

- **Deterministic evaluation.** Every finding is produced by
  rule-based predicates against observable data, with no
  probabilistic inference. Counter-positions against AI-based
  security tools whose findings cannot be verified. Addresses
  the opacity problem the Aikido survey documents (69% of
  organizations have found AI-code vulnerabilities;
  accountability for AI-generated flaws is split across roles).

- **AI-ready output.** Stave produces structured output shaped
  for downstream AI consumption — JSON schema for parsing,
  per-finding remediation context for prompt templates, inline
  reasoning traces for verification. Stave has zero AI
  internally; Stave's output is designed to be the reliable
  input AI tools need. Addresses the Aikido survey's direct
  data points (79% use AI autofix tools, 98% trust them); the
  pain is reliable input data, and Stave solves the input-
  reliability side without becoming an AI tool itself.

- **Inspectable reasoning.** Every finding carries its
  reasoning chain inline (the `reasoning_trace` field on each
  Finding). Enables downstream verification by humans, AI
  consumers, and compliance auditors. Complementary to
  deterministic evaluation: determinism ensures correctness,
  inspectability ensures trust. Addresses opacity across
  multiple metrics the Aikido survey surfaces.

- **Extended ontology mechanism.** Apps extend core's ontology
  without modifying core. Today's instance is the alternatives-
  block + inventory-file pattern: control YAMLs declare
  alternatives, inventory files declare external-tool check
  sets, core aggregates without knowing the tools' shapes.
  Preserves core's persona-agnostic shape while enabling app-
  specific composition for vertical use cases.

- **Credential-free operation.** Stave evaluates local
  snapshots without requiring cloud credentials. Addresses
  access-control complexity in multi-tool environments —
  adopting Stave does not require provisioning yet another
  set of service credentials, rotating keys, or managing
  access scopes. Reduces operational friction that contributes
  to tool sprawl's administrative burden.

- **Sanitization policy.** Stave's output may carry data
  derived from observations: account IDs, ARNs, principal
  names, resource identifiers. The sanitization policy is
  type-discriminated. Values that can carry identifier-shaped
  data — strings and collections of strings — route through a
  per-field opt-in Sanitizer (the
  `internal/core/kernel.Sanitizer` interface). Primitive
  types (booleans, integers, floats, null) pass through
  unchanged. This preserves the factual content of
  observations (a PAB flag is `false`, a retention threshold
  is `30`) while preventing identifier leakage where
  sensitivity is declared. The AI-ready architectural
  decision depends on this policy: AI consumers and
  fix-plan templates need the actual observed values to
  generate coherent remediation prompts.

These commitments are durable. Each was made because a market
problem demanded it, not because it was convenient. Reversing
one requires the same threshold of evidence that admits a new
target persona under `positioning.md`'s scope-expansion rule:
the proposal cites the validated market problem the reversal
serves and explains why the original commitment no longer holds.

## Scope-expansion rule

Core primitives are added when a validated market problem
requires them and no existing primitive suffices. App-shaped
functionality (persona-specific composition, domain logic beyond
invariants, report generation) goes in apps, not core.

A proposal that adds persona-specific logic, domain composition,
or market-question answers to core, *or that conflicts with one
of the architectural decisions above*, requires explicit
justification that the functionality is actually primitive-
shaped (or that the architectural commitment no longer holds).
Three justifications that are not sufficient:

- *Elegant.* Aesthetic appeal does not establish primitive shape.
  Many app-shaped features look elegant inside core because
  they get to share core's plumbing. The appeal is the cost.
- *Convenient.* Putting an answer in core because callers want
  to consume the answer directly bypasses the apps layer. The
  convenience is paid back as core bloat.
- *Reuses existing code.* Code reuse is a positive when both
  consumers are primitive-shaped. When one consumer is app-
  shaped and the other is core, "reuse" is the failure mode the
  rule exists to prevent.

The rule prevents two failure modes:

- Core accumulating app-shaped functionality that pollutes the
  primitives layer. Symptoms: persona-specific output formats
  in core, business-logic composition in core, persona-named
  fields on primitive shapes.
- Apps duplicating logic that should be a shared core
  primitive. Symptoms: two apps both implementing the same
  derivation; apps post-processing core output to recover
  information core could have exposed directly.

Both failure modes are detectable in code review. The rule
makes the reviewer's question explicit: "is this primitive-
shaped?"

## The CLI as experimental harness

The CLI (`cmd/stave/`) is Stave's first app. It exists to
verify that core primitives compose cleanly into real answers.
New primitives ship with CLI usage demonstrating they compose
correctly; the CLI's existence is the integration test for the
core platform.

The CLI is not the product. It is the development interface
that makes primitives testable end-to-end. Other apps
(dashboards, AI-prompt workflows, CI/CD integrations) are also
consumers of core's primitives; the CLI is the first and most
primitive-facing.

Implications:

- CLI commands that compose primitives into persona-specific
  answers are valid as experimental composition. They prove
  the primitives suffice; they do not promote the composition
  to a durable core feature.
- Persona-specific CLI output modes (e.g., a `--ciso-summary`
  flag, a compliance-report subcommand) are app-shaped, not
  core-shaped. They are CLI-as-app decisions; they do not
  imply core changes.
- When an experimental CLI composition proves valuable for a
  specific persona, the graduation path is extracting it into a
  dedicated app (separate binary, separate repository, separate
  distribution), not promoting it into core. Promotion into
  core is the failure mode the rule exists to prevent.

This document does not propose any specific extraction. The
graduation path is named so future iterations have a recipe; no
extraction is in scope here.

### stave-explorer (scaffolding, not a Stave app)

`stave-explorer/` is a minimal bubbletea-based TUI living at
the monorepo level (sibling to `stave/`). It probes Stave's
JSON output against the five pain-point metrics validated by
the Aikido 2026 and Thales 2026 surveys: triage time, false-
positive rate, MTTR, compliance knowledge, tool sprawl. It
invokes Stave via `./stave apply` and consumes the resulting
JSON envelope; it has no special access to Stave core
internals and does not require core modifications.

Its primary affordance is structured logging: every
computation step (JSON field reads, intermediate structs,
classification decisions, final answers) is logged via
`log/slog`'s JSONHandler to
`stave-explorer/logs/session-{timestamp}.log`. The TUI is the
interaction surface; the logs are the evidence. Per-question
log volume serves as a shape-quality signal — a question that
takes 280 log lines to compute a number indicates the
envelope is missing a pre-aggregated primitive; a question
that takes 5 lines indicates the envelope is shaped well for
the metric.

The prototype's purpose is to surface measurement gaps in
Stave's output that drive future core iterations. Gap
observations land in `stave-explorer/gaps.yaml` (per-question,
with session-log line references) and `stave-explorer/findings.md`
(top-three gap candidates plus clean observations). Future
core iterations may consume these as evidence-grounded inputs
to prioritization, in the same shape that `docs/audits/`
documents drive iteration prompts.

Like the CLI, stave-explorer is not a Stave app in the
platform-pattern sense. It is scaffolding at the user-question
layer. Personal-specific output, dashboard-style composition,
or product-quality interaction belong in apps proper; this
prototype exists only to make the envelope's measurement
adequacy visible.

### bucket-intent (scaffolding, not a Stave app)

`bucket-intent/` is a hello-world prototype living at the
monorepo level (sibling to `stave/` and `stave-explorer/`). It
answers one question — "is this S3 bucket public when the
intent is private?" — for one bucket at a time, declared via
`--bucket` and `--intent` flags. The prototype's value is
what writing it teaches about intent-vs-actual composition,
not the question itself: it is hello-world scope for a future
larger intent-checking surface.

Same scaffolding pattern as stave-explorer: shells out to
Stave / consumes JSON output, logs every step via `log/slog`
to `bucket-intent/logs/session-{timestamp}.log`. Observations
land in `bucket-intent/observations.md`, including specific
calls to Stave-output shape gaps surfaced by writing the
prototype (e.g., `Finding.classification` would let consumers
distinguish state-assertion controls from parameterized
checks without re-deriving via control_id substring
heuristics — already shown to misclassify on the lordofheaven
fixture's `CTL.S3.PUBLIC.PREFIX.001` case).

The "third copy = extraction" rule applies: pieces copied
from stave-explorer are tracked in observations.md. When a
third prototype reuses the same scaffolding, the duplication
becomes evidence for promoting it to a shared scaffolding
module — until then, copying is cheaper than designing a
shape that hasn't been validated by use.

## Relationship to metrics.md and positioning.md

Three constraints govern feature proposals:

- **`metrics.md`** defines what good output looks like for the
  target persona. Six output-model metrics, each with a
  definition, baseline, target, improvement signal, and
  deterioration signal.
- **`positioning.md`** defines who the target persona is and
  what evidence threshold a proposal must clear to serve a
  different persona.
- **`architecture.md` (this document)** defines what belongs in
  core versus in apps. The platform shape.

Every proposal runs through all three:

- Improves a metric *and* serves the target persona *and* is
  core-shaped → in scope.
- Improves a metric *and* serves the target persona *and* is
  app-shaped → goes to an app (the CLI, initially).
- Improves a metric *and* serves a non-primary persona →
  requires positioning-level evidence before shipping.
- Does not improve a metric → out of scope unless it closes
  drift or documentation gaps (the existing carve-out in
  `metrics.md`'s enforcement section).

The three documents are co-equal constraints. They share an
evidence base (the Aikido 2026 survey, plus adjacent research
informally consulted) but each governs a different axis of
proposal scope. When two documents pull in different directions,
the conflict is the signal — resolve it explicitly in the
proposal rather than picking the more permissive interpretation.

## Enforcement

Every iteration prompt that proposes new work references this
document alongside `metrics.md` and `positioning.md`. The
proposal states whether the work is core or app, and if core,
which market-validated problem it serves.

If a proposal adds app-shaped functionality to core, it is out
of scope unless the justification per the scope-expansion rule
is explicit. "Stated up front, not retrofitted after pushback"
applies here as it does in `positioning.md`.

If a proposal adds a new core primitive, it cites which
validated market problem requires the primitive. If no existing
problem requires it, the primitive is speculative and deferred
until evidence emerges. The same evidence-shifting test that
governs persona expansion in `positioning.md` governs primitive
expansion here.

If a proposal conflicts with an architectural decision —
introducing cloud-provider-specific optimization that breaks
vendor-agnosticism, adding AI inference to evaluation, requiring
cloud credentials for operation, or any other reversal of the
commitments enumerated in *Architectural decisions* — it cites
the validated market problem the reversal serves and the
evidence the original commitment no longer holds. Feature
rationale alone does not clear this bar.

The document is living. Market research surfacing new validated
problems can expand the primitive set. Core refactoring can
extract app-shaped functionality into apps. Changes are tracked
here, not assumed in commits or proposals. Informal additions to
the platform set — mentioned in commits, slacked around, assumed
in subsequent proposals — do not bind.
