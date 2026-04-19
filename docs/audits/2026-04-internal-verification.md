# Internal Verification — Output Model + Architecture

**Date**: 2026-04-19

## What this evaluates

Whether Stave's bottom-up implementation meets the top-down
design captured across three constraint documents
(`docs/product/metrics.md`, `docs/product/positioning.md`,
`docs/product/architecture.md`). Three layers of verification:

1. **Per-metric assessment** — does the output deliver the six
   output-model metrics in practice?
2. **Architectural-decisions verification** — do the nine
   architectural commitments in `architecture.md` hold in
   actual runs?
3. **Primitive-sufficiency assessment** — could an app built on
   Stave's primitives compose answers to the top-four market
   questions?

This is internal verification: implementation against design.
It does **not** verify product-market fit. PMF requires
external deployment and user observation; both are out of
scope for this iteration. A bottom-up implementation that
matches its top-down design can still be the wrong design;
this audit cannot detect that.

## What this does not evaluate

- **Product-market fit.** The audit verifies Stave delivers
  what the documents promise. Whether users want what the
  documents promise is a separate question requiring external
  deployment and user observation.
- Catalog completeness or breadth (separate audits exist
  per-domain — see `docs/audits/2026-04-ssrf-imds-s3-coverage.md`)
- Contract hygiene
- UI/UX surfaces beyond default text, JSON, SARIF
- Performance against asset counts beyond the 4-bucket fixture
- Acknowledgment / exemption / SLA-escalation flows

## Snapshot

`testdata/e2e/e2e-disclosure-lordofheaven-2025/observations/` —
4 S3 buckets across 2 timestamps (2025-07-15, 2025-07-23).
Three writable, one hardened. Real disclosed incident.

Two runs against the same observations:

1. **Bundled-controls run** (3 controls): replays the
   documented incident.
2. **Full-catalog run** (656 controls / 44 domains): how a
   prospect would invoke Stave.

Both runs deterministic via `--now 2026-01-11T00:00:00Z`.
Captured outputs at `/tmp/output-eval/{bundled,full}.{text,json,sarif}`.

The same snapshot was used for the prior audit
(`docs/audits/2026-04-output-model-evaluation.md`, commit
`52b417106`). That audit covers per-metric depth; this audit
references it where appropriate and focuses on the new
architectural-decisions and primitive-sufficiency layers.

A live-account snapshot would surface real-vs-synthetic
distribution gaps but is not available in this iteration.

## Per-metric assessment

For per-metric depth, see the prior audit at commit
`52b417106`. Findings restated here in compressed form so the
queue at the end of this document stands on its own; the
prior audit's per-metric What-works / What-falls-short detail
remains the authoritative reading.

### Metric 1 — Prioritization — REFINEMENT (with blocking-adjacent noise)

Top-9 by score is correctly ordered: writable-bucket
PUBLIC.001/003 at 400, PUBLIC.LIST.001 at 300. Score
breakdown formula visible inline. **Catalog noise inflates
the count: 24 of 78 findings (31%) fire from controls that
should not match S3 buckets** (`CTL.ELB.INCOMPLETE.001`,
`CTL.ROUTE53.INCOMPLETE.001`, etc., predicates use `op:
missing` on fields the asset type doesn't carry). Three
writable buckets all score identical 400 — no inter-asset
differentiation.

### Metric 2 — Deduplication — REFINEMENT

78 → 42 Issues. Top 3 Issues genuinely consolidate (5
findings each per writable bucket). **23 of 42 Issues are
singletons** that add surface area instead of reducing it.
Same-control entries within an Issue (4× `CTL.S3.PUBLIC.PREFIX.001`)
lack differentiators in the Issue summary.

### Metric 3 — Traceability — REFINEMENT

Every finding carries finding_id (sha256), control_id,
reasoning_trace, score_breakdown, evidence block. Source-
file/line attribution missing because the lordofheaven
observations carry no `source_ref` (extractor-side gap, not
output-model gap). `policy_fingerprint` empty in human-
readable form.

### Metric 4 — Remediation data quality — REFINEMENT-toward-BLOCKING

`remediation_context` exists with the right shape. **Three
data-quality bugs**: (1) `current_value: "[SANITIZED]"` for
boolean fields strips the entire signal; (2) `description:
"Set storage.access.public_read to "` (trailing space, no
value); (3) `command:` field carries prose instead of a
parameterized CLI command, contradicting the field name's
implication.

### Metric 5 — Self-explaining output — BLOCKING-adjacent

Translation present per finding. **"must equal X, but is X"
reads as a contradiction**. Gate clauses leak alongside
violation clauses with no structural distinction
(`storage.kind must equal "bucket", but is "bucket"`,
`the load balancer uses TLS 1.2 or higher must be missing
(and is)` on an S3 asset). The structural claim is met; the
practical effect undermines clarity.

### Metric 6 — Single source of truth / cross-tool posture — REFINEMENT

Coverage posture works: 20/21 Prowler S3, 44/47 Prowler IAM
in the full-catalog run. Per-finding `Alternative:` lines
appear correctly. **Bundled-controls run shows 0/47 IAM
because the fixture controls don't carry annotations** —
output reads as "Stave is empty" instead of "this controls
dir has no annotations." Coverage posture also reports
inventory totals for tools whose checks aren't in scope for
the run's observations.

## Architectural-decisions verification

Nine decisions in `architecture.md`. Each verified against
the captured outputs (full-catalog run unless otherwise
noted).

### Vendor-agnostic core — HOLDS

The output's `asset_vendor` field carries the string `aws`
in this run because the snapshot is AWS-only. The field is
opaque to core; nothing in the JSON envelope or SARIF wire
shape presumes AWS. The catalog includes 46 domains; non-AWS
ones include `gcs/`, `dns/`, `cisco/`, `vsphere/`, `k8s/`
(verified by listing `controls/`). GCS controls use
`vendor: gcp` in their fixtures. The asset-type field
(`aws_s3_bucket` here) is also opaque. Core treats vendor
strings the same way it treats tool names in alternatives:
opaque identifiers passed through.

A test against a non-AWS snapshot would be the strongest
verification; this audit confirms the structural shape
permits other providers.

### Standard export formats — HOLDS

JSON validates against `schemas/output/v1/output.schema.json`
(verified via `jsonschema.validate`). SARIF declares
`version: 2.1.0` and the OASIS schema URL; `runs[0]` shape
matches SARIF spec. Text output is grep-friendly with
section headers and consistent indentation. A downstream
consumer parsing JSON or SARIF needs no Stave-specific
knowledge; both wire formats are public standards or
documented schemas.

### Alternatives annotations and coverage posture — HOLDS

Findings carry per-finding `alternatives` arrays (sample:
`prowler/s3_bucket_public_access (covered)` with note
explaining the split). Coverage posture surfaces in JSON
(`coverage_posture.prowler.{s3,iam}.{covered,total,not_covered_checks}`)
and text (`prowler / s3: 20 of 21 checks covered`). A
consolidation-decision app could read these primitives
without bespoke parsing.

The framing gap from the prior audit (bundled-controls run
showing 0/47 reads as "Stave covers nothing") affects user-
facing interpretation, not the architectural decision —
the data is correct.

### Deterministic evaluation — HOLDS

Two consecutive `stave apply` runs against the same
observations with `--now 2026-01-11T00:00:00Z` produce
byte-identical JSON output and byte-identical text output
(verified via `diff -q`; both diffs exit 0). No
probabilistic inference anywhere in the pipeline. Output is
a pure function of (controls, observations, run config).

### AI-ready output — PARTIAL

`remediation_context` exists per-finding with structured
sub-fields (`asset`, `violation`, `changes`, `command`).
Composing a plausible AI prompt from one finding's
context:

> Asset gov-writable-bucket-1 (aws_s3_bucket) violates
> CTL.S3.PUBLIC.001: No Public S3 Bucket Read.
> Severity: critical.
> Reasoning: the bucket allows anonymous read must equal
> true, but is true (observed key:
> storage.access.public_read = True).
> Required action: Enable S3 Public Access Block (all four
> settings). Remove any bucket policy statements granting
> access to Principal "*". ...
> Property changes: storage.access.public_read
> (current=[SANITIZED])

The prompt is structurally coherent — an AI consumer can
parse the shape and produce a fix suggestion. **Two
problems** that downgrade this from HOLDS to PARTIAL:

- The reasoning clause embedded as text reads "must equal
  true, but is true" — the AI consumer inherits the M5
  contradiction-shape problem.
- `current_value: "[SANITIZED]"` strips boolean signal the
  AI needs to confirm "yes, change `true` to `false`."

The architectural decision (output shaped for AI
consumption) holds; the field contents undermine the
delivered value.

### Inspectable reasoning — HOLDS

`reasoning_trace` field present on every finding with
matched predicate clauses, observation keys, observed
values. A reader can verify why a finding fired from the
output alone — the trace is self-contained, doesn't require
re-running stave or accessing the control YAML.

The same M5 contradiction-shape problem affects readability
of the rendered text; the trace data itself is complete.
Inspectability (the architectural decision) is delivered
even where rendering quality (the output-model metric) is
not.

### Extended ontology mechanism — HOLDS

The alternatives-block + inventory-file pattern is
documented in `architecture.md`'s Primitive shapes section
and exercised by `data/alternatives/prowler-{s3,iam}.yaml`.
Adding a new external tool is a data-only change; core
contains zero references to specific tool names (verified
in step 4 of the architecture-foundation iteration).

The mechanism is documented and accessible; it has been
exercised once (Prowler) so far. Wider use would
strengthen the verification.

### Credential-free operation — HOLDS

Apply ran against local snapshot files only. No
`AWS_*` environment variables set; no `aws.config`
imports in `cmd/apply/` or `internal/adapters/observations/`
(verified via grep). Stave evaluates what the extractor
captured; the cloud connection is the extractor's
responsibility, not Stave core's.

### Summary

| Decision | Status |
|---|---|
| Vendor-agnostic core | HOLDS |
| Standard export formats | HOLDS |
| Alternatives + coverage posture | HOLDS |
| Deterministic evaluation | HOLDS |
| AI-ready output | PARTIAL |
| Inspectable reasoning | HOLDS |
| Extended ontology mechanism | HOLDS |
| Credential-free operation | HOLDS |

Eight of nine HOLD; one is PARTIAL because of two specific
field-contents bugs (M4 / M5 cross-cutting effects). No
decision is VIOLATED. Architectural drift is not yet a
concern.

## Primitive-sufficiency assessment

Could an app built on Stave's primitives compose answers
to the top-four market questions surfaced in
`architecture.md`?

### Tool sprawl — SUFFICIENT

A consolidation-advisor app could compose:

- "Stave covers 20 of 21 Prowler S3 checks for this
  catalog" — from `coverage_posture.prowler.s3`.
- "Stave covers 44 of 47 Prowler IAM checks" — same
  source.
- "These specific Prowler checks are not yet covered:
  `s3_bucket_event_notifications_enabled`" — from
  `coverage_posture.prowler.s3.not_covered_checks`.
- "If you keep Stave, you can drop Prowler's S3 and IAM
  domains except for those 4 checks" — derived from the
  above.

Per-finding `alternatives` arrays let the same app
attribute each Stave finding to the equivalent Prowler
check name. SUFFICIENT. The framing gap (bundled-run
showing 0/47) is a presentation issue, not a primitive
gap.

### Cloud as attack surface — PARTIAL

A surface-mapper app could compose:

- "Asset X has Y findings, ranked by exposure score" —
  from per-asset Issues consolidation + Critical-Path
  Exposures top-N.
- Score breakdown shows the multiplicative factors.
- Per-asset grouping is accessible via
  `findings[].asset_id` and `issues[].asset_id`.

**Two gaps** that knock this from SUFFICIENT to PARTIAL:

- Catalog noise (M1's 31% noise rate) corrupts the
  surface: an app would list 78 findings when ~54 are
  the actual surface. Filtering needs scope_tags
  awareness the primitives don't currently surface
  cleanly.
- No inter-asset differentiation: three identically-
  configured buckets all score 400. An attack-surface
  app that wants to rank assets ("which bucket should
  I fix first?") has no input beyond "they're all
  equally bad." Score doesn't differentiate by data
  classification, blast radius across assets, or
  business criticality — none of those are observable
  in the current contract.

### Credential theft — PARTIAL

The lordofheaven snapshot has no IAM observations, so
this assessment is based on catalog primitives, not
observed run data.

The IAM control catalog under `controls/iam/` is broad:
24 escalation controls, root-account controls, MFA
controls, credential-rotation controls, federation
controls. Each carries reasoning_trace and remediation
data shaped the same as S3 controls. An app could
compose:

- "Here are credential-exposure findings, ordered by
  severity" — from finding emission.
- "This IAM principal can escalate via these N
  techniques" — from per-technique escalation controls.
- "Remediation: detach this policy, narrow this trust
  relationship" — from remediation_context.

**Gap**: cross-resource derivation absent. The SSRF audit
at `docs/audits/2026-04-ssrf-imds-s3-coverage.md`
documents this: Stave can't currently say "the EC2
instance role reachable via IMDS is in the KMS key's
allowed-decrypt principal list for this bucket's key."
The credential-theft story is per-control, not
cross-resource. PARTIAL.

### Misconfiguration — PARTIAL

A misconfig-explainer app could compose:

- "Bucket X has these misconfigurations" — Issues block.
- "Why each is a problem" — control description +
  reasoning_trace.
- "How to fix" — remediation block + remediation_context.

**Gaps** that knock this from SUFFICIENT to PARTIAL:

- M5 contradiction-shape rendering: the "why" is
  technically present but reads worse than the raw
  predicate would.
- M4 data-quality bugs: the "how" carries the prose
  Action in the `command` field (consumers expecting
  CLI commands get prose instead) and the `current_value`
  is sanitized for booleans (consumers don't see the
  state).
- Catalog noise: the misconfig-explainer would surface
  ELB/Route53 controls firing on S3 assets with no way
  to tell those apart from real misconfigurations
  without inspecting each reasoning trace.

### Summary

| Market question | Status |
|---|---|
| Tool sprawl | SUFFICIENT |
| Cloud as attack surface | PARTIAL |
| Credential theft | PARTIAL |
| Misconfiguration | PARTIAL |

The strongest primitive-sufficiency case is tool-sprawl,
which the alternatives + coverage-posture work directly
targeted in the most recent iteration. The other three
inherit the M1 noise problem and the M4/M5
field-quality issues as primitive-level constraints on
what apps can build downstream.

## Cross-metric and cross-layer observations

### Catalog noise cascades through metrics, decisions, and primitives

The 31% noise rate observed in M1 affects:

- M1 (prioritization) — inflates count
- M2 (deduplication) — generates singleton Issues
- M3 (traceability) — noise findings carry full trace
  metadata, indistinguishable in shape
- M5 (self-explaining) — exposes the gate-clause leak
- AI-ready output (architectural decision, partial) —
  AI consumers receive noise-finding contexts
- Cloud-attack-surface primitive sufficiency (partial) —
  surface-mapper apps must filter or accept noise
- Misconfiguration primitive sufficiency (partial) —
  misconfig-explainer apps face the same problem

A single architectural mechanism (asset-type-scoped
control selection at evaluation time) would close the
issue across all six layers. This is the highest-
leverage refinement in the queue.

### M4/M5 contradiction shape is a single fix touching multiple layers

"must equal X, but is X" appears in:

- Inline Reasoning text (M5)
- `remediation_context.violation.reasoning[].clause` (M4)
- AI-ready output (architectural decision, partial) — AI
  consumers receive the contradiction-shape text
- Misconfiguration primitive sufficiency (partial) —
  misconfig-explainer downstream

One fix in the translation layer improves M4, M5, the
AI-ready architectural decision, and misconfiguration
primitive sufficiency simultaneously. Second-highest-
leverage refinement.

### Coverage posture's framing problem affects only the user-facing layer

The "0/47 IAM" reading in the bundled-controls run is a
presentation issue, not a primitive shortfall. Apps
consuming `coverage_posture` directly read accurate
counts; only the text writer's rendering frames
unintuitively. This is a writer-layer fix, not a
primitive-layer one.

### Architectural decisions reinforce each other in the strong cases

Determinism + standard exports + inspectable reasoning
together mean the JSON envelope is a stable, parseable,
verifiable artifact. An AI consumer that reads it once
gets the same result as an audit consumer that reads it
later. The combination is more than the sum: each alone
would be useful; together they make Stave's output the
"reliable input" the AI-ready decision targets.

### Determinism enables but does not guarantee usefulness

Byte-identical output between runs is a strong
correctness property. It is also the floor: the same
output that is byte-identical can still be wrong (the
catalog noise produces deterministically wrong
findings). Determinism enables verification; it does
not produce verification-worthy content.

## Differentiation-claim assessment

The seven promises restated, with delivery state from
this run:

| Promise | Delivers? |
|---|---|
| Reduce triage time to zero | **Partial.** Issues consolidates 78→42; 23 are singletons. Critical-Path top-9 is the fastest front door. Catalog noise (24 of 78) inflates triage cost. |
| Reduce false positives to zero | **Fails.** 31% noise rate from controls firing on assets they don't apply to. Indistinguishable in shape from real findings. |
| Provide reasoning for prioritization | **Delivers.** Score breakdown formula shown inline per finding. Verifiable. |
| Provide reasoning for flagging | **Partial.** Reasoning trace exists per finding. M5 contradiction-shape and gate-clause leakage degrade legibility. |
| Provide actionable remediation | **Partial.** Action prose is concrete; `changes[]` enumerates property paths. The advertised parameterized `command` field carries prose; sanitizer strips current values. |
| Play well with other tools | **Delivers.** SARIF taxa via properties bag; JSON envelope validates against schema; coverage posture surfaces cross-tool dedup story. |
| Preserve inspectability over AI tools | **Delivers.** Every finding carries finding_id, reasoning trace, score breakdown — full provenance, no opaque scores. |

Same scorecard as the prior audit (per-metric findings
unchanged across the day). Three deliver, three partial,
one fails. The fully-delivered three are downstream-
machine-consumption (SARIF, JSON, alternatives) and
inspectability (provenance, no opaque ML scores). The
partials and the failure are the human-reading surfaces.
**Stave is strong where machines consume the output and
weak where humans do.**

The architectural decisions reinforce the strong half.
The metric/primitive gaps live in the weak half. The
refinement queue follows.

## Resolution log

**2026-04-19** — Item 1 (asset-type scoping) resolved.
A new `applicable_asset_types` field on control YAMLs
gates evaluation by asset type before predicate
evaluation. Six noise-causing controls migrated
(`CTL.{ELB,ROUTE53,AUTOSCALING,CLOUDFORMATION,GUARDDUTY,SECURITYHUB}.INCOMPLETE.001`).
Re-running apply against the LordofHeaven snapshot
produced 54 findings (down from 78), all S3-domain.
Identity-set check confirms 24 unique finding_ids
removed across the six expected domains, zero added.
Architectural decisions unchanged: silent-skip
preserves inspectable reasoning (gated controls are
absent from output the same way they would be if
absent from the catalog). The exit condition the audit
named is met exactly.

## Prioritized refinement queue

Ordered by (1) blocking gaps first, (2) architectural
fixes before feature refinements, (3) evidence-grounded
over speculative, (4) leverage-weighted across metrics
+ decisions + primitives.

1. ~~**Asset-type scoping at evaluation time.**~~
   **RESOLVED** (see Resolution log above). Original
   text retained for historical reference: "Suppress
   controls whose `scope_tags` or asset-type gates
   don't match the asset. Closes the 31% noise
   observed in M1, M2, M3, M5. Improves
   cloud-attack-surface and misconfiguration primitive
   sufficiency. Touches the AI-ready architectural
   decision (cleaner inputs to AI consumers). Highest
   leverage. Evidence: 24 of 78 findings cross-tabbed
   by `(domain, asset_type)`."

2. **Reasoning-trace wording fix.** Replace "must equal
   X, but is X" with non-contradictory phrasing.
   Distinguish gate clauses from violation clauses
   (separate `gates[]` from `violations[]`; render only
   violation clauses inline). Improves M4, M5, AI-ready
   architectural decision, misconfiguration primitive
   sufficiency. Second-highest leverage; one fix, four
   layers.

3. **Per-field sanitization policy.** Sanitize
   identifiers and strings; preserve booleans,
   enumerated values, numeric ranges. Closes the
   `current_value: "[SANITIZED]"` data-loss in M4
   and the AI-ready architectural decision's
   downgrade-to-PARTIAL. Single layer, single
   refinement.

4. **`command` field carries a parameterized command.**
   Either rename to `action` (matching the YAML field)
   or populate with a real shell command using the
   asset identifier. Closes M4 expectation-mismatch.
   Improves AI-ready primitive (consumers expecting
   CLI commands get them).

5. **Issues block: suppress singletons by default.**
   When an Issue groups one finding, it adds no
   consolidation value. Show only N≥2 Issues.
   Reduces clutter. Improves M2.

6. **Issues block: differentiate same-control entries.**
   When `CTL.X.001` appears 4× under one Issue, render
   the differentiator (parameter, evidence key) per
   entry. Improves M2.

7. **Coverage posture: distinguish "no annotations"
   from "no coverage."** Add a one-line preamble
   stating how many loaded controls carry alternatives
   annotations. Improves M6 framing without changing
   the underlying data.

8. **Coverage posture: scope to applicable
   observations.** Posture should reflect what could
   have run against the run's observations, not what
   the catalog declares globally. Improves M6 +
   tool-sprawl primitive sufficiency.

9. **Inter-asset score differentiation.** Either via
   contract extension (data classification, business
   criticality) or via blast-radius asset-graph
   composition. Closes the cloud-attack-surface
   primitive PARTIAL. Larger scope; defer until 1–4
   land.

10. **Cross-resource derivation for credential
    theft.** Per the SSRF audit's KMS-join gap:
    derivations like "EC2 role → IMDS → KMS key →
    bucket" need a contract-level join mechanism.
    Closes the credential-theft primitive PARTIAL.
    Largest scope in the queue; clear future
    direction.

Items 1–4 are highest leverage (each touches multiple
layers). Items 5–8 are layer-local refinements. Items
9–10 are larger scope and depend on contract or
extractor work.

## Honesty notes

Per the prompt: "if the evaluation surfaces that a
metric's claimed delivery is actually broken rather
than refinement-needed, flag it explicitly."

- **Metric 5 self-explaining output is structurally
  present but practically counterproductive.** The
  contradiction-shape rendering and gate-clause
  leakage make inline Reasoning harder to read than
  the raw predicate would be. Marking M5 as
  PARTIAL-moving-toward-CLOSED is honest about the
  structural claim and dishonest about the user-
  facing effect.

- **Metric 4 `command` field name advertises content
  the field doesn't carry.** A consumer integrating
  against the JSON envelope reasonably expects
  `findings[].remediation_context.command` to be a
  shell command. It carries prose. Structurally
  delivered, contractually misleading.

- **AI-ready architectural decision is PARTIAL, not
  HOLDS, because of M4/M5 cross-cutting effects.**
  The architectural shape is right; the field
  contents undermine downstream usefulness. This is
  the only architectural decision that does not fully
  hold. Worth flagging because architectural drift is
  harder to reverse than feature drift; the
  contributing M4/M5 fixes (queue items 2, 3, 4) lift
  the architectural decision back to HOLDS.

- **Cloud-attack-surface and misconfiguration
  primitives are PARTIAL because of the same noise
  + reasoning issues.** The architectural choice to
  build apps on top of core primitives is sound, but
  the primitives currently leak noise and degraded
  reasoning into every consumer. The first two queue
  items lift both PARTIAL ratings simultaneously.

- **Tool-sprawl is the only top-four market question
  Stave currently answers SUFFICIENT.** This is also
  the most recently delivered iteration. The pattern
  suggests primitive-sufficiency is achievable per
  market question with focused work; the other three
  need the corresponding focused iteration cycles.

These notes are not metric-target updates. The audit's
job is verification; updating `metrics.md`,
`positioning.md`, or `architecture.md` to reflect what
this audit surfaces is a separate iteration's work, if
warranted.

## Explicit non-scope (restated)

This is internal verification only. The audit
demonstrates that Stave delivers (or does not deliver)
what its design documents promise. It cannot
demonstrate that the design itself is what users want.
Verification of product-market fit requires:

- External deployment to real users with cloud
  environments
- Observation of which output sections users read,
  which they ignore, which they integrate downstream
- Measurement of whether the output replaces or
  supplements existing tools in users' actual
  workflows
- Evidence that the persona positioning.md targets
  exists in sufficient numbers to constitute a market

None of these are answerable from a fixture-replay
audit. A future iteration that captures user-
observation evidence would be the right place to
test fit; until then, this audit is the floor (does
the implementation match the design) and PMF
verification is the deferred ceiling.
