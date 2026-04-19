# Output Model Evaluation — Lordofheaven 2025 Replay

**Date**: 2026-04-19

## What this evaluates

Whether the seven completed output-model iterations
(prioritization, traceability, deduplication, self-explaining
output, remediation data quality, cross-tool posture, plus the
golden-regeneration tooling) actually deliver the differentiation
the Aikido 2026 survey motivated, when measured against `stave
apply` output run on a real disclosed incident.

The metrics in `docs/product/metrics.md` track structural delivery
(does the field exist, does the section render). This document
measures whether the rendered output meets the bar a prospect would
set: would they see the differentiation, or would they see another
alert-generating tool?

The evaluation runs Stave against the lordofheaven 2025 disclosure
fixture under two conditions: (1) the fixture's bundled 3-control
slice (replays the documented incident faithfully), and (2) the
full embedded catalog (656 controls across 44 domains —
representative of how a prospect would invoke Stave). Differences
between the two are catalog-breadth artifacts, not output-model
gaps; both are reported so the distinction stays visible.

Outputs captured to `/tmp/output-eval/{bundled,full}.{text,json,sarif}`
during evaluation.

## What this does not evaluate

- Catalog completeness / breadth (a separate concern; see existing
  hipaa-coverage and ssrf-coverage audits)
- Contract hygiene (extractor obligations, observation schema
  drift)
- UI/UX surfaces beyond default text, JSON, SARIF outputs
- Performance or scalability against asset counts beyond the
  4-bucket fixture
- Acknowledgment / exemption / SLA-escalation flows (fixture does
  not exercise them)

## Snapshot

`testdata/e2e/e2e-disclosure-lordofheaven-2025/observations/` —
4 S3 buckets across 2 timestamps (2025-07-15 and 2025-07-23). Three
buckets carry `public_read=true, public_list=true,
public_write=true`; one is hardened. Real disclosed incident,
representative of an extractor's output against a small set of
buckets.

Run command (full-catalog form):

```
./stave apply \
  --controls controls \
  --observations testdata/e2e/e2e-disclosure-lordofheaven-2025/observations \
  --max-unsafe 168h --now 2026-01-11T00:00:00Z \
  --allow-unknown-input --format text
```

Bundled-controls run substitutes `--controls
testdata/e2e/e2e-disclosure-lordofheaven-2025/controls`. Both runs
use deterministic `--now` for reproducibility.

## Per-metric assessment

### Metric 1 — Prioritization

**What the output shows.** Full-catalog run produces 78 findings.
The Critical-Path Exposures section caps display at 10; only 9
appear. Top 6 entries are `CTL.S3.PUBLIC.001` and
`CTL.S3.PUBLIC.003` against the three writable buckets, all scoring
400.0 with identical breakdowns (`base=100 × duration=2.0 ×
blast=1.0 × exposure=2.0 × chain=1.0`). Items 7–9 are
`CTL.S3.PUBLIC.LIST.001` against the same three buckets at score
300.0.

**Against target.** The metric's Target says output should put the
most attention-worthy finding first. For the writable-buckets
incident, the public-read and public-write findings ranking at the
top is correct.

**What works.** Score breakdown formula is shown inline (`base ×
duration × blast × exposure × chain`) — readers see how the score
was produced, can reason about weights, and can verify the formula
against the metrics document. The cap at 10 keeps the section
scannable.

**What falls short.**

- **Catalog noise inflates the violation count.** A cross-tab of
  `(control_domain, asset_type)` reveals 24 of 78 findings (31%)
  fire from controls that should not match S3 bucket assets at
  all: `CTL.ELB.INCOMPLETE.001`, `CTL.ROUTE53.INCOMPLETE.001`,
  `CTL.AUTOSCALING.INCOMPLETE.001`, `CTL.CLOUDFORMATION.INCOMPLETE.001`,
  `CTL.GUARDDUTY.INCOMPLETE.001`, `CTL.SECURITYHUB.INCOMPLETE.001`
  — 4 each, one per asset. Their predicates use `op: missing` on
  fields like `loadbalancer.encryption.tls_1_2_or_higher` or
  `dns_service.health_checks_configured`; an S3 bucket has no
  load-balancer or DNS-service field, so the `missing` clause
  trivially matches. These findings score 20–50 and rank at the
  bottom, but they're present in the count, present in the
  Issues consolidation, and present in the per-finding list. A
  prospect skimming the headline "78 violations" gets a 31%
  noise impression before reading the ordering.

- **No inter-asset score differentiation.** Three writable
  buckets all score 400.0 with identical breakdowns. The score
  formula has no signal that distinguishes
  `gov-writable-bucket-1` from `gov-writable-bucket-2` — they
  carry the same configuration, so the same score is correct,
  but the output gives a reader no hint about which to address
  first. In practice asset business-criticality, data
  classification, or blast-radius differ between buckets; the
  current model surfaces no such input.

**Severity.** REFINEMENT for ordering itself; the legitimate
findings rank correctly. BLOCKING-adjacent for the 31% noise
inflation — a prospect comparing Stave to Prowler / ScoutSuite
would see "Stave produces more findings per asset" and read it as
noisier, not deeper. The catalog-scope problem is technically a
control-authoring issue (those `*.INCOMPLETE.001` controls lack
proper `scope_tags` / asset-type gates), but it surfaces in the
output and the output model offers no filter.

### Metric 2 — Deduplication

**What the output shows.** 78 findings consolidate into 42 Issues.
The top three Issues each group 5 findings on a writable bucket
(PUBLIC.001 + PUBLIC.003 + PUBLIC.LIST.001 + PUBLIC.LIST.002 +
GOVERNANCE.001) under the same shared root-cause keys
(`storage.access.public_read`, `storage.access.public_write`,
etc.). Items 4–5 group 1 and 4 findings against the hardened
bucket. Items 6–17 group 2–4 findings each. Items 20–42 are
single-finding "Issues."

**Against target.** Metric 2's Target says "consolidated Issues
view ahead of the per-finding list." Issues do appear ahead of
findings, and the top entries deliver real consolidation (3
writable buckets reduced from 5 findings each to 1 Issue each).

**What works.** The 5→1 collapse on writable buckets is exactly
the dedup the metric promises: a triager sees one Issue per
bucket, not five separate findings to investigate. Shared-key
display surfaces the common root-cause fields, which lets the
reader confirm "yes, these all chain off one configuration."

**What falls short.**

- **Singleton-dominated Issues list.** 23 of 42 Issues (55%) are
  single-finding entries. The Issues abstraction was designed to
  reduce surface area; in this output it inflates surface area
  because the section lists these singletons in addition to the
  per-finding view below. The writer's existing `anyMulti` gate
  suppresses the entire Issues block only when *all* Issues are
  singletons; mixed cases like this one render every singleton
  alongside the genuine consolidations. Cluttered.

- **Per-finding distinction within an Issue is invisible.** Issue
  #5 (gov-hardened-bucket) lists `CTL.S3.PUBLIC.PREFIX.001` four
  times under "Members:" with no differentiator between the
  entries. Each represents a distinct prefix
  (`backups/`, etc., per the per-finding view below) but the
  Issue summary shows `CTL.S3.PUBLIC.PREFIX.001` four times
  identically. A reader has to scroll to the per-finding section
  to learn what the 4 entries actually are.

- **Issues do not deduplicate noise findings.** The 24 noise
  findings from M1 each generate a singleton Issue. Issues
  consolidation cannot rescue findings that should not exist in
  the first place.

**Severity.** REFINEMENT. The genuine consolidation is real and
useful; the singleton-clutter and missing-differentiator problems
are clear refinement opportunities, not blocking gaps.

### Metric 3 — Traceability

**What the output shows.** Every finding carries: `finding_id`
(stable sha256), `control_id`, `control_name`, `asset_id`,
`evidence` block (first-unsafe / last-seen timestamps, duration,
threshold), `reasoning_trace` (matched predicate clauses),
`remediation` (description + action), `score_breakdown` (factors).
JSON envelope adds `policy_fingerprint` (empty in this run, see
below), `coverage_posture`, and `extensions` with project context
and git metadata.

**Against target.** The metric's Target promises every finding
traces back to its predicate, control file, and observation
inputs. The reasoning trace + control_id + finding_id satisfy the
predicate / control half. Observation traceability is partial: the
`Source: file:line` line per finding (referenced in
`finding_writer.go:243` writer code) does not appear in this run's
output, suggesting the lordofheaven observations carry no
`source_ref` field.

**What works.** Every finding has a stable, deterministic
finding_id. The reasoning trace lists the matched predicate
clauses with observation_key and observed_value, in JSON. Run
metadata captures the git commit, project root, and resolved input
paths under `extensions.git` and `extensions.resolved_paths`.

**What falls short.**

- **Source line attribution missing.** The lordofheaven
  observations have no `source_ref` annotations, so the per-
  finding `Source:` line is empty across all 78 findings. This
  isn't an output-model bug — the writer correctly hides the
  line when source is absent — but the most concrete trace
  ("which Terraform file produced this asset state") is silent.
  The metric's Target talks about source traceability; the
  output delivers it conditionally on extractor output, which
  the fixture doesn't carry.

- **`policy_fingerprint` is empty in the run output.** JSON shows
  `extensions.context_name: "stave"` but no fingerprint hash
  rendering for the policy bundle in human-readable form. The
  fingerprint exists on the data structure (controls have a
  `Fingerprint` method) but the apply output renders nothing
  visible.

- **Finding ID is not human-quotable.** `sha256:6d62411519f8c956`
  is stable but not memorable. A triager wanting to reference
  "the third bucket-1 finding" in chat or a ticket has no
  shorter alternative; the per-finding numbered list (1, 2, 3
  …) is local to one apply invocation and not stable across
  runs. This is intrinsic to content-addressing and probably
  unavoidable, but worth naming as a friction point.

**Severity.** REFINEMENT. The structural plumbing is in place;
extractor output and fingerprint surfacing are the limiting
factors.

### Metric 4 — Remediation data quality

**What the output shows.** Each finding renders a Remediation
block: a description sentence and an Action line. The Action text
is the raw template from the control YAML (e.g., "Enable S3
Public Access Block (all four settings). Remove any bucket policy
statements granting access to Principal \"*\". Remove any ACL
grants to AllUsers or AuthenticatedUsers."). JSON adds
`remediation_context` with `asset`, `violation`, `changes`, and
`command` fields.

**Against target.** Metric 4's Target says output should provide
asset-parameterized commands an operator can paste into a shell.
What the output actually provides is prose action text and a
`changes` array with the property paths to modify.

**What works.** The Action text is concrete and operationally
sound — a reader knows what to do. The `changes` array enumerates
the property paths a fix would touch. The structured shape
(`asset` / `violation` / `changes` / `command`) is suitable input
for an AI prompt template, per the metric's downstream-consumer
goal.

**What falls short.**

- **`current_value: "[SANITIZED]"` strips the most useful info
  for boolean fields.** For `storage.access.public_read`, the
  actual current value is `true`. Sanitization replaces it with
  the placeholder, leaving the operator with no indication
  whether the field is currently true or false — for a Boolean,
  that's the whole signal. Sanitization is appropriate for
  identifiers (bucket names, ARNs); applying it indiscriminately
  to boolean property values destroys the data.

- **`description: "Set storage.access.public_read to "` (trailing
  space, no value).** The required value is missing from the
  description string. This is a data-quality bug in the
  remediation_context builder: it concatenates "Set <path> to
  <required_value>" but `required_value` is empty, leaving the
  trailing space and no target value. An AI prompt or ticketing
  consumer fed this string sees an incomplete instruction.

- **`command:` field carries prose, not a shell command.** The
  metric's Target is "asset-parameterized CLI command"; what
  surfaces is the same Action text from the control YAML. A
  consumer expecting `aws s3api put-public-access-block --bucket
  gov-writable-bucket-1 ...` sees the prose action description
  instead. The `command` field name advertises a parameterized
  command; the content delivers prose. Expectation mismatch.

**Severity.** REFINEMENT-moving-toward-BLOCKING. The structural
shape is right (the `remediation_context` block exists, has the
right fields, surfaces in JSON and SARIF), but the contents fail
to deliver what the field names promise. A prospect inspecting
the JSON output expecting executable commands would be
disappointed.

### Metric 5 — Self-explaining output

**What the output shows.** Every finding renders a Reasoning
block with translated predicate clauses. Examples from this run:

```
Reasoning:
  the bucket allows anonymous read must equal true, but is true

Reasoning:
  BlockPublicAcls is enabled must equal false, but is false

Reasoning:
  the load balancer uses TLS 1.2 or higher must be missing (and is)

Reasoning:
  storage.kind must equal "bucket", but is "bucket"

Reasoning:
  the exposure source must equal "missing_evidence", but is "missing_evidence"
  the protected prefix must equal "backups/", but is "backups/"
```

**Against target.** Metric 5's Target says output should explain
violations in plain English, accessible to readers who don't know
the predicate DSL.

**What works.** The translation does happen — readers see English
phrases, not raw `field/op/value` triples. Field-name
translations like "the bucket allows anonymous read" (for
`storage.access.public_read`) and "all four Public Access Block
flags are enabled" surface meaningful concepts.

**What falls short.**

- **"must equal X, but is X" reads as a contradiction.** The
  Reasoning text describes the *unsafe state* — the predicate
  matched, so the value equals the unsafe value. The grammar
  ("must equal true, but is true") implies the value violates
  expectation; in fact it confirms expectation that the unsafe
  pattern is present. A reader fluent in security tooling will
  squint and parse it correctly; a reader new to Stave will
  read "must equal true, but is true" as a parser bug. The
  underlying clause structure (expected vs. observed) was
  designed for predicate evaluation; the writer renders it
  literally instead of inverting for the unsafe-match case.

- **Precondition / gate clauses leak into Reasoning.** Several
  reasoning lines describe predicate gates that are not
  violations: `storage.kind must equal "bucket", but is
  "bucket"` is the gate-clause that limits the predicate to
  bucket assets. `the load balancer uses TLS 1.2 or higher must
  be missing (and is)` is a similar gate via `op: missing` on a
  field that the asset type doesn't carry. `the protected
  prefix must equal "backups/", but is "backups/"` is the
  parameterized prefix this control is keyed on, not a
  violation. These gate clauses would be useful as "the
  predicate matched because" notes, but they're displayed
  alongside genuine unsafe-match clauses with no visual or
  structural distinction. A reader cannot tell which clause
  identifies the unsafe state.

- **Multi-clause `all:` predicates flatten without grouping.**
  Issue #35 shows two clauses both reading "must equal X, but
  is X" — one is the gate (`exposure_source = missing_evidence`)
  and one is the parameterized constraint (`protected_prefix =
  backups/`). Both render as identical-shape lines.

**Severity.** BLOCKING-adjacent. The translation is
*technically* present, satisfying the metric's structural claim,
but the rendered text undermines clarity rather than adding it.
A prospect comparing Stave's "self-explaining output" to a
competitor's "view raw rule" link would see Stave's output and
read it as a worse experience than just showing the predicate.
The metric is CLOSED-eligible only after the contradiction shape
is fixed and gate-vs-violation clauses are distinguished.

### Metric 6 — Single source of truth / cross-tool posture

**What the output shows.** Full-catalog run renders:

```
Coverage posture
----------------
  prowler / iam: 44 of 47 checks covered
  prowler / s3: 20 of 21 checks covered

  Not covered (prowler iam): iam_administrator_access_with_mfa, ...
  Not covered (prowler s3): s3_access_point_public_access_block, ...
```

Per-finding output adds `Alternative: prowler/s3_bucket_acl_prohibited
(covered)` lines under affected findings. JSON output carries
`coverage_posture` with full inventory difference. SARIF output
puts `properties.alternatives` on both rule descriptors and
results.

**Against target.** Metric 6's Target says control-level
`alternatives:` populated, finding-level annotations emitted,
apply-output coverage-posture section. All three are present.

**What works.** The coverage posture line for the full-catalog run
is informative: "20 of 21" is a concrete number a prospect can
compare to their existing Prowler dashboard. The per-finding
Alternative line lets a Prowler-using team find the matching
Stave control without reading separate docs. JSON and SARIF
expose the same data structurally.

**What falls short.**

- **Bundled-controls run shows misleading 0/47 IAM coverage.**
  The fixture's bundled `controls/` directory carries 3 S3
  controls without `alternatives:` blocks (the fixture predates
  the alternatives migration and was not updated). Output shows
  "prowler / iam: 0 of 47 checks covered" — accurate to input,
  misleading to read. A user running `stave apply --controls
  /my/controls` whose controls don't carry annotations sees
  "Stave covers 0 of 47" when in fact Stave has a canonical
  catalog that does cover 44 of 47. The coverage section reads
  like "Stave is empty" instead of "this controls dir has no
  annotations."

- **Per-domain coverage shown for tools whose checks aren't in
  scope.** The full-catalog run reports IAM coverage even though
  the lordofheaven observations contain no IAM principals — the
  inventory totals are reported regardless of which checks could
  have run against the observed assets. A reader sees "44 of 47
  IAM" and wonders where the IAM findings are; they aren't there
  because there were no IAM observations. The posture section
  conflates "checks covered by the catalog" with "checks
  applicable to this run." The metric's Target language ("for
  the scanned resource set") suggests the latter; the
  implementation delivers the former.

- **Coverage posture lists are static across runs.** The same
  21 not-covered checks appear regardless of what observations
  fed apply. This is correct given the implementation but means
  the posture section tells you about the catalog, not about
  this run.

**Severity.** REFINEMENT. The data is correct, the wire format is
right, the architecture is sound. The framing — "what does this
run tell me about coverage" vs. "what does the catalog tell me
about coverage" — needs sharpening.

## Cross-metric observations

### Catalog noise cascades through every metric

24 of 78 findings (31%) fire from controls whose predicates use
`op: missing` on fields the S3 bucket assets don't carry —
`CTL.ELB.INCOMPLETE.001`, `CTL.ROUTE53.INCOMPLETE.001`, and four
others. The cascade through metrics:

- **M1 (prioritization):** inflates the headline count
- **M2 (deduplication):** generates 24 singleton Issues
- **M3 (traceability):** each carries a finding_id and reasoning
  trace, indistinguishable in shape from genuine findings
- **M5 (self-explaining):** the reasoning lines surface the
  gate-clause leak ("the load balancer uses TLS 1.2 or higher
  must be missing (and is)")

The root cause is in the catalog (`*.INCOMPLETE.001` controls
lacking proper asset-type gates), not in the output model. But
the output model offers no defense: there's no asset-type filter
on which controls run against which assets, no display gate on
findings whose evidence is "the field is absent because the asset
type doesn't carry it." A future iteration that addresses any of
these metrics in isolation will improve the surface area
incrementally; an iteration that adds asset-type scoping at
evaluation time would improve all of them simultaneously.

### Issues consolidation and Critical-Path duplicate the same data

Issues block lists 42 entries. Critical-Path Exposures lists 9.
Per-finding Violations block lists all 78. The same writable-
bucket data is rendered three times: once consolidated by asset
(Issues), once ranked by score (Critical-Path), once enumerated
by control (Violations). Each is useful in isolation; together
they front-load the output before a reader reaches the
remediation guidance. The text length for the full-catalog run is
1594 lines; a reader looking for "what should I do first" has to
scroll past three orderings of the same data.

### Reasoning-trace contradiction-shape is a single fix with broad impact

The "must equal X, but is X" wording appears in both the inline
Reasoning block (M5) and the JSON `remediation_context.violation.reasoning`
clauses (M4). Fixing the wording in the translation layer
improves M4's AI-prompt input quality and M5's text-output
clarity simultaneously. This is the closest analogue in this
evaluation to the reasoning-infrastructure cluster: one fix, two
metrics improved.

### Sanitization defaults strip remediation signal

The sanitizer's blanket replacement of `current_value` with
`[SANITIZED]` makes sense for IDs but destroys boolean signal.
The output model treats sanitization as an all-or-nothing
post-processing pass; per-field sanitization policy (sanitize
identifiers, preserve booleans and enumerated values) would let
the remediation block stay informative without reintroducing the
identifier-leak risk sanitization was designed to prevent.

## Differentiation-claim assessment

The output model was supposed to deliver seven properties.
Whether the observed output actually delivers each:

| Promise | Observed delivery |
|---|---|
| Reduce triage time to zero | **Partial.** Issues consolidation collapses 78→42 but 23 are singletons; reader still has 19 multi-finding Issues to triage. Critical-Path top-9 is a faster front door. Catalog noise (24/78) inflates triage cost. |
| Reduce false positives to zero | **Fails.** 31% noise rate in the full-catalog run from misapplied controls. The output presents these as findings, indistinguishable in shape from real ones until the reader inspects each Reasoning trace. |
| Provide reasoning for prioritization | **Delivers.** Score breakdown formula (`base × duration × blast × exposure × chain`) is shown inline per finding. A reader can verify why one finding outranks another. |
| Provide reasoning for flagging | **Partial.** Reasoning trace exists per finding. The "must equal X, but is X" shape and gate-clause leakage make the reasoning harder to read than necessary. Technically self-explaining; practically not. |
| Provide actionable remediation | **Partial.** Action text is concrete prose; `changes[]` enumerates property paths. The advertised parameterized `command` field carries prose instead of CLI; sanitizer strips current values. An operator can act on the prose, but the structured shape promised by the JSON envelope underdelivers. |
| Play well with other tools | **Delivers.** SARIF taxa (via properties.alternatives) carry per-finding cross-tool mapping. JSON envelope is stable and documented. Coverage posture surfaces the full catalog-vs-Prowler comparison. The cross-tool dedup story is real. |
| Preserve inspectability over AI tools | **Delivers.** Every finding carries finding_id, control_id, reasoning_trace, score_breakdown — full provenance, no opaque scores. The reasoning trace's literal predicate-clause origin is *too* visible (precondition leakage, contradiction shape) but the inspectability claim itself is sound. |

Three of seven promises are fully delivered; three are partial;
one fails. The fully-delivered three are downstream-machine-
consumption (SARIF, JSON envelope, alternatives) and
inspectability (provenance, no opaque ML scores). The partials
and the failure are the human-reading surfaces: triage time,
false positives, plain-language reasoning. The output model is
strong where machines consume it, weak where humans do.

## Prioritized refinement queue

Ordered by (1) blocking gaps first, (2) evidence-grounded over
speculative, (3) leverage-weighted across metrics.

1. **Asset-type scoping at evaluation time.** Suppress controls
   whose `scope_tags` or asset-type gates don't match the asset.
   Closes the 31% noise rate observed in the full-catalog run.
   Improves M1, M2, M3, M5 simultaneously. Highest leverage in
   the queue. Evidence: 24 of 78 findings; cross-tab in §M1.

2. **Reasoning-trace wording fix.** Replace "must equal X, but
   is X" with "is X (matches unsafe pattern)" or similar non-
   contradictory phrasing. Distinguish gate clauses from
   violation clauses in the trace structure (e.g., separate
   `gates[]` from `violations[]` in the matched-clauses output;
   render only the violation clauses in inline Reasoning).
   Closes the M5 BLOCKING-adjacent gap. Improves M4
   (remediation_context.violation.reasoning consumes the same
   translations).

3. **Per-field sanitization policy.** Sanitize identifiers and
   strings; preserve booleans, enumerated values, and numeric
   ranges. The current `current_value: "[SANITIZED]"` for
   `storage.access.public_read = true` destroys the field's
   entire information content. Closes the M4 data-quality
   refinement.

4. **`command` field actually carries a parameterized command.**
   Either rename to `action` (matching the YAML field) or
   populate with a real shell command using the asset
   identifier. Current behavior — prose in a field named
   `command` — is an expectation mismatch that the JSON
   envelope's downstream consumers will hit. Closes the M4
   refinement.

5. **Issues block: suppress singletons by default.** When an
   Issue groups only one finding, the Issues view adds no
   consolidation value over the per-finding view below. Skip
   single-finding Issues from the Issues section; show only
   genuine consolidations (N≥2). Reduces clutter in
   mixed-cardinality runs (this run: 23 of 42 Issues are
   singletons). Improves M2.

6. **Issues block: differentiate same-control entries.** When
   an Issue lists `CTL.X.001` four times for one asset, render
   a per-entry differentiator (the parameter that varies, the
   matched evidence key, etc.) so a reader can tell what makes
   the four members distinct without scrolling to the per-
   finding section. Improves M2.

7. **Coverage posture: distinguish "no annotations" from "no
   coverage."** When a run loads controls that don't carry
   `alternatives:` blocks (e.g., a user's custom catalog), the
   posture section should say so explicitly rather than report
   "0 of 47 covered." Add a one-line preamble: "X of Y loaded
   controls carry alternatives annotations" before the per-
   tool counts. Improves M6.

8. **Coverage posture: scope to applicable observations.** The
   metric's Target language ("for the scanned resource set")
   suggests posture should reflect what could have run against
   the observations, not what the catalog declares globally.
   Likely needs an "applicable" subset of the inventory based
   on observation asset types. Improves M6.

9. **Source attribution in observations.** Most fixture
   observations carry no `source_ref`. The output writer
   already renders `Source: file:line` when present; the gap
   is on the extractor side. Worth flagging here so a future
   extractor iteration knows the output model is ready to
   consume the data. Improves M3.

10. **Three-layer headline ordering.** Issues + Critical-Path +
    Violations all front-load before remediation guidance, with
    1594 lines of text between "what's wrong" and "what to do."
    Reorder or collapse. Improves M1, M2 readability.

Items 1–4 are evidence-grounded gaps with concrete observed
output excerpts. Items 5–8 are refinement opportunities with
clear before/after states. Items 9–10 are smaller polish items.
The next iteration should not pick from this list mechanically;
items 1 and 2 are the highest-leverage and the most evidence-
backed.

## Honesty notes

Per the prompt's directive that "if the evaluation surfaces that
a metric's claimed delivery is actually broken rather than
refinement-needed, flag it explicitly":

- **Metric 5 self-explaining output is structurally present but
  practically counterproductive.** The contradiction-shape
  rendering and gate-clause leakage make the inline Reasoning
  harder to read than the raw predicate would be. Marking
  Metric 5 as PARTIAL-moving-toward-CLOSED is honest about the
  structural claim and dishonest about the user-facing effect.
  The metric's Target language ("plain English") is met
  literally; the implied promise (clearer than the predicate)
  is not.

- **Metric 4 `command` field name advertises content the field
  doesn't carry.** A consumer integrating against the JSON
  envelope reasonably expects `findings[].remediation_context.command`
  to be a shell command. It carries prose. The metric's
  baseline marks parameterized commands as a target;
  declaring the field "delivered" without populating it with
  parameterized commands is structurally true but
  contractually misleading.

- **Metric 6 coverage posture is correctly computed from the
  loaded data; the framing leads readers to wrong conclusions.**
  "0 of 47 IAM checks covered" reads as "Stave is missing
  these" when the actual cause is "this controls directory
  doesn't carry annotations." Not a delivery bug, a framing
  bug.

These three should be reflected in metrics.md target sections
when this evaluation feeds the next iteration's prompt — not as
target shifts (the metric scope is right) but as known gaps the
PARTIAL marking implicitly carries.
