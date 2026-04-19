# Stave output-model metrics: implementation plan

This plan translates the six output-model metrics in `docs/stave-output-model-metrics.md` into concrete engineering work, sequenced for dependencies and grounded in the Aikido "State of AI in Security & Development 2026" findings that the metrics document itself cites.

Each metric section opens with the surveyed problem, names the solution formulation Stave is committing to, and flags where that formulation is one reasonable response among several — so the validation checkpoint is explicit rather than implicit.

## Standing architectural constraint

Stave's core vocabulary is vendor-agnostic. Vendor-specific translation — AWS, GCP, Azure, Kubernetes — lives in adapter layers and does not propagate into the observation contract, control predicates, core scoring, or core dedup logic. When a metric's solution shape would require vendor vocabulary inside the core, that metric's implementation moves the vendor-specific portion to an adapter. This constraint is load-bearing for every metric below; when in tension with a metric's solution shape, the constraint wins and the metric's implementation shape adapts.

## Metric 1 — Prioritization: partial → full

**Surveyed problem.** 98% of organizations report false positives from their security tools (Aikido 2026). False positives manifest on the output side as absent prioritization: every finding carries equal weight, noise and signal arrive in the same queue, triage proceeds sequentially until exhaustion.

**Solution formulation.** Rank findings by a composed, inspectable score — base severity × duration factor × blast multiplier × exposure multiplier + chain bonus — with the full factor breakdown emitted on every finding. Confidence: **high** — survey names "too many findings, can't act on them" directly; ranked output with visible reasoning is the near-universal response across the category. What makes Stave's version defensible rather than me-too is the 4.5-year "silent killer" duration tier and the requirement that the breakdown be emitted, not hidden.

Three concrete changes, in order of independence:

**1a. Change the default sort of `findings[]`.** Flip `SortFindings` in `internal/core/evaluation/finding.go` from `(ControlID, AssetID)` to `(ExposureScore desc, ControlID, AssetID)` — keep the alphabetical keys as tiebreakers so ordering stays deterministic across runs. This is the single smallest change that delivers the largest behavioural shift. Every downstream consumer — text writer, JSON emission, fixture goldens — immediately reads top-down by priority.

**1b. Emit the score and breakdown on every finding.** `risk.RankExposures` currently produces `top_exposures[]` with the factor breakdown. Lift the breakdown onto `Finding.ExposureScore` as a sibling struct — `{base, duration_factor, blast_multiplier, exposure_multiplier, chain_bonus, total}`. The `top_exposures[]` view becomes a pointer slice into `findings[]` rather than a separate computation. One source of truth; the view is a projection.

**1c. Fold chain membership into the score.** `Finding.ChainMembership[]` exists but is inert for ranking. Add a `chain_bonus` factor: for each chain a finding participates in, add `chain.compound_score × role_weight` where `role_weight` is 1.0 for members and 0.5 for missing-safeguard findings. A fixture that fires a chain should demonstrably re-rank member findings above non-member peers at the same base severity — add that as a fixture-level assertion.

**1d (stretch, defer).** Broaden exploitability beyond `Exposure.IsPublic`. Introduce an `exposure.type` enum and a principal-scope value; each gets a distinct multiplier. This is a contract change — coordinate with `docs/contract/` first; don't sneak it in under a ranking commit.

**Validation checkpoint.** Show a first-time user output before and after the default-sort change. They should reach for the top item without prompting. If they ask "why is this first" and the factor breakdown doesn't satisfy them, the breakdown shape is wrong, not the sort.

**Deterioration signals.** Non-determinism (no wall-clock inputs), hiding the breakdown (always emit decomposition alongside total), per-tenant scoring config.

## Metric 3 — Traceability: partial → full

**Surveyed problem.** Aikido 2026 identifies that developers and security engineers lose trust in tools whose verdicts cannot be inspected. A finding that asserts without showing evidence is indistinguishable from noise.

**Solution formulation.** Inline matched-clauses-with-observed-values on every finding in every output format. Full step-by-step trace remains opt-in behind `--trace`. Confidence: **medium-high** — the problem is survey-validated, but the specific shape (matched clauses + observed values) is one choice among several (decision-tree rendering, natural-language explanation, visual reasoning graphs). The matched-clauses shape is the one that's machine-consumable and visually compact; it's the right bet but not the only plausible one.

Ordering this metric ahead of M5 is deliberate — the translator adapter in M5 consumes this shape.

`Evidence.Misconfigurations[]` already carries `{property, operator, unsafe_value, actual_value}`. Two shape gaps:

**3a. Rename and restructure.** The current shape reads as a "violations list"; the target reads as a "matched clauses" list. Same data, different framing. Rename the emission field to `reasoning.matched_clauses` and structure it as `{field, op, value, observed}`. Field paths remain in the vendor-agnostic observation-contract vocabulary. Keep the old field as an alias for one release.

**3b. Handle `any` vs `all` semantics.** For `all` predicates, every clause contributed and gets emitted. For `any` predicates, only the clauses that were true. `Misconfigurations[]` today doesn't distinguish — walk the predicate AST at evaluation time and tag each clause with its quantifier parent.

**3c. Stable schema documentation.** Add the `reasoning` shape to `docs/contract/` as a versioned schema. Downstream consumers — AI prompts especially — need this to be a commitment, not a convention.

**3d. `--trace` stays as superset.** The full `LogicTrace` with per-step timing and skipped clauses remains opt-in. Inline is a subset, trace is the superset. Don't collapse them.

Fixture-level assertion: for a named control and fixture, the emitted `reasoning.matched_clauses` exactly matches the clauses the predicate actually evaluated to true.

**Validation checkpoint.** Show a practitioner a finding with and without inline matched clauses and ask which they trust. Trust should increase with the clauses visible. If they say "I'd need to see the CEL expression too," the inline shape isn't capturing what they verify against.

**Deterioration signals.** Reasoning in JSON only, not text. AST-level vocabulary (raw operator enums, CEL expression strings) instead of clause-level structure. Observed values omitted. Truncation without a documented convention. Inline dependent on `--trace` being enabled.

## Metric 5 — Self-explaining output: partial → full

**Surveyed problem.** Aikido 2026 identifies that security tooling with high adoption friction gets bypassed. Friction comes from output that requires tool-specific fluency before the first finding is actionable.

**Solution formulation.** Translate Stave's vendor-agnostic vocabulary to vendor-specific vocabulary for the target reader, via a translation adapter in the adapter layer. The core emits `reasoning.matched_clauses` in observation-contract vocabulary (what M3 produces). Adapters render that into AWS-specific, GCP-specific, Azure-specific, or other vendor vocabulary as configured. Confidence: **medium** on the vocabulary choice for a given vendor, **high** on the adapter placement — the hexagonal discipline isolates every vocabulary decision so that a wrong persona bet is swappable, not a refactor.

The Aikido 2026 report should be re-read for persona breakdown before the AWS adapter's vocabulary is authored; if it flags developer-fluent audiences as the adoption blocker rather than cloud-security-fluent ones, the adapter's vocabulary changes. Flag this as pre-work research for the adapter, not an assumption.

Decomposition reflects the adapter boundary:

**Core work (vendor-neutral).**

- **5a-core. Operator-to-phrase mapping.** `eq false` → "has no", `any` → "at least one", `all` → "every". This is about predicate logic, not cloud semantics. Lives in core-adjacent translation scaffolding, shared across adapter implementations.
- **5b-core. Translator interface.** A hook point in the text writer that takes `{field, op, value, observed}` and invokes a registered translator adapter. No adapter registered → text writer emits the raw DSL (current behavior). Safe default.
- **5c-core. Control-ID glossary emission.** When a control ID first appears in text output, render its `summary` field (one line, scan-optimized). Add a `summary:` field to control YAML; backfill all controls. The `summary:` is vendor-agnostic per control — controls already target the domain concept, not the vendor rendering. The long-form `description` stays for the full entry.

**Adapter work (vendor-specific, AWS first).**

- **5a-adapter. AWS translator implementation.** Lives under `internal/adapters/output/text/translate/aws/`, sibling to the existing text writer, not inside it. The translator is a pure function from `{field, op, value, observed}` → English prose using AWS vocabulary.
- **5b-adapter. AWS field-concepts mapping.** `translate/aws/field-concepts.yaml` covers every field in the S3 and IAM observation namespaces. Example: `storage.access.has_scoping_condition` → "bucket policy scoping Condition". This is the vendor-specific data that makes the core's vendor-agnostic output readable to an AWS-fluent reader.
- **5c-adapter. Fixtures.** AWS-adapter fixtures assert the translated text output for named controls. Fixture goldens catch drift in the translation tables.

**Configuration.** A `--output-vocabulary aws` flag (or environment equivalent) selects which translator adapter is active. Default is no adapter — the core is complete and usable emitting raw DSL. The AWS adapter is opt-in at invocation.

**Future adapters.** GCP, Azure, Kubernetes adapters follow the same structure: `translate/gcp/`, `translate/azure/`, `translate/k8s/`, each with its own `field-concepts.yaml`. Adding a vendor is an adapter, not a core change.

**JSON output.** Structured DSL fields in JSON remain verbatim, vendor-agnostic. Downstream tooling relies on them. The translator is a text-rendering concern, never a data-model concern.

**Validation checkpoint — the strongest in this plan.** A developer who has never seen Stave is shown AWS-adapter-translated output and a Prowler equivalent for the same misconfiguration. Ask which reads faster. If Prowler wins, the AWS adapter's vocabulary is wrong — too jargon-heavy, too terse, or missing the "so what." Because the vocabulary is isolated in the adapter, revising it is an adapter change, not a core refactor. This is why the hexagonal placement matters for this metric specifically.

This metric has a content-authoring cost per vendor (field-concepts mappings, per-control summaries) that engineering time alone doesn't close. Budget it as catalog work per adapter, not feature work.

**Deterioration signals.** Vendor vocabulary propagating into the core (observation contract, predicate, scoring, dedup). Removing structured DSL fields from JSON to simplify text. Translator vocabulary that assumes Stave-specific concepts (profile names, `scope_tags`, CEL syntax). Different translations across output formats for the same finding. Control YAML descriptions written for Stave insiders or locked to one vendor's vocabulary.

## Metric 2 — Deduplication: partial → full

**Surveyed problem.** The same Aikido 2026 false-positives finding (98%) applies: noise manifests not only as unranked findings but as repeated findings. A single misconfiguration that five controls each detect produces five triage tickets.

**Solution formulation.** Consolidate by root cause — shared predicate-consumed observation fields per asset. Emit an `issues[]` parallel view. Confidence: **medium** — the repeated-findings problem is survey-validated; the specific dedup key (shared fields, per asset) is distinctive and may or may not match what practitioners recognize as "the same issue." Semantic similarity or remediation-action grouping (what Stave already has) are plausible alternatives.

Ordering this after M1 is deliberate — the `issues[]` view wants to order by the highest-scoring contributing finding, which requires M1's score on every finding.

The hard part is the root-cause key. Two options for declaring which observation fields a control consumes:

**Option A — AST inference.** Parse the CEL predicate and extract field references. Pure; no per-control annotation overhead; always in sync with the predicate. Cost: CEL AST traversal code, edge cases around `has()` and nested field access.

**Option B — Explicit `root_cause_fields:` annotation.** Simple; human-readable in YAML; reviewable. Cost: per-control authoring burden; drift risk when the predicate changes but the annotation doesn't.

Pick A for correctness, B as an override for controls where the predicate reads fields it doesn't actually gate on (defensive reads, shape checks). Do both.

**Dedup logic.** Group findings where `(asset_id, root_cause_fields_set)` match. Emit `issues[]`; each issue carries `{asset_id, root_cause_fields, contributing_findings: [finding_id, ...]}`. `findings[]` stays — dedup is a view, not a replacement. `BuildGroups` (remediation-action grouping) stays as a distinct secondary view.

**Verification fixture.** One bucket that fires `CTL.S3.CONTROLS.001` (PAB umbrella) and all four `CTL.S3.PAB.*` sub-flag controls. Assert: 5 findings in `findings[]`, 1 issue in `issues[]`, issue references all 5 finding IDs.

**Validation checkpoint.** Show someone the old five-finding output, then the one-issue-with-five-contributors output. If they don't recognize the consolidation as helpful, root-cause-by-shared-fields was the wrong dedup key — consider falling back to what practitioners actually call "same issue" in their own language.

**Deterioration signals.** Lossy dedup (can't reach contributing findings from an issue). Cross-asset collapse without explicit semantics. Runtime-configurable dedup keys.

## Metric 4 — Remediation data quality: partial → full

**Surveyed problem.** Aikido 2026 identifies remediation handoff as where security tooling breaks down — the finding names a problem, the developer translates it into a change. AI-assisted development amplifies the gap because AI assistants need structured input to produce reliable changes.

**Solution formulation.** Structured, parameterized, AI-consumable remediation data. No auto-fix execution — the boundary is Stave produces data, something else executes. Confidence: **high** on the problem (survey is explicit), **high** on the no-auto-fix position (deliberate counter-positioning against where commercial tools are racing), **medium-high** on the specific export shape for AI prompts (one plausible shape among several — IaC-specific PRs, interactive CLI, ticket templates are alternatives).

**Architectural note.** Current CLI `Action` strings in control YAML are AWS-specific (`aws s3api put-public-access-block ...`). This is a vendor-vocabulary-in-core boundary violation analogous to the one Metric 5 now resolves via adapters. The honest long-term shape separates remediation *intent* (vendor-neutral: "enable full public-access block on this bucket-analog") from *rendering* (vendor-specific: the `aws s3api` command). Intent lives in the control catalog; rendering lives in a remediation adapter parallel to the translation adapter. This refactor is out of scope for the immediate metrics work — but new remediation fields added under 4a/4b/4c should be structured to accommodate the future split (e.g., a `remediation.intent` layer alongside a `remediation.rendering.aws_cli` layer). Do not entrench the current AWS-coupling further.

Three gaps, three fixes, distinct scopes:

**4a. Parameter resolution.** CLI `Action` strings contain `<name>`, `<bucket>`, and similar placeholders. The asset identity is already in scope at `RemediationSpec` build time. Resolve the placeholders against the asset's actual fields; emit the concrete command. Fixture-level test: grep the emitted fixture outputs for `<` and fail if any placeholder token remains on a resolved field. Parameter resolution happens at the rendering layer, not the intent layer — so this change is forward-compatible with the future intent/rendering split.

**4b. `required_value_prompt` for `HasSafeDefault=false`.** When the control can't emit a concrete `RequiredValue` (encryption key ARN, VPC endpoint ID, retention days), the current emission leaves it empty. Add a `RequiredValuePrompt` field on `PropertyChange` — the prose of the question to ask the user. The prompt text is vendor-agnostic where possible ("which KMS-analog key should encrypt this resource?") and lives at the intent layer. Vendor-specific phrasing can be added by a future remediation adapter. Populate on every control where `HasSafeDefault=false`; audit the catalog for completeness.

**4c. Structured-export-for-AI shape.** Publish the shape in `docs/contract/remediation-export.md` with a small example prompt that consumes it. Commit to schema stability with a version field on the root. The export shape should expose both intent and rendering fields when present, so AI consumers can choose to work at either layer.

**Non-negotiable: no auto-fix.** The document calls this a hard scope constraint; the deterioration signal names "CLI flag, API, watch mode, CI-hook-triggered mutation" explicitly. The plan preserves the boundary.

Fixture-level test: invoking the emitted CLI string against a mock AWS CLI produces a command that would close the specific door (syntactic valid, parameters resolved, right action verb). Not executing against real AWS.

**Validation checkpoint.** Hand the structured export blob to an AI assistant without explaining the shape. If it produces a correct remediation PR, the export shape is AI-consumable as intended. If it asks clarifying questions, those are the fields the shape is missing.

**Deterioration signals.** Auto-fix execution direct or transitive. AI-inferred remediation data (breaks reliability). Prose-only descriptions replacing structured fields. Varying remediation shape across output formats. Shipping remediation without a fixture-level test confirming it closes the detection. Entrenching vendor-specific CLI at the intent layer.

## Metric 6 — Cross-tool posture: absent → full

**Surveyed problem.** Aikido 2026 identifies tool sprawl as a material operational cost — teams run three to seven security tools in parallel, each producing a partial view, with dedup happening manually or not at all.

**Solution formulation.** Per-control `equivalents:` metadata mapping to Prowler and ScoutSuite, finding-level `equivalent_signals:`, and a coverage-posture section in `apply` output. Confidence: **medium** on the problem-to-solution mapping — tool sprawl is survey-validated, but the specific response ("we tell you what the other tools call this") is unusual in the market, which means it's either blue-ocean or a metric no one values enough to build. No practitioner has validated this specific response yet.

This metric is metadata, not vocabulary — it attaches `equivalents:` to controls without pulling vendor terms into the core's reasoning logic. Safe with respect to the standing architectural constraint.

Two surfaces, different effort profiles:

**6a. Per-control `equivalents:` metadata.** Add to control YAML schema:

```yaml
equivalents:
  prowler: [s3_bucket_public_access_block, s3_account_level_public_access_blocks]
  scoutsuite: [s3-bucket-no-public-access-block]
  playbook:
    - source: rhino-iam-cluster
      section: "S3 public access detection"
```

Backfill from `docs/methodology-coverage-s3-prowler.md` and `docs/methodology-coverage-iam-prowler.md`. One-time cost; subsequent edits live in YAML. Write a `gencoveragedocs` tool that emits the markdown from YAML; markdown becomes generated output.

**6b. Finding-level `equivalent_signals:` emission.** Trivial once 6a is done — copy the control's equivalents onto the finding at emit time.

**6c. Coverage posture in `apply` output.** A new section summarizing, for the scanned resource set, how many Prowler checks Stave covers and how many ran. Default on in text mode; `--no-coverage-posture` suppresses.

Equivalence bar is intent-overlap, not exact-check match. Commercial-tool equivalence stays out — Wiz, Orca, Lacework don't publish their catalogs.

**Validation checkpoint — the most important one.** Show a prospect running Prowler alongside Stave the coverage-posture output. If they react with "this helps me justify using both" or "this helps me drop Prowler," the metric lands. If the reaction is neutral, this metric is internally coherent but externally unvalued — the same risk Invariants as Code carries. In that case, deprioritize 6c and keep 6a/6b as defensible metadata that costs little to maintain.

**Deterioration signals.** Commercial-tool equivalence without attested reference. Exact-check-match bar producing false-negative gaps. Removing methodology-coverage markdown in favor of code-only generation. Coverage-posture as a hard dependency rather than best-effort. Vendoring another tool's output format.

## Sequencing

Dependencies:

- M3 (traceability) feeds M5 (self-explaining). The translator adapter consumes the matched-clauses shape; if M3 is still churning, adapter authoring is wasted. Land M3 first.
- M1 (prioritization) is independent — lands anytime.
- M2 (deduplication) benefits from M1 being done first, because `issues[]` wants to order by the highest-scoring contributing finding.
- M4 (remediation) is independent — lands anytime. The intent/rendering split is a future refactor; this metric's scope is to avoid entrenching the current coupling further.
- M6 (cross-tool) is mostly catalog authoring; the backfill runs in parallel with any of the others.

Order: M1 → M3 → M5 → M2 → M4 → M6, with M6's backfill happening in parallel across the whole sequence.

M1 is the highest-leverage single change (it visibly reorders every output the user sees). M3 and M5 together close the "trust the output" story. M2 and M4 close the "act on the output" story. M6 closes the "displace the other tools" story.

## Validation-first framing

Every metric above names a validation checkpoint because the Aikido survey grounds the *problem* but not the *specific solution shape*. The practitioner-conversation sequence already planned (GitHub curated lists → peer tool authors → newsletters → prominent researchers) is the natural place to run these checkpoints. Each conversation tests one or two metric formulations and the results feed back into the Target section of the metrics document.

Metrics where the validation comes back negative don't get scrapped — the formulation gets revised. The problem is real whether Stave's specific response is optimal or not; that's what having external grounding for the problem (vs. the solution) means. For Metric 5 specifically, the hexagonal placement means a negative validation against the AWS adapter's vocabulary triggers an adapter revision, not a core refactor.

## Attribution footnote pattern

Per the metrics document's own standing guidance ("future updates should add verbatim percentages as specific findings are matched to metrics"), each metric's commit that moves it from partial to full should update the document's Baseline section with the specific Aikido finding it closed. Format: `Closed by [commit hash]: Aikido 2026 [specific finding, verbatim with percentage where quoted, thematic where not]`. That makes the trail — survey finding → metric formulation → implementation → shipped change — inspectable end-to-end. Eating the dog food at the meta level.

## The goldens caveat

Each of these reads clean as a plan. Every one understates one cost: **goldens churn**. Changing the default sort of `findings[]` alone will regenerate most fixture goldens. The behavioral-vs-metadata classifier landed this session was built for exactly this kind of work — the mitigation is in place, but budget reviewer time accordingly. Expect every metric to produce a PR with a large but *classified* diff rather than a small targeted one. Land them one at a time with the classifier's output in the PR description so reviewers scan the behavioral changes and wave through the metadata noise.
