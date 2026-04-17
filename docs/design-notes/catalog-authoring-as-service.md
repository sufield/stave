# Catalog authoring is a service offering, not in-product tooling

## What was attempted

Iteration 3 built a catalog conflict analyzer: a pipeline that took the
630-control built-in catalog plus the existing fixture corpus and
classified every overlapping control pair into one of four categories
(CONTRADICTION, REDUNDANCY, EMPIRICAL_SUBSUMPTION, DIVERGENCE). The
intent was a `stave verify catalog` command that catalog authors —
users — would run before publishing changes. A `ConflictReport`
schema (`v0.1/conflict-report.schema.json`) and a Go pipeline
(`internal/catalog/conflict/`) were implemented end-to-end, with
synthetic fixture tests, a 600+ line precedence rationale doc, and
five iterations of correctness work (3.5 matched-vs-evaluated, 3.6
routing-vs-evaluation denylist, 3.7 namespace agreement) chasing
false positives down from a peak of 836 CONTRADICTIONs to a "clean"
zero, and back to 590 once the analyzer started actually resolving
property paths against real assets.

## What the data showed

The 3.5–3.7 sequence revealed three distinct implementation defects
in the analyzer itself, each of which masked the next. After three
rounds of corrective work the analyzer still produced 590
CONTRADICTIONs on the real catalog, 546 of them keyed on
`properties.*.kind` — sub-asset-class router fields that gate which
controls apply to which sub-class, not substantive evaluation
fields. The pattern is identical to the bare-`type` routing
problem 3.6 already addressed; eliminating it would require
extending the metadata-only filter, which would almost certainly
expose another routing layer below it. The observation: on a 630-
control catalog grown from real incidents, a generic conflict
analyzer cannot produce a signal clean enough to act on without
indefinite iterations of catalog-shape-specific filter work. The
analyzer's "false positive rate" is not a tunable; it is a property
of the conceptual gap between syntactic predicate overlap and
semantic control conflict, which the analyzer has no information to
bridge.

## The decision

Catalog authoring assistance is a paid service, not in-product
tooling. The five primitives in the ontology (Asset, Control,
CompoundRisk, PostureFinding, Exemption) describe what Stave evaluates
and what it produces; they do not describe the catalog as an object
to be analyzed. A future contributor — or future-self — looking at
the codebase and considering "should we build a catalog conflict
analyzer" should treat that question as already answered: no, not
in-product. Catalog quality is a service deliverable, the same way
control authoring itself is. The mode-one test (does this output
change what a SOC team does this week) and the mode-two test (does
shipping this build user trust in the engine) both fail for an
in-product analyzer; the analyzer's outputs feed catalog authoring
decisions, not operational decisions, and an analyzer with a 90%+
false positive rate degrades trust in the engine that runs it.
PRECEDENCE.md — the precedence rules and conceptual-distinctions
checklist that came out of this work — is preserved in
[`docs/design-notes/analyzer-construction-lessons.md`](analyzer-construction-lessons.md)
because the lessons apply to any future analyzer (drift correlation
in particular), not because the conflict analyzer should return.
