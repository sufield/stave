# Analyzer construction: durable lessons

Lessons preserved from the Iteration 3 conflict-analyzer work.
The analyzer itself was withdrawn (see
[`catalog-authoring-as-service.md`](catalog-authoring-as-service.md));
these lessons apply to any future analyzer over the catalog, the
fixture corpus, or the finding stream — drift correlation in
particular.

## Four conceptual distinctions worth pinning

Each distinction below compiles fine if you ignore it, fails subtly
in production, and only surfaces under real-data stress. A future
analyzer adding a new category, a new field, or a new payload type
should scan this list and confirm the change respects each one.

### 1. Matched vs evaluated

Two different denominators: the count of items the analyzer
*considered* and the count of items the analyzer's claim *applies
to*. Coverage signals read from evaluated; semantic claims read
from matched. Conflating them is what produces vacuous findings
that score "high confidence" against zero relevant evidence.

The single rule that prevents the failure mode: any code that
reads a per-item record to make a semantic claim about the
aggregate must filter on "matched" first. Counting raw presence
is correct only for the coverage denominator.

### 2. Observed vs differing values

When two analyses disagree, the data the consumer needs differs
by *why* they're looking. "We agreed on the inputs and disagreed
on the output" wants the *shared* values (what they both saw).
"We disagreed on both inputs and outputs" wants the *differing*
values (what the delta was). Same data model, different views;
collapsing them into one field erases the diagnostic distinction
that makes either useful.

### 3. Disqualifying vs precedence

When category assignment uses an ordering, the rule is almost
always *disqualifying* (a higher-precedence match excludes from
lower-precedence ones), not *first-match-wins* (return the
highest-precedence match and stop). The two look identical until
a case fits multiple categories — at which point first-match
silently misclassifies the case as the higher category, while
disqualifying correctly escalates it. Pin the rule with a test
that constructs a multi-fit case and asserts the higher
classification; do not let the ordering drift into a tolerance
threshold ("90%-redundant counts as redundant") without escalating
the design.

### 4. Reads-for-routing vs reads-for-evaluation

A predicate reads some property paths to gate which inputs it
applies to (asset class, sub-asset class, vendor) and other paths
to evaluate the input's state. Static dependency extraction does
not distinguish the two — both come back as plain dependency
paths — so two predicates that route on the same metadata field
appear to "share a dependency" they do not actually share
semantically. Any analyzer that reasons about predicate overlap
must either separate routing reads at extraction time (the
structural fix) or filter routing paths from candidate overlaps
at analysis time (the interim defense). Without one of those, the
analyzer reports overlap on every routing-only co-evaluation, and
the false-positive rate is dominated by the catalog's routing
vocabulary rather than its content.

## The meta-lesson

The pattern across all four: a conceptual distinction in the
taxonomy that compiles fine if you ignore it, fails subtly in
production, and only surfaces under real-data stress. Pinning
tests are the only durable defense — discussion-only rules walk
back in. When an analyzer's synthetic test corpus passes clean
but the real-data run blows up by an order of magnitude, the
synthetic tests are almost always stubbing past one of these
distinctions; the fix is fidelity in the test setup, not new
filter logic.

## Provenance

Iteration 3 (Nodes 3a–3f, 3.5, 3.6, 3.7) of the catalog conflict
analyzer surfaced each of these distinctions in turn. The
analyzer was withdrawn after 3.7; these distinctions are
analyzer-construction lessons that outlive the specific analyzer
that taught them.
