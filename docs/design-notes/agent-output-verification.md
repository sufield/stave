# Verifying agent-produced citations before they enter durable docs

A discipline note generalized from a process failure during the
CSA evidence check for Iteration 4 (2026-04-17). Sits alongside
[`analyzer-construction-lessons.md`](analyzer-construction-lessons.md)
because it shares the same shape: don't trust the scaffolding to
reflect reality, exercise the actual thing.

## What happened

The Explore agent was asked to find CSA evidence on
posture-change attribution. It returned a structured report with
quote-perfect material at specific line numbers in specific
files. Spot-checking found the line numbers were wrong and one
cited file path didn't exist at the location given. The themes
the agent named were real and the underlying source material
existed in the repo, but the *specific quotes attributed to
specific lines* were fabricated. Absent verification, those
quotes would have landed in a committed design note as
authoritative CSA citations.

## Why this happens

Language models produce plausible-shaped output that
pattern-matches the request. "Find me CSA evidence with file
paths and line numbers" returns a result shaped like CSA
evidence with file paths and line numbers, regardless of whether
the specific bindings are accurate. The agent is not lying — it
is producing the shape requested. The shape is what gets
verified by skim-reading; the bindings are what require direct
checking.

## The discipline

Any agent output that makes specific factual claims about
external artifacts must be verified against the artifacts before
it enters durable documentation. The categories that need this
treatment:

- **Survey or research citations** — quoted text, response
  rates, page or section references.
- **API behaviors and library semantics** — what a function
  returns, what an endpoint accepts, what an option flag does.
- **Standards conformance claims** — "OCSF supports X,"
  "OSCAL requires Y," "CSA prescribes Z."
- **Code references** — function names, file paths, line numbers
  in the current repo or in dependencies.

The verification method is the same in every case: open the
cited artifact and confirm the specific binding. For files in
the repo, read the cited line range. For external standards,
fetch the spec section. For library behavior, run the code or
read the source. If the agent cited it, you can cite it; if you
can't cite it, you can't quote it.

## Where this matches the analyzer lesson

Iteration 3.5–3.7 surfaced that synthetic test fixtures hand-
constructed to pattern-match the data model masked a
namespace-resolution bug — the tests' setup *looked like* the
real thing but was off by one indirection. The fix was end-to-
end pipeline tests using the actual production code paths. Same
pattern here: an agent's structured output *looks like* the real
research but the bindings are off; the fix is reading the
actual source. The general rule across both: when you need
fidelity, exercise the path that production traverses, not a
shape that resembles it.

## Cost

The verification step costs minutes — open the file, read the
lines, confirm or correct. The cost of skipping it is a
committed design note that misattributes claims to sources, and
downstream decisions made against citations that don't say what
the doc claims they say. The cost ratio is asymmetric enough
that verification is the default, not the exception.
