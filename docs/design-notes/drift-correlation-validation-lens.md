# Iteration 4 validation lens: drift-to-finding correlation

The discipline carried over from the conflict-analyzer work: answer
the validation-lens question before writing code. Two paragraphs;
the question is the deliverable until the answer validates the
feature.

## What documented pain does drift-to-finding correlation address?

The executive-level question SOC teams already ask their tooling:
*"my posture score dropped overnight, what changed?"* Today the
answer requires manually diffing snapshots and re-running
evaluations against both — which is exactly the work that should
be automated by the engine that ran the original evaluation. The
indirect evidence is convergent: every posture management product
ships some version of "what changed and why did the finding fire"
(Wiz "configuration change timeline," Prisma "drift correlation,"
AWS Config "change history → compliance status"), and they ship it
because customers ask. The direct evidence — CSA *State of Cloud
Security* survey data on time-to-root-cause for posture
regressions, or equivalent — is the next thing to confirm before
treating this as settled. If the survey data does not exist or
points elsewhere, the lens question is open and the iteration
scopes down. The bar to clear: a documented pain point with
attribution, not just analyst intuition that the feature seems
useful.

### CSA evidence check (2026-04-17)

**No CSA practitioner survey with response-rate data on
time-to-root-cause for posture regressions exists in the repo's
research corpus.** The repo's CSA materials are: (1) a researcher's
Five Whys analysis of 8 historical breaches
[`build/zt-tool/research/problems/csa-survey.md`], (2) a
categorization of CSA Top Threats
[`build/zt-tool/research/problems/csa-problems.md`], and (3) a
Stave-side coverage note against a single CSA blog post on the
AWS crypto-mining campaign [`stave/docs/csa-coverage.md`]. None
quantify the specific pain "how long does it take to attribute a
finding to the change that caused it." The closest direct match
is qualitative, from the CSA blog: *"Configuration changes
complicate recovery. Attackers made subtle configuration
modifications to slow containment. Organizations lacked visibility
into what changed"* (csa-coverage.md, Lesson 4) — which the
existing `snapshot diff` already addresses for the field-level
question, leaving drift-to-*finding* correlation as the unaddressed
extension. The adjacent quantified evidence is from CSA Top
Threats: *"Problem 2.3: Configuration drift from secure baselines.
Initial secure configurations degrade over time as changes
accumulate without security review. Impact: Security posture
degrades invisibly. Point-in-time audits miss drift between
assessments"* (csa-problems.md:57-61), in a category cited at *"5
of 8 breaches (Tier 1 - Most Frequent)"* (csa-problems.md:43).
The corresponding control prescription is *"P5 / CCC-07: Detection
of Baseline Deviation — Detective, High Impact, Continuous"*
(csa-problems.md:589) — explicitly *detection of deviation*, not
*attribution of findings to deviation events*. Counter-signal
also exists in the corpus, though not from CSA: the
tool-sprawl/false-positives research
(`build/zt-tool/research/problems/false-positives.md`) reports
*"98% report false positives"* and *"engineers spend 6.1
hours/week on triage"* with overhead growing super-linearly in
tool count, framing the dominant practitioner pain as
alert-volume rather than per-finding context, which a feature
that adds per-finding attribution risks worsening rather than
improving.

**Honest classification: outcome 2, weakly.** Adjacent CSA
signal exists for *drift detection from baseline* (a different
feature with stronger evidence), and qualitative CSA signal
exists for *visibility into configuration changes* (which Stave
already partially addresses via `snapshot diff`). The specific
framing "drift-to-finding correlation" is one inferential step
beyond the documented evidence. Strong outcome-1 evidence (a
quantified survey response-rate on attribution-time as a top
practitioner pain) does not exist in the repo. Whether to treat
this as outcome 2 (proceed with scope-down instincts active) or
outcome 3 (re-scope before code) is a judgment the evidence
supports either way; the honest read is that an adjacent
feature with direct evidence — *baseline-deviation detection*
matching CCC-07 — is a stronger mode-one candidate than the
attribution feature as currently scoped.

## Re-scope to CCC-07 baseline-deviation detection (2026-04-17)

### Why the scope changed

The original drift-to-finding correlation framing was one
inferential step beyond what CSA evidence supports — convergent
indirect signal from competing tools, but no quantified direct
support. On reading the actual CSA sources, *baseline-deviation
detection* has direct, named, quantified support: a CSA-prescribed
control ID (CCC-07: *Detection of Baseline Deviation*, Detective
/ High Impact / Continuous), a Tier 1 frequency citation (the
misconfiguration-and-change-control category covers 5 of 8
analyzed breaches), and a clear failure mechanism (*"point-in-time
audits miss drift between assessments"*). The counter-signal from
the tool-sprawl research compounds the case: the dominant
practitioner pain is alert volume, and baseline-deviation
detection can be framed as *reducing* volume (suppress steady-
state findings, surface only deviations from the approved
posture), where attribution would have *added* per-finding
context to an already-noisy stream. The mode-one test favors
CCC-07 cleanly; the original framing required an inferential
defense the evidence does not provide.

### What CCC-07 means as a Stave feature

A baseline is a saved reference posture — the set of findings
approved at a point in time by an authorized user. Deviation is
any finding present in the current evaluation that differs from
the baseline (new violation, resolved-then-reappeared, severity
escalation, scope expansion). Detection surfaces deviations as
first-class OCSF Compliance Finding events with `activity_id:
UPDATE`, the baseline state in the prior-observable fields, and
enough context (which control, which asset, what changed) to act
on without re-running a full analysis. The control identifier is
recorded as `CCC-07` in the finding's compliance metadata, which
gives Stave a direct alignment claim against CSA's top-threat
categorization rather than a generic "we help with posture
management" framing. The integration story compounds: Stave
produces CCC-07 findings natively in OCSF, consumable by any GRC
tool that reads OCSF, mapped to the CSA control ID — one coherent
story, not two adjacent ones.

### Iteration sequence implication

The original plan had Iteration 4 (drift-to-finding correlation)
preceding Iteration 5 (semantic baseline diff). The re-scoping
collapses the two: CCC-07 baseline-deviation detection is closer
to what Iteration 5 was supposed to be than to the original
Iteration 4. The honest sequence is *5 before 4, or 5 absorbing
4* — the five-iteration plan becomes four, with attribution
demoted to a possible-but-not-guaranteed follow-on. The trigger
for that follow-on is user feedback after CCC-07 ships: if users
who can already see deviations ask *"yes, but why did this
deviation happen,"* attribution becomes mode-one work with
direct user-articulated pain behind it. Building attribution
first put it in front of the pain it was supposed to address,
which is the same shape as the conflict-analyzer mistake; this
re-scope corrects it before any code is written.

## What's the standards-adjacent shape?

OCSF Compliance Finding (class_uid: 2003) already models finding
state transitions through `activity_id` (CREATE, UPDATE, CLOSE)
and supports before/after observable lists on the event payload.
Drift-to-finding correlation maps cleanly: a property-path change
between two snapshots that flips a control's verdict produces an
OCSF finding event with `activity_id: UPDATE`, the changed
property paths as `observables[]`, and the prior verdict in the
event metadata. This is not a new schema — it is the existing
OCSF shape filled with cloud-posture-specific content, which
matches how the rest of the ontology has handled
standards-adjacent work (PostureFinding extending OCSF rather
than replacing it). The benefit is the same one that made the
ontology iterations go smoothly: downstream consumers (SIEMs,
dashboards) already know how to parse OCSF events, so the output
is consumable on day one without an integration project.

## If both validate

Iteration 4 proceeds as mode-one work: extend `snapshotdiff` with
controls re-evaluation against both snapshots, emit OCSF-shaped
finding state-change events, pin `catalog_hash` in output to
distinguish "the asset changed" from "the catalog changed." Scope
matches the original framing.

## If either does not validate

Scope down to a mode-two experiment with a specific question to
answer, not a feature to ship. Candidates: "is property-change
attribution deterministic enough to be useful without temporal
heuristics?" (a question, answered with a one-off script, no CLI
surface) or "do consumers actually want OCSF events for state
changes or do they want a different shape?" (a question, answered
by talking to one or two consumers, not by building).
