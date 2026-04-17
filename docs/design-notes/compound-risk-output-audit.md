# CompoundRisk output audit (2026-04-17)

A diagnostic pass on how Stave currently surfaces CompoundRisk
("chain") findings through `apply` and `export ocsf`. The question
this audit answers: when a chain fires, does the relationship
between the compound finding and its constituent findings survive
to a downstream consumer? The answer drives whether Iteration 4
should target alert-volume reduction, baseline deviation, or
something else entirely. No code changes here — evidence and
classification only.

## Node 1 — Native `apply` output

Stave's native assessment shape (`out.v0.1`) preserves the chain
relationship in both directions.

The compound side: `ComplianceReport` carries a top-level
`ChainFindings []risk.CompoundFinding` array distinct from the
top-level `Findings []Finding`
(`stave/internal/core/evaluation/audit.go:248-264`). The
`CompoundFinding` struct
(`stave/internal/core/evaluation/risk/chain_engine.go:11-22`)
records the chain ID, the failing controls, missing safeguards,
compound score, severity, narrative, and attack stages — enough to
explain *why* the chain fired without re-deriving it.

The constituent side: each `Finding` carries
`ChainMembership []ChainMembershipEntry`
(`stave/internal/core/evaluation/finding.go:32-34, 62-76`) listing
every chain it participates in along with the chain severity, stage
span, and narrative. The annotation is wired in workflow at
`stave/internal/app/eval/workflow.go:169-172`
(`report.ChainFindings = risk.DetectChains(...);
annotateChainMembership(report)`).

Verified against the hand-authored fixture at
`stave/testdata/e2e/graph-ontology/experiment-02-active-chain/assessment.json`:
3 findings + 1 chain_finding for `data_exfiltration_path`, with the
3 findings each carrying a `chain_membership[]` entry pointing back
to the chain. Bidirectional linkage holds.

**Native verdict: GREEN.** A consumer reading `out.v0.1` can walk
either direction (chain → constituents, or constituent → chains)
without re-evaluating anything.

## Node 2 — `export ocsf` behaviour

The OCSF export discards every chain signal Node 1 established.

`cmd/export/ocsf.go:51-53` reads the assessment file with this
shape:

```go
var assessment struct {
    Findings []remediation.Finding `json:"findings"`
}
```

`chain_findings[]` is unmarshalled into nothing — the field is
silently ignored at the parser level. Per-finding
`chain_membership[]` is also dropped: the OCSF emit struct
(`stave/internal/app/ocsf/export.go:12-73`) is `ComplianceFinding`
with fields `ClassUID, ClassName, ActivityID, SeverityID, Severity,
StatusID, Status, Finding, Compliance, Resources` and nothing else.
There is no `correlation_uid`, no `related_events`, no
`observables`, no `enrichments`, no chain reference, no
attack-stages carry-through.

Confirmed by running `stave export ocsf` against the
experiment-02-active-chain assessment: output is 3 independent flat
ComplianceFinding events. Zero correlation, zero relationship,
zero context that would let a downstream SIEM reconstruct that
those three events are members of a single chain.

**OCSF export verdict: relationship completely stripped.**

## Node 3 — OCSF 1.5 correlation idioms

OCSF 1.5 has standard mechanisms for cross-event correlation. None
of them are currently used by Stave's OCSF export, but all are
available.

Verified against
`https://schema.ocsf.io/1.5.0/classes/compliance_finding`:

- `metadata.correlation_uid` is the standard cross-event grouping
  identifier — events sharing a `correlation_uid` are "related" by
  consumer convention. It lives in `metadata`, not on the event
  body. This is the mechanism Stave should use to mark chain-member
  findings as belonging to the same chain.
- `finding_info.related_events[].uid` carries pointers (uid only,
  not full embedded events) to other Findings — appropriate when a
  consolidated chain-level event needs to reference its
  constituents.
- `observables[]` and `enrichments[]` exist on Compliance Finding
  but are for *context* (entities involved, scoring metadata) not
  cross-event linkage — they are not the right primitive here.
- `correlation_uid` and `related_events` are *not* fields on
  Compliance Finding directly; they sit on `metadata` and
  `finding_info` respectively. This matters: any fix has to write
  to the right nested location.

OCSF GitHub issue #995 (Cisco-authored, CLOSED March 2024,
verified via `gh issue view 995 --repo ocsf/ocsf-schema`) documents
that OCSF cannot embed full Activity events inside a Finding —
`finding_info.related_events[].uid` is pointer-only. The accepted
idiom is N flat events sharing a `correlation_uid` in metadata,
with consumers responsible for joining. Stave is not blocked by an
OCSF gap; it is failing to use the available primitives.

**Correlation idiom verdict: standard mechanism exists; Stave
doesn't use it.**

## Node 4 — Classification

**YELLOW.** The CompoundRisk relationship is preserved cleanly in
Stave's native `out.v0.1` output (Node 1 — bidirectional, complete)
but is completely stripped in OCSF export (Node 2 — three flat
events, zero linkage). Standard OCSF correlation primitives exist
to fix it (Node 3 — `metadata.correlation_uid`,
`finding_info.related_events[].uid`).

The gap is at the export boundary, not in the data model. The fix
does not require restructuring `ComplianceReport`, the chain
engine, the YAML schema, or any consumer of native output. It
requires the OCSF export struct to gain a `metadata.correlation_uid`
field populated from each chain-member finding's `chain_membership[].
chain_id`, plus optionally a consolidated chain-level OCSF event
that uses `finding_info.related_events[].uid` to point to its
constituents. Single sprint, scoped to `cmd/export/ocsf.go` and
`internal/app/ocsf/export.go`.

The CSA evidence base from
[`drift-correlation-validation-lens.md`](drift-correlation-validation-lens.md)
applies here too: false-positive / alert-volume pain dominates
practitioner research (`98% report false positives`, 6.1
hours/week on triage). Preserving chain relationships in OCSF
export is *alert-volume reducing* in the same way CCC-07
baseline-deviation detection is — three correlated events that a
SIEM can group are operationally one alert; three flat
uncorrelated events are three alerts. The two iteration candidates
are pulling on the same rope.

## Node 5 — Recommendation

Iteration 4 should fix OCSF export to use standard correlation
idioms. Specifically:

1. Add `metadata.correlation_uid` to the OCSF `ComplianceFinding`
   emit struct and populate it from
   `Finding.ChainMembership[0].ChainID` when a finding belongs to a
   chain. Multi-chain memberships use the most-severe chain's ID
   (chain severity already exists on `ChainMembershipEntry`).
2. Optionally emit one consolidated `ComplianceFinding` per chain,
   sourced from `ChainFindings[]`, using
   `finding_info.related_events[].uid` to point at the constituent
   findings' UIDs. This gives consumers one event to alert on
   instead of N, while preserving the per-control detail behind
   stable pointers.
3. Carry `attack_stages` through to the OCSF event as an
   `enrichments[]` entry on the consolidated event, so the chain
   narrative survives without inventing a non-standard field.

This is mode-one work: the gap is documented (Node 2 demonstrates
it directly), the fix is scoped (one package, one command), the
standard supports it (Node 3 verified), and the practitioner pain
it addresses is the same alert-volume pain CCC-07 was targeting —
making Iteration 4 a complement to the CCC-07 framing rather than a
competitor.

CCC-07 baseline-deviation detection remains the right Iteration 5
candidate. The two iterations compose: CCC-07 reduces the *count*
of findings by suppressing steady-state baseline matches; OCSF
correlation reduces the *count of alerts per finding* by grouping
chain members into one consumer-side incident. Both attack
alert-volume; neither attacks attribution (which remains a
possible-but-not-guaranteed follow-on, per the existing re-scope
note).

Out of scope for Iteration 4: changes to the chain engine,
`ComplianceReport`, the YAML chain schema, or consumers of native
`out.v0.1` output. The native shape is correct; only the export
needs the fix.
