# Example — CloudTrail Stop Logging

Demonstrates the `cloudtrail-stop-logging` pattern using
Stave's library API. Pattern P9 in
[`examples-plan.md`](../../../examples-plan.md), grounded
in **MITRE ATT&CK T1562.008** (*Disable or Modify Cloud
Logs*) and the established AWS incident-response pattern
where the first action after a successful compromise is
`StopLogging` on the management trail.

The bug: a CloudTrail trail exists, looks healthy in the
console, is configured as multi-region — but `IsLogging`
is `false`. The trail is not recording anything. Every
subsequent action in the account happens unobserved.

## What it does

Loads two fixture snapshot directories — fixtures/before
(trail stopped) and fixtures/after (trail running) — and
asserts that `CTL.CLOUDTRAIL.STOP.DETECT.001` fires on the
first and is silent on the second.

Severity is `critical`, exposure score 100. The trail
being stopped is the configuration that determines
whether the *rest of the audit story* is recoverable. A
single trail stopped for a week creates a week-long
audit blind window; the per-finding score reflects that
the impact is not just on this one asset but on every
forensic question the team will later try to answer.

## Run

From `stave/`:

```bash
go run ./examples/cloudtrail-stop-logging           # both phases
go run ./examples/cloudtrail-stop-logging before    # trail stopped only
go run ./examples/cloudtrail-stop-logging after     # trail running only
```

## Expected output

```
=== before (trail stopped) ===
  status: NON_COMPLIANT   total_assets=1   violations=1
  CTL.CLOUDTRAIL.STOP.DETECT.001 fired on 1 asset(s):
    - arn:aws:cloudtrail:us-east-1:111122223333:trail/org-audit-trail   severity=critical   exposure_score=100.00
  assertion: fires=true (expected) ✓

=== after  (trail re-started) ===
  status: COMPLIANT   total_assets=1   violations=0
  CTL.CLOUDTRAIL.STOP.DETECT.001: no findings
  assertion: fires=false (expected) ✓
```

## The Predicate

```yaml
unsafe_predicate:
  any:
    - field: properties.trail.is_logging
      op: eq
      value: false
    - field: properties.trail.is_multi_region_trail
      op: eq
      value: false
```

`any` — either condition fires the control. The first
covers stopped trails (the attacker called
`StopLogging`); the second covers single-region trails
that miss API events from other regions. A multi-region
trail that's actively logging is the only configuration
that satisfies the safety property.

## Why Z3 doesn't help

This is a presence check, not a reachability question.
The collector reads two booleans from the trail's
configuration; CEL's predicate is a two-leaf disjunction.
There's no logical search space, no quantification, no
witness to enumerate. Reaching for an SMT solver here
would be an instance of the "hammer looking for nail"
antipattern.

A different question — "given this trail's S3 bucket
policy, can the attacker delete log objects after the
fact?" — *would* be reachability-shaped, and would benefit
from Z3. That's `CTL.CLOUDTRAIL.S3.OBJECTLOCK.001`'s
territory, not this control's.

## Diagnostic fields

The before fixture carries forensic context as
diagnostic fields the predicate doesn't read but the
incident-response team does:

```json
"trail": {
  "is_logging": false,
  "is_multi_region_trail": true,
  "stopped_at": "2026-01-01T00:00:00Z",
  "stopped_by": "arn:aws:sts::111122223333:assumed-role/incident-actor/session"
}
```

`stopped_by` names the principal that called
`StopLogging`. `stopped_at` bounds the audit-blind
window. Stave's predicate doesn't use these fields — they
exist to give the responder the next investigative thread
once the finding fires.

## Layout

```
examples/cloudtrail-stop-logging/
├── README.md
├── main.go
├── controls/
│   └── CTL.CLOUDTRAIL.STOP.DETECT.001.yaml
├── fixtures/
│   ├── before/observations/{T1,T2}.json   # is_logging=false × 2 weeks
│   └── after/observations/{T1,T2}.json    # is_logging=true × 2 weeks
└── expected/
    ├── before-output.txt
    └── after-output.txt
```

## Where this fits

This is **Iteration 8, Phase B** of the examples roadmap.
No new `pkg/stave` API was needed. Phase C is the
article, framed as the defense-evasion stage of a
post-compromise campaign — the trail looks fine to a
casual observer; only `is_logging: false` distinguishes
"audit blind" from "all clear."
