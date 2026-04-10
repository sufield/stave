# Logic Trace — Evaluation Audit Trail

Stave can record a structured audit trail of every decision the safety
engine makes during evaluation. The trace explains *how* the engine
arrived at each verdict — not just why something failed, but why it was
considered compliant ("Proof of Pass").

## Quick Start

```bash
# Via CLI flag
stave apply --controls controls --observations observations \
  --max-unsafe 168h --trace audit_trace.json

# Via environment variable (CI/CD pipelines)
STAVE_TRACE=1 stave apply --controls controls --observations observations \
  --max-unsafe 168h
```

When `STAVE_TRACE=1` is set without `--trace`, the trace is written to
`audit_trace.json` in the current directory.

## What the Trace Records

Each control × asset pairing produces an **Assessment** with an ordered
list of **Steps** — the reasoning chain the engine followed:

| Step | When Recorded | What It Shows |
|------|--------------|---------------|
| `exemption_check` | Always | Whether the asset was exempted by an organizational policy override |
| `predicate_evaluation` | Always | Whether the unsafe predicate matched the asset's properties |
| `threshold_check` | When predicate matched | SLA duration, observation gap, whether the threshold was exceeded |
| `coverage_check` | When threshold not exceeded | Observation span vs required span, data sufficiency |
| `recurrence_check` | Recurrence controls | ExposureWindow count vs limit within the time window |
| `verdict_decision` | PASS verdicts | Why the resource was considered compliant |

Every step has an `input` (what the engine examined) and a `result`
(what it concluded).

## Output Schema

The trace file is JSON with schema version `trace.v0.1`:

```json
{
  "schema_version": "trace.v0.1",
  "run_id": "",
  "generated_at": "2026-04-08T10:30:00Z",
  "stave_version": "dev",
  "assessments": [
    {
      "resource_id": "res:aws:s3:bucket:private-bucket",
      "policy_id": "CTL.EXP.DURATION.001",
      "verdict": "PASS",
      "confidence": "HIGH",
      "steps": [
        {
          "name": "exemption_check",
          "result": { "exempted": false }
        },
        {
          "name": "predicate_evaluation",
          "input": { "currently_unsafe": false, "exposure_count": 0 },
          "result": { "matched": false }
        },
        {
          "name": "verdict_decision",
          "result": {
            "verdict": "PASS",
            "reason": "predicate not matched — resource is compliant"
          }
        }
      ]
    },
    {
      "resource_id": "res:aws:s3:bucket:public-bucket",
      "policy_id": "CTL.EXP.DURATION.001",
      "verdict": "VIOLATION",
      "confidence": "HIGH",
      "steps": [
        {
          "name": "exemption_check",
          "result": { "exempted": false }
        },
        {
          "name": "predicate_evaluation",
          "input": { "currently_unsafe": true, "exposure_count": 1 },
          "result": { "matched": true }
        },
        {
          "name": "threshold_check",
          "input": { "threshold_hours": 168, "max_gap_hours": 0 },
          "result": { "exceeds_threshold": true }
        }
      ],
      "finding_id": "CTL.EXP.DURATION.001@res:aws:s3:bucket:public-bucket"
    }
  ],
  "summary": {
    "total_assessments": 2,
    "violations": 1,
    "passes": 1,
    "skipped": 0,
    "inconclusive": 0
  }
}
```

## Reading the Trace

### Proof of Pass

When a resource is marked PASS, the trace shows exactly why:

```
exemption_check → not exempted
predicate_evaluation → predicate not matched (resource is safe)
verdict_decision → PASS: "predicate not matched — resource is compliant"
```

A security researcher reads this as: "The engine checked if this bucket
was publicly accessible. It wasn't. Therefore it passed."

### Proof of Violation

When a finding is produced, the trace links to it:

```
exemption_check → not exempted
predicate_evaluation → matched (resource is unsafe)
threshold_check → exceeded (240 hours > 168 hour threshold)
→ finding_id: CTL.EXP.DURATION.001@public-bucket
```

### Inconclusive Verdicts

When data is insufficient to make a determination:

```
exemption_check → not exempted
predicate_evaluation → not matched
threshold_check → not exceeded
coverage_check → insufficient ("maximum observation gap 216h exceeds threshold 12h")
→ verdict: INCONCLUSIVE
```

This tells the researcher: "We can't prove this bucket is safe because
there's a 9-day gap in the observation data."

## Air-Gap Safe

The trace system writes a local JSON file. It makes no network calls
and has no OpenTelemetry dependency. Safe for air-gapped environments.

## Performance

When `--trace` is not set, the engine uses a zero-allocation no-op
tracer. There is no performance overhead for normal evaluation runs.

## Architecture

```
internal/core/trace/         — LogicTrace model (Assessment, Step, Summary)
internal/core/ports/tracer.go — Tracer + AssessmentSpan interfaces
internal/core/evaluation/engine/ — nopSpan (zero-cost when disabled)
internal/adapters/telemetry/ — LocalFileTracer (mutex-protected, air-gap safe)
```

The tracer is injected as a struct field on the Assessor, following the
same pattern as Logger and Clock. Strategies record steps via the
`currentSpan()` method on the strategy dependency interface.
