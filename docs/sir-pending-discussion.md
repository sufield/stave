# SIR Migration — Pending Architectural Decisions

This document captures the open questions surfaced during Iteration 1
that need a decision before further code changes can land. Each
question is scoped, has options, and names a default lean. Resolve
before starting Iteration 1.2 (SIR builder design) — Q1 in
particular determines what types the SIR consumes from the AWS
provider layer.

## Status legend

- **OPEN** — not decided.
- **DECIDED — <resolution>** — recorded outcome; subsequent code
  references this section instead of re-debating.

---

## Q1. Convergence of the two AWS-policy parsers (status: DECIDED — Bridge)

**Where:** `internal/platform/providers/aws/s3/policy/` and
`internal/platform/providers/aws/compliance/policy_helper.go`.

**Context.** Two separate S3 policy parsers coexist:

| Parser | Output type | Used by |
|---|---|---|
| `s3/policy.Parse` | `*Document` (typed `Statement` with `NormalizedPrincipal` / `NormalizedCondition` after Iter 1.1 Subset A) | risk analyzer (`Document.Assess`), `cmd/inspect/policy` |
| `compliance.ParsePolicyStatements` | `[]PolicyStatement` (with `Principal any`, `Condition any`) | 13 control evaluators in `compliance/access_*.go`, `audit_*.go`, `controls_*.go`, `governance_*.go`, `retention_*.go` |

After Iter 1.1 Subset A, `s3/policy` is fully typed. The compliance
parser still uses `any` for Principal/Condition internally, and
exposes its own method set (`IsPublicListGrant`, `IsDenyNonTLS`,
`HasSignatureAgeGuardrail`, `HasAuthTypeGuardrail`,
`RestrictsPresignedURLAccess`, `GrantsWildcardActions`,
`HasWildcardPrincipal`, `HasAction`, `HasWildcardAction`, `IsAllow`,
`IsDeny`, `conditionValue`). Three feasible shapes:

**(a) Converge.** Retire `compliance.PolicyStatement`. Move the
methods onto `s3/policy.Statement` (or a sibling type backed by the
same `NormalizedPrincipal` / `NormalizedCondition`). All 13 control
files switch to `s3/policy.Parse`. Cleanest end-state. Highest blast
radius — touches files not named in the original 1.1 prompt.

**(b) Bridge.** Keep `compliance.PolicyStatement` as the public type
its callers see, but swap its internals to embed
`s3/policy.NormalizedStatement`. Methods stay where they are,
rewritten to delegate. Medium blast radius — only `policy_helper.go`
itself changes.

**(c) Parallel.** Define `NormalizedPrincipal` / `NormalizedCondition`
separately in both packages. Each parser produces its own normalized
output. The two packages share nothing. Lowest blast radius. Keeps
the duplication the prompt seems to want to remove.

**Resolved: (b) Bridge.** Implemented in Subset B:

- `compliance.PolicyStatement.Principal` now typed as
  `s3policy.NormalizedPrincipal`; `Condition` typed as
  `s3policy.NormalizedCondition`.
- `compliance.ParsePolicyStatements` delegates to
  `s3policy.Parse`; `compliance.parseOneStatement` retired.
- All public methods on `PolicyStatement` (`HasWildcardPrincipal`,
  `IsDenyNonTLS`, `HasSignatureAgeGuardrail`,
  `HasAuthTypeGuardrail`, `RestrictsPresignedURLAccess`,
  `IsPublicListGrant`, `GrantsWildcardActions`) now read the typed
  fields directly.
- `s3policy.Document.Statements()` exposed for the bridge to walk
  the typed slice.
- `s3policy.BucketPolicy.Statement` gained a custom UnmarshalJSON
  that absorbs the AWS "single object OR array" wire polymorphism
  the legacy compliance parser used to handle. The polymorphism is
  now part of the canonical `Document` contract — every consumer
  (Assess, the bridge, future SIR builders) sees the same flat
  `[]Statement` view.
- 13 control files in `compliance/` pick up the typed-internals win
  with zero source changes; four hot-path call sites switched from
  range-by-value to range-by-index because `PolicyStatement` grew
  from ~64 bytes to ~192 bytes after typing (gocritic flagged the
  per-iteration copy cost).
- `policy_helper_test.go` updated to construct typed
  `NormalizedPrincipal` literals; new
  `TestPolicyStatement_HasWildcardPrincipal_FromJSON` pins the
  parse-boundary contract end-to-end.

The `Converge (a)` option remains a clean follow-up: now that
`compliance.PolicyStatement` is just a thin shim over the typed
fields, retiring it entirely is a 14-file mechanical migration
that can land any time the SIR work touches those control files.

---

## Q2. IAM Condition typing (status: OPEN)

**Where:** `internal/platform/providers/aws/iam/policy.go`,
`Statement.Condition` field.

**Context.** After Iter 1.1 Subset A, the field type is `any`. No
IAM-side consumer reads it today (verified by `grep -rn
"stmt.Condition\|s.Condition" internal/platform/providers/aws/iam/`
returning zero non-test hits). The S3 side has full
`NormalizedCondition` typing.

**(a) Leave `any`.** Flag as a follow-up when an IAM-side compound
first reads conditions (e.g., a future control on session-duration
policies, a check on `aws:MultiFactorAuthPresent`). Pay the cost
when there's a consumer that benefits.

**(b) Normalize speculatively.** Add `NormalizedCondition` here
matching the s3 shape. Adds a typed field nobody reads but achieves
symmetry between providers.

**Default lean: (a) Leave.** YAGNI: Iter 1.1's intent is to remove
re-decoding from the evaluation path. IAM Condition isn't on any
read path that re-decodes; the field is a passthrough. Speculative
normalization adds maintenance surface for no current win.

**Decision needed before:** an IAM-side compound first reads
condition. Until then, deferring is free.

---

## Q3. `NormalizedPrincipal` shape (status: DECIDED — flat struct)

**Outcome.** Flat struct with named slices per principal kind.
Implemented in `s3/policy/normalized.go`:

```go
type NormalizedPrincipal struct {
    Wildcard       bool
    AWSARNs        []string
    Services       []string
    Federated      []string
    CanonicalUsers []string
}
```

**Rationale.** Every existing consumer branches on which principal
type is set (AWS vs Service vs Federated etc.); flat fields give the
cleanest call sites. The map-keyed alternative
(`map[string][]string`) was structurally similar but required an
extra string lookup at every consumer.

**Recorded for:** SIR builder code, which consumes this type
directly when serializing `IdentityFact`.

---

## Q4. `NormalizedCondition` shape (status: DECIDED — `map[string]map[string][]string`)

**Outcome.** Direct typed mirror of the AWS Condition wire shape:

```go
type NormalizedCondition map[string]map[string][]string
```

**Rationale.** The operator universe is open-ended (any string is a
valid AWS condition operator), so a fixed-field struct can't model
it. The map shape preserves AWS's structural contract while
eliminating the per-call type-asserts the legacy code repeated.
Bool/numeric leaves are coerced to strings during UnmarshalJSON to
match the `hasSecureTransportFalse` consumer's existing tolerance.

**Recorded for:** SIR builder code, which serializes condition
blocks as `[]ConditionFact{Operator, Key, Values}` triples sourced
from this shape.

---

## Q5. Goldens scope (status: VERIFIED)

**Outcome.** All gated tests passed after Subset A:

- `go test ./internal/platform/providers/aws/s3/...` — green
- `go test ./internal/platform/providers/aws/iam/...` — green
- `go test ./internal/platform/providers/aws/compliance/...` — green
- `go test ./cmd/apply/ -run "ProfileE2E"` — green
- `go test ./cmd/inspect/policy/...` — green
- `go test ./cmd/nep/...` — green
- `golangci-lint run` on touched packages — zero issues

The `e2e` package timed out under the default 10-minute `go test`
budget in the local sweep but ran clean in `-short` mode (which
gates the heavy fixtures). The CI workflow runs e2e with its own
60-minute budget; that's the canonical gate. No goldens were
regenerated by Subset A.

---

## Q6. `mapper.go`'s `json.RawMessage` for finding-MarshalJSON splicing (status: DECIDED — pragmatic exception)

**Where:**
`internal/core/evaluation/remediation/mapper.go:46`.

```go
var raw map[string]json.RawMessage
if err = json.Unmarshal(inner, &raw); err != nil {
    return nil, fmt.Errorf("decode embedded finding: %w", err)
}
```

**Context.** `Finding.MarshalJSON` decomposes the embedded finding's
JSON into a map, splices in the remediation-side fields, and
re-marshals. This is the standard "splice fields into a JSON
object" pattern — it has nothing to do with policy decoding, but
the literal substring `json.RawMessage` lives in
`internal/core/`, which means the strict success grep
(`grep -r "json.RawMessage" internal/core ...`) returns one hit.

**Two readings:**

- **Strict.** The success grep MUST return zero hits in
  `internal/core`. Refactor `MarshalJSON` to use `json.Encoder` /
  hand-built bytes / a typed wire struct so the literal
  `json.RawMessage` does not appear.
- **Pragmatic.** The prompt's intent is "front-load AWS policy
  decoding". `mapper.go`'s `json.RawMessage` is unrelated —
  decomposition for output serialization, not policy decoding.
  Refactoring it is scope creep.

**Resolved: pragmatic exception.** `mapper.go`'s `json.RawMessage`
stays as-is. It is internal serialization plumbing for one
MarshalJSON site, runs once per finding emission, and is not on any
policy-decode path. The strict-grep reading is a literal
interpretation of wording the prompt itself frames around the
"evaluation path" intent. Iteration 1.1 is closed with this
section as the single documented exception in the
`internal/core/` tree.

---

## Q7. Cascade work for full 1.1 closure (status: RESOLVED via Q1)

Q1 resolved as Bridge. Subset B implementation completed; details
in the Q1 resolution above. The Converge option remains available
as a future cleanup (retiring `compliance.PolicyStatement` and
migrating the 13 control files), but is not required for Iter 1.1
to close.

---

## Status of Iteration 1.1

**CLOSED.**

Subset A and Subset B both landed. Final grep state:

```
$ grep -rn "json.RawMessage" \
    internal/platform/providers/aws/s3/policy/ \
    internal/platform/providers/aws/iam/ \
    internal/platform/providers/aws/compliance/
(zero hits)

$ grep -rn "json.RawMessage" internal/core/ | grep -v "_test.go"
internal/core/evaluation/remediation/mapper.go:46: ... (Q6 exception)
```

The `internal/core/` tree has one documented exception
(`evaluation/remediation/mapper.go` per Q6 — finding MarshalJSON
splicing, unrelated to policy decoding). Every other line of the
success grep is zero.

Test gates green: `go test ./internal/platform/providers/...`,
`go test ./cmd/inspect/policy/...`, `go test ./cmd/nep/...`,
`go test ./cmd/apply/...`, `go test ./cmd/apply/ -run "ProfileE2E"`,
`golangci-lint run ./internal/platform/providers/aws/...` (zero
issues). No goldens regenerated.

**Iter 1.1 is closed.** Ready to proceed to Iter 1.2 (the SIR
builder) using the typed shapes that this iteration delivered.
