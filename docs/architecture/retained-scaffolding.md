# Retained Scaffolding — Zero-Caller Code That Must Not Be Deleted

Code identified by automated dead-code analysis (ponytail-audit, 2026-07-02)
as having zero production callers but retained because it is architectural
scaffolding for backlog items. Deleting it removes work that would be rebuilt
from scratch.

## Compound Chain Engine

**Files:** `internal/core/compliance/compound/rules.go`, `compound_test.go`

**Backlog:** FM-042, FM-046, FM-063, FM-079 (TASK-011 through TASK-015)

Three concrete compound rules (COMPOUND.001–003) define cross-control
correlation patterns: public-access + overly-broad-IAM, encryption-without-
access-control, and VPC-endpoint-without-endpoint-policy. Full test coverage
for all three rules plus the `Detect()` driver.

Zero callers today because compound chains are not wired into the evaluation
pipeline yet — the rules are prompt-ready, implementation pending. The
`Detect(rules, outcomes)` function and the `Rule` type are the integration
surface for the pipeline work.

**Delete when:** compound chain evaluation ships via FM-042 and these rules
are either integrated or superseded by a different composition mechanism.

## Hexagonal Port Contracts

**Files:** `internal/core/ports/alert.go`, `internal/core/ports/evidence.go`

**Backlog:** continuous monitoring (alert delivery), evidence packaging
(air-gap transfer)

`AlertSink` defines the contract for watch-mode alert delivery: transition
types (REGRESSION, RECOVERY, DEGRADATION, STABLE, INITIAL, ERROR), SLA
metrics, and owner-routing fields. `EvidenceBundler` defines the contract for
cryptographically sealed evidence archives.

Zero implementors today because no adapter exists yet. In the hexagonal
architecture, a port with no adapter means "contract defined, adapter
pending" — not dead code. Compound chains will need alert delivery
("emit a finding with evidence") and the interface is already designed.

**Delete when:** the port is superseded by a different contract, or the
feature is explicitly abandoned.

## Kernel ID Types

**Files:** `internal/core/kernel/finding_id.go`, `internal/core/kernel/issue_id.go`, `internal/core/kernel/chain_id.go`

**Backlog:** compound chain dedup, issue consolidation

Typed-string constructors with empty-value guards. `FindingID` is the
per-(control, asset) fingerprint for dedup. `IssueID` is the per-(asset,
shared-keys, headline-control) fingerprint for issue consolidation. `ChainID`
identifies compound-risk chain definitions.

The types themselves are used in struct definitions across the kernel; the
`New*` constructors are the boundary check that prevents empty-string
foot-guns during compound chain evaluation. Zero callers today because the
compound chain pipeline hasn't wired them yet.

**Delete when:** compound chain evaluation ships and either uses these
constructors or replaces them with a different validation approach.

## go-z3 Dependency (main go.mod)

**File:** `go.mod` (direct dependency on `github.com/aclements/go-z3`)

**Backlog:** FM-060 (TASK-011) — production Z3 SMT integration

The dependency has zero imports in the main module (`cmd/`, `internal/`,
`pkg/`). All 25 imports are in `examples/` and `experiments/` which declare
their own `go.mod` with `replace` directives.

`go mod tidy` correctly removes it from the main `go.mod` — this is safe.
The `examples/` and `experiments/` directories containing the Z3 prototypes
must NOT be deleted; they are the reference implementation for FM-060.

**Action:** run `go mod tidy` to clean the main `go.mod`. Leave the
prototype directories untouched.
