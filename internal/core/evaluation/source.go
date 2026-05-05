package evaluation

import (
	"context"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/controldef"
)

// FindingRequest is the input to a FindingSource.ProduceFindings call.
//
// Controls is the catalog the source MUST evaluate. Implementations
// silently skip controls outside their competence (e.g., a Z3 source
// that only models S3 leaves IAM controls to a peer source) — the
// shadow comparator then accounts for the empty-vs-non-empty
// difference rather than treating it as an error.
//
// Snapshots is the time-ordered observation grid. The source decides
// which snapshots it consumes; a stateless predicate evaluator may
// only inspect the latest, while a duration-aware solver walks the
// full history.
//
// Now is the audit timestamp the report is anchored to. Sources that
// reason about dwell time or SLA breach use Now (never the process
// wall clock) so every source in a shadow pair sees the identical
// clock.
//
// SLADefault is the catalog-level default for unsafe duration. Sources
// that compute SLA outcomes use this when a control declares no
// override; sources that only produce raw violations may ignore it.
type FindingRequest struct {
	Controls   []controldef.ControlDefinition
	Snapshots  []asset.Snapshot
	Now        time.Time
	SLADefault time.Duration
}

// FindingSource produces a finding set from a FindingRequest.
//
// Implementations are the swappable backends behind the assessor:
// the legacy CEL/strategy engine wrapped as InternalFindingSource
// today, a Z3-backed solver via subprocess in the future. The
// assessor composes them through this single interface — it never
// type-asserts to a concrete source.
//
// ctx cancellation MUST short-circuit the source. A source that
// ignores ctx is incompatible with the shadow timeout discipline
// and will be rejected at integration time.
//
// Architectural note: FindingSource lives in evaluation/ rather
// than ports/ because both controldef and evaluation/remediation
// already import ports for cross-cutting interfaces (Digester,
// Tracer, Clock); placing FindingSource in ports would invert
// those edges. evaluation/ is the natural home — Finding lives
// here, and FindingSource is the contract for things that produce
// Finding values.
type FindingSource interface {
	ProduceFindings(ctx context.Context, req FindingRequest) ([]Finding, error)
}
