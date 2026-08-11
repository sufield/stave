package engine

import (
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/ports"
)

// ---------------------------------------------------------------------------
// AssessorBuilder — reduces 15-line Assessor construction to a fluent chain.
//
// Usage:
//   a := newTestAssessor().
//       withClock(base.Add(48 * time.Hour)).
//       withSLA(168 * time.Hour).
//       withControls(ctl1, ctl2).
//       alwaysUnsafe().
//       build()
//   result, err := a.Assess(snapshots)
// ---------------------------------------------------------------------------

type assessorBuilder struct {
	clock         ports.Clock
	sla           time.Duration
	controls      []policy.ControlDefinition
	predicateEval policy.PredicateEval
	exemptions    *policy.ExemptionConfig
	exceptions    *policy.ExceptionConfig
	tracer        ports.Tracer
}

func newTestAssessor() *assessorBuilder {
	return &assessorBuilder{
		clock:      stubClock{t: time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)},
		sla:        168 * time.Hour,
		exemptions: policy.NewExemptionConfig("", nil),
		exceptions: policy.NewExceptionConfig(nil),
	}
}

func (b *assessorBuilder) withClock(t time.Time) *assessorBuilder {
	b.clock = stubClock{t: t}
	return b
}

func (b *assessorBuilder) withSLA(d time.Duration) *assessorBuilder {
	b.sla = d
	return b
}

func (b *assessorBuilder) withControls(ctls ...policy.ControlDefinition) *assessorBuilder {
	b.controls = ctls
	return b
}

// alwaysUnsafe sets the predicate evaluator to always return true (asset is unsafe).
func (b *assessorBuilder) alwaysUnsafe() *assessorBuilder {
	b.predicateEval = func(_ *policy.ControlDefinition, _ asset.Asset, _ []asset.CloudIdentity) (bool, error) {
		return true, nil
	}
	return b
}

// alwaysSafe sets the predicate evaluator to always return false (asset is safe).
func (b *assessorBuilder) alwaysSafe() *assessorBuilder {
	b.predicateEval = func(_ *policy.ControlDefinition, _ asset.Asset, _ []asset.CloudIdentity) (bool, error) {
		return false, nil
	}
	return b
}

func (b *assessorBuilder) withTracer(t ports.Tracer) *assessorBuilder {
	b.tracer = t
	return b
}

func (b *assessorBuilder) build() *Assessor {
	a := NewAssessor()
	a.clock = b.clock
	a.slaThreshold = b.sla
	a.controls = b.controls
	a.exemptions = b.exemptions
	a.exceptions = b.exceptions
	a.predicateEval = b.predicateEval
	if a.predicateEval == nil {
		// Default the precondition fields so tests that don't care about
		// predicate evaluation continue to satisfy Assess()'s preconditions.
		a.predicateEval = func(_ *policy.ControlDefinition, _ asset.Asset, _ []asset.CloudIdentity) (bool, error) {
			return false, nil
		}
	}
	a.predicateParser = func(_ any) (*policy.UnsafePredicate, error) {
		return &policy.UnsafePredicate{}, nil
	}
	a.tracer = b.tracer
	return a
}

// ---------------------------------------------------------------------------
// ControlBuilder — reduces control definition construction.
//
// Usage:
//   ctl := newTestControl("CTL.TEST.DURATION.001").
//       typed(policy.TypeUnsafeDuration).
//       build()
// ---------------------------------------------------------------------------

type controlBuilder struct {
	id  string
	nm  string
	typ policy.ControlType
	sev policy.Severity
}

func newTestControl(id string) *controlBuilder {
	return &controlBuilder{
		id:  id,
		nm:  "Test Control",
		typ: policy.TypeUnsafeState,
		sev: policy.SeverityHigh,
	}
}

func (b *controlBuilder) typed(t policy.ControlType) *controlBuilder {
	b.typ = t
	return b
}

func (b *controlBuilder) build() policy.ControlDefinition {
	return policy.ControlDefinition{
		ID:       kernel.ControlID(b.id),
		Name:     b.nm,
		Type:     b.typ,
		Severity: b.sev,
	}
}

// ---------------------------------------------------------------------------
// SnapshotBuilder — reduces snapshot construction for lifecycle tests.
//
// Usage:
//   snaps := newLifecycleBuilder(base).
//       at(0, "bucket-1").
//       at(48*time.Hour, "bucket-1").
//       build()
// ---------------------------------------------------------------------------

type lifecycleBuilder struct {
	base      time.Time
	snapshots []asset.Snapshot
}

func newLifecycleBuilder(base time.Time) *lifecycleBuilder {
	return &lifecycleBuilder{base: base}
}

// at adds a snapshot at base+offset with the given asset IDs.
func (b *lifecycleBuilder) at(offset time.Duration, assetIDs ...string) *lifecycleBuilder {
	assets := make([]asset.Asset, len(assetIDs))
	for i, id := range assetIDs {
		assets[i] = asset.Asset{ID: asset.ID(id), Type: "s3_bucket"}
	}
	b.snapshots = append(b.snapshots, asset.Snapshot{
		CapturedAt: b.base.Add(offset),
		Assets:     assets,
	})
	return b
}

func (b *lifecycleBuilder) build() []asset.Snapshot {
	return b.snapshots
}

// Assertion helpers moved to internal/testutil — use testutil.AssertViolationCount,
// testutil.AssertSecurityState, testutil.AssertNoError, etc.
