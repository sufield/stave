package engine

import (
	"errors"
	"slices"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
)

// DurationFindingInput groups the data required to build a duration-based violation finding.
type DurationFindingInput struct {
	ExposureLifecycle *asset.ExposureLifecycle
	Control           *policy.ControlDefinition
	Threshold         time.Duration
	Now               time.Time
	Identities        []asset.CloudIdentity
	PredicateParser   policy.PredicateParser
}

// CreateDurationFinding generates a violation finding specifically for
// duration-based controls.
//
// Return contract — callers must check both values:
//   - (finding, nil): success. Use the finding.
//   - (finding, err): partial success. The finding is still populated
//     (with UnsafeDurationHours set to the -1 sentinel) so the violation
//     is still emitted, and the caller is expected to surface err via
//     its own logger — core/ stays free of side effects.
//   - (nil, err): hard precondition failure. The function rejects
//     malformed input (currently: nil ExposureLifecycle) and returns
//     no finding. Callers that assumed "always non-nil finding" would
//     panic on the next dereference; the strategy.go call site
//     therefore nil-checks the finding before consuming it.
func CreateDurationFinding(in DurationFindingInput) (*evaluation.Finding, error) {
	if in.ExposureLifecycle == nil {
		// Required input. Returning early keeps the engine from
		// dereferencing a nil pointer in the duration / asset path
		// — a malformed call site (test harness, partial result
		// reconstruction) should fail loud rather than panic.
		return nil, errors.New("CreateDurationFinding: ExposureLifecycle is required")
	}
	if in.Control == nil {
		// Sibling guard: in.Control.Params and in.Control.UnsafePredicate
		// are dereferenced below, and newBaseFinding's ctl.Metadata()
		// would also fault. Same fail-loud rationale as the
		// ExposureLifecycle branch — a malformed call site is the
		// only way this fires.
		return nil, errors.New("CreateDurationFinding: Control is required")
	}
	a := in.ExposureLifecycle.Asset()
	duration, durationErr := in.ExposureLifecycle.ExposureDuration(in.Now)
	if durationErr != nil {
		// Sentinel: -1 hour. Plain `-1` is a Duration of -1 nanosecond,
		// and -1ns.Hours() ≈ -2.78e-13, which downstream renderers
		// would print as "0.00 hours" — visually indistinguishable
		// from a real "no exposure observed" result. Using -1 hour
		// makes the sentinel render as "-1.00" so the failed
		// calculation is obvious in evidence output.
		duration = -1 * time.Hour
	}
	ctx := policy.NewAssetEvalContext(a, in.Control.Params, in.PredicateParser, in.Identities...)
	misconfigs := policy.ExtractMisconfigurations(&in.Control.UnsafePredicate, ctx)
	causes := DeriveRootCauses(misconfigs)

	f := newBaseFinding(in.Control, in.ExposureLifecycle)
	f.Evidence = evaluation.Evidence{
		FirstUnsafeAt:       in.ExposureLifecycle.FirstExposedAt(),
		LastSeenUnsafeAt:    in.ExposureLifecycle.LastObservedAt(),
		UnsafeDurationHours: duration.Hours(),
		ThresholdHours:      in.Threshold.Hours(),
		Misconfigurations:   misconfigs,
		RootCauses:          causes,
		SourceEvidence:      ExtractSourceEvidence(a, causes),
		TemporalRisk:        in.ExposureLifecycle.FormatExposureSummary(in.Threshold, in.Now),
	}
	f.ReasoningTrace = evaluation.ReasoningTraceFromMisconfigurations(misconfigs)
	f.Delta = policy.DeriveDeltas(misconfigs)
	return f, durationErr
}

// DeriveRootCauses maps misconfiguration categories to high-level mechanism labels.
// Stable order: identity before resource. Returns [RootCauseGeneral] if
// misconfigurations exist but none are categorized.
func DeriveRootCauses(misconfigs []policy.Misconfiguration) []evaluation.RootCause {
	found := make(map[policy.Category]bool)
	for _, mc := range misconfigs {
		found[mc.Category] = true
	}

	var causes []evaluation.RootCause
	if found[policy.CategoryIdentity] {
		causes = append(causes, evaluation.RootCauseIdentity)
	}
	if found[policy.CategoryResource] {
		causes = append(causes, evaluation.RootCauseResource)
	}
	if len(causes) == 0 && len(misconfigs) > 0 {
		causes = append(causes, evaluation.RootCauseGeneral)
	}
	return causes
}

// ExtractSourceEvidence retrieves supporting raw data from the asset based on the detected root causes.
func ExtractSourceEvidence(a asset.Asset, causes []evaluation.RootCause) *evaluation.SourceEvidence {
	if len(causes) == 0 {
		return nil
	}

	evidence := &evaluation.SourceEvidence{}

	for _, cause := range causes {
		switch cause {
		case evaluation.RootCauseIdentity:
			evidence.IdentityStatements = toSorted[kernel.StatementID](a.PolicyStatementIDs())
		case evaluation.RootCauseResource:
			evidence.ResourceGrantees = toSorted[kernel.GranteeID](a.ACLGranteeIDs())
		}
	}

	if len(evidence.IdentityStatements) == 0 && len(evidence.ResourceGrantees) == 0 {
		return nil
	}
	return evidence
}

// toSorted clones a string slice, sorts it, and converts to typed IDs.
func toSorted[T ~string](values []string) []T {
	if len(values) == 0 {
		return nil
	}
	sorted := slices.Clone(values)
	slices.Sort(sorted)
	ids := make([]T, len(sorted))
	for i, v := range sorted {
		ids[i] = T(v)
	}
	return ids
}
