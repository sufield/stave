package engine

import (
	"slices"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
)

// DurationFindingInput groups the data required to build a duration-based violation finding.
type DurationFindingInput struct {
	Timeline        *asset.Timeline
	Control         *policy.ControlDefinition
	Threshold       time.Duration
	Now             time.Time
	Identities      []asset.CloudIdentity
	PredicateParser policy.PredicateParser
}

// CreateDurationFinding generates a violation finding specifically for duration-based controls.
func CreateDurationFinding(in DurationFindingInput) *evaluation.Finding {
	a := in.Timeline.Asset()
	duration, _ := in.Timeline.UnsafeDuration(in.Now)
	ctx := policy.NewAssetEvalContext(a, in.Control.Params, in.PredicateParser, in.Identities...)
	misconfigs := policy.ExtractMisconfigurations(&in.Control.UnsafePredicate, ctx)
	causes := DeriveRootCauses(misconfigs)

	f := newBaseFinding(in.Control, in.Timeline)
	f.Evidence = evaluation.Evidence{
		FirstUnsafeAt:       in.Timeline.FirstUnsafeAt(),
		LastSeenUnsafeAt:    in.Timeline.LastSeenUnsafeAt(),
		UnsafeDurationHours: duration.Hours(),
		ThresholdHours:      in.Threshold.Hours(),
		Misconfigurations:   misconfigs,
		RootCauses:          causes,
		SourceEvidence:      ExtractSourceEvidence(a, causes),
		WhyNow:              in.Timeline.FormatUnsafeSummary(in.Threshold, in.Now),
	}
	return f
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
