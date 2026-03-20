package engine

import (
	"slices"
	"strings"
	"time"

	"github.com/sufield/stave/pkg/alpha/domain/asset"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation"
	"github.com/sufield/stave/pkg/alpha/domain/kernel"
	"github.com/sufield/stave/pkg/alpha/domain/maps"
	"github.com/sufield/stave/pkg/alpha/domain/policy"
)

const (
	pathPolicyStatements = "source_evidence.policy_public_statements"
	pathACLGrantees      = "source_evidence.acl_public_grantees"

	suffixIdentity = "_via_identity"
	suffixResource = "_via_resource"
)

// CreateDurationFinding generates a violation finding specifically for duration-based controls.
// Identities and predicateParser are required for correct evidence extraction
// on controls that use any_match or identity-based predicates.
func CreateDurationFinding(
	t *asset.Timeline,
	ctl *policy.ControlDefinition,
	threshold time.Duration,
	now time.Time,
	identities []asset.CloudIdentity,
	predicateParser func(any) (*policy.UnsafePredicate, error),
) *evaluation.Finding {
	a := t.Asset()
	duration := t.UnsafeDuration(now)
	ctx := policy.NewAssetEvalContext(a, ctl.Params, identities...)
	ctx.PredicateParser = predicateParser
	misconfigs := policy.ExtractMisconfigurations(&ctl.UnsafePredicate, ctx)
	causes := DeriveRootCauses(misconfigs)

	f := newBaseFinding(ctl, t)
	f.Evidence = evaluation.Evidence{
		FirstUnsafeAt:       t.FirstUnsafeAt(),
		LastSeenUnsafeAt:    t.LastSeenUnsafeAt(),
		UnsafeDurationHours: duration.Hours(),
		ThresholdHours:      threshold.Hours(),
		Misconfigurations:   misconfigs,
		RootCauses:          causes,
		SourceEvidence:      ExtractSourceEvidence(a, causes),
		WhyNow:              t.FormatUnsafeSummary(threshold, now),
	}
	return f
}

// DeriveRootCauses maps misconfiguration property paths to high-level mechanism labels.
// Stable order: policy before acl. Returns nil if no mechanisms detected.
func DeriveRootCauses(misconfigs []policy.Misconfiguration) []evaluation.RootCause {
	var hasIdentity, hasResource bool
	for _, mc := range misconfigs {
		if strings.Contains(mc.Property, suffixIdentity) {
			hasIdentity = true
		}
		if strings.Contains(mc.Property, suffixResource) {
			hasResource = true
		}
	}

	var causes []evaluation.RootCause
	if hasIdentity {
		causes = append(causes, evaluation.RootCauseIdentity)
	}
	if hasResource {
		causes = append(causes, evaluation.RootCauseResource)
	}
	return causes
}

// ExtractSourceEvidence retrieves supporting raw data from the asset based on the detected root causes.
func ExtractSourceEvidence(a asset.Asset, causes []evaluation.RootCause) *evaluation.SourceEvidence {
	if len(causes) == 0 {
		return nil
	}

	props := maps.ParseMap(a.Properties)
	evidence := &evaluation.SourceEvidence{}

	for _, cause := range causes {
		switch cause {
		case evaluation.RootCauseIdentity:
			evidence.IdentityStatements = getSortedIDs[kernel.StatementID](props, pathPolicyStatements)
		case evaluation.RootCauseResource:
			evidence.ResourceGrantees = getSortedIDs[kernel.GranteeID](props, pathACLGrantees)
		}
	}

	if len(evidence.IdentityStatements) == 0 && len(evidence.ResourceGrantees) == 0 {
		return nil
	}
	return evidence
}

// getSortedIDs extracts a string slice from a property path, converts to typed IDs, and sorts.
func getSortedIDs[T ~string](props maps.Value, path string) []T {
	values := props.GetPath(path).StringSlice()
	if len(values) == 0 {
		return nil
	}
	slices.Sort(values)
	ids := make([]T, len(values))
	for i, v := range values {
		ids[i] = T(v)
	}
	return ids
}
