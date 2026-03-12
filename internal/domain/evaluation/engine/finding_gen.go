package engine

import (
	"slices"
	"strings"
	"time"

	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/policy"
	"github.com/sufield/stave/internal/pkg/maps"
)

const (
	pathPolicyStatements = "source_evidence.policy_public_statements"
	pathACLGrantees      = "source_evidence.acl_public_grantees"

	suffixIdentity = "_via_identity"
	suffixResource = "_via_resource"
)

// CreateDurationFinding generates a violation finding specifically for duration-based controls.
func CreateDurationFinding(
	t *asset.Timeline,
	ctl *policy.ControlDefinition,
	threshold time.Duration,
	now time.Time,
) *evaluation.Finding {
	a := t.Asset()
	duration := t.UnsafeDuration(now)
	misconfigs := policy.ExtractMisconfigurations(&ctl.UnsafePredicate, a.Properties)
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
		causes = append(causes, evaluation.RootCausePolicy)
	}
	if hasResource {
		causes = append(causes, evaluation.RootCauseACL)
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
		case evaluation.RootCausePolicy:
			evidence.PolicyPublicStatements = getSortedEvidence(props, pathPolicyStatements)
		case evaluation.RootCauseACL:
			evidence.ACLPublicGrantees = getSortedEvidence(props, pathACLGrantees)
		}
	}

	if len(evidence.PolicyPublicStatements) == 0 && len(evidence.ACLPublicGrantees) == 0 {
		return nil
	}
	return evidence
}

// getSortedEvidence extracts a string slice from a property path and sorts it for deterministic output.
func getSortedEvidence(props maps.Value, path string) []string {
	values := props.GetPath(path).StringSlice()
	if len(values) == 0 {
		return nil
	}
	slices.Sort(values)
	return values
}
