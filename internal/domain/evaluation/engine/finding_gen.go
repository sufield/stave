package engine

import (
	"sort"
	"strings"
	"time"

	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/policy"
	"github.com/sufield/stave/internal/pkg/maps"
)

const (
	sourceEvidencePolicyStatementsPath = "source_evidence.policy_public_statements"
	sourceEvidenceACLGranteesPath      = "source_evidence.acl_public_grantees"
)

// CreateDurationFinding generates a finding for a specific control.
func CreateDurationFinding(
	timeline *asset.Timeline,
	ctl *policy.ControlDefinition,
	maxUnsafe time.Duration,
	now time.Time,
) evaluation.Finding {
	duration := timeline.UnsafeDuration(now)
	resource := timeline.Asset()
	misconfigs := policy.ExtractMisconfigurations(&ctl.UnsafePredicate, resource.Properties)
	rootCauses := DeriveRootCauses(misconfigs)

	f := baseFinding(ctl, timeline)
	f.Evidence = evaluation.Evidence{
		FirstUnsafeAt:       timeline.FirstUnsafeAt(),
		LastSeenUnsafeAt:    timeline.LastSeenUnsafeAt(),
		UnsafeDurationHours: duration.Hours(),
		ThresholdHours:      maxUnsafe.Hours(),
		Misconfigurations:   misconfigs,
		RootCauses:          rootCauses,
		SourceEvidence:      ExtractSourceEvidence(resource, rootCauses),
		WhyNow:              timeline.FormatUnsafeSummary(maxUnsafe, now),
	}
	return f
}

// DeriveRootCauses extracts mechanism labels from misconfiguration property paths.
// Paths containing "_via_policy" produce "policy"; "_via_acl" produce "acl".
// Stable order: policy before acl. Returns nil if no mechanisms detected.
func DeriveRootCauses(misconfigs []policy.Misconfiguration) []evaluation.RootCause {
	hasPolicy := false
	hasACL := false
	for _, mc := range misconfigs {
		if strings.Contains(mc.Property, "_via_policy") {
			hasPolicy = true
		}
		if strings.Contains(mc.Property, "_via_acl") {
			hasACL = true
		}
	}
	var causes []evaluation.RootCause
	if hasPolicy {
		causes = append(causes, evaluation.RootCausePolicy)
	}
	if hasACL {
		causes = append(causes, evaluation.RootCauseACL)
	}
	return causes
}

// ExtractSourceEvidence extracts source evidence from canonical resource
// properties. The domain relies only on canonical fields and does not read
// vendor-specific property paths.
func ExtractSourceEvidence(resource asset.Asset, rootCauses []evaluation.RootCause) *evaluation.SourceEvidence {
	if len(rootCauses) == 0 {
		return nil
	}

	props := maps.ParseMap(resource.Properties)
	evidence := &evaluation.SourceEvidence{}

	for _, cause := range rootCauses {
		populateSourceEvidenceForCause(cause, props, evidence)
	}

	if len(evidence.PolicyPublicStatements) == 0 && len(evidence.ACLPublicGrantees) == 0 {
		return nil
	}
	return evidence
}

func populateSourceEvidenceForCause(cause evaluation.RootCause, props maps.Value, evidence *evaluation.SourceEvidence) {
	switch cause {
	case evaluation.RootCausePolicy:
		evidence.PolicyPublicStatements = populateSourceEvidenceList(
			evidence.PolicyPublicStatements,
			props,
			sourceEvidencePolicyStatementsPath,
		)
	case evaluation.RootCauseACL:
		evidence.ACLPublicGrantees = populateSourceEvidenceList(
			evidence.ACLPublicGrantees,
			props,
			sourceEvidenceACLGranteesPath,
		)
	}
}

func populateSourceEvidenceList(existing []string, props maps.Value, path string) []string {
	if len(existing) > 0 {
		return existing
	}
	values := props.GetPath(path).StringSlice()
	sort.Strings(values)
	return values
}
