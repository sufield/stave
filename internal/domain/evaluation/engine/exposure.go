package engine

import (
	"fmt"
	"time"

	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/evaluation/exposure"
	"github.com/sufield/stave/internal/domain/policy"
)

const (
	propExposureSource  = "exposure_source"
	propProtectedPrefix = "protected_prefix"
	valNotConfigured    = "not_configured"
	valConfigOverlap    = "config_overlap"
)

// EvaluatePrefixExposureForRow evaluates whether protected prefixes are publicly readable.
func EvaluatePrefixExposureForRow(
	timeline *asset.Timeline,
	ctl *policy.ControlDefinition,
	_ time.Time,
) (evaluation.Row, []evaluation.Finding) {
	row := newPrefixExposureRow(timeline, ctl)

	// 1. Validate Control Configuration
	allowed, protected := prefixExposureSets(ctl)

	if protected.Empty() {
		return buildConfigIssue(row, ctl, timeline, msgMissingProtectedPrefixes(), valNotConfigured)
	}

	if conflict := policy.DetectOverlap(allowed, protected); conflict != nil {
		return buildOverlapIssue(row, ctl, timeline, conflict)
	}

	// 2. Evaluate Asset Facts
	return evaluateAssetExposure(row, ctl, timeline, protected)
}

func newPrefixExposureRow(t *asset.Timeline, ctl *policy.ControlDefinition) evaluation.Row {
	resType := t.Asset().Type
	return evaluation.Row{
		ControlID:   ctl.ID,
		AssetID:     t.ID,
		AssetType:   resType,
		AssetDomain: resType.Domain(),
		Decision:    evaluation.DecisionPass,
		Confidence:  evaluation.ConfidenceHigh,
	}
}

func evaluateAssetExposure(
	row evaluation.Row,
	ctl *policy.ControlDefinition,
	t *asset.Timeline,
	protected policy.PrefixSet,
) (evaluation.Row, []evaluation.Finding) {
	facts := exposure.FactsFromStorage(t.Asset().Properties)
	var findings []evaluation.Finding

	for _, prefix := range protected.Prefixes() {
		res := facts.CheckExposure(prefix)
		if !res.Exposed {
			continue
		}

		evidence := res.String()
		findings = append(findings, *NewFinding(ctl, t, FindingContext{
			Reason: fmt.Sprintf("Protected prefix %q is publicly readable via %s.", prefix, evidence),
			Misconfigs: []policy.Misconfiguration{
				{Property: propExposureSource, ActualValue: evidence, Operator: "eq", UnsafeValue: evidence},
				{Property: propProtectedPrefix, ActualValue: string(prefix), Operator: "eq", UnsafeValue: string(prefix)},
			},
		}))
	}

	if len(findings) > 0 {
		row.Decision = evaluation.DecisionViolation
	}

	return row, findings
}

// --- Configuration Error Helpers ---

func buildConfigIssue(
	row evaluation.Row,
	ctl *policy.ControlDefinition,
	t *asset.Timeline,
	why string,
	reasonCode string,
) (evaluation.Row, []evaluation.Finding) {
	row.Decision = evaluation.DecisionViolation
	f := NewFinding(ctl, t, FindingContext{
		Reason: why,
		Misconfigs: []policy.Misconfiguration{
			{Property: propExposureSource, ActualValue: reasonCode, Operator: "eq", UnsafeValue: reasonCode},
		},
	})
	return row, []evaluation.Finding{*f}
}

func buildOverlapIssue(
	row evaluation.Row,
	ctl *policy.ControlDefinition,
	t *asset.Timeline,
	c *policy.PrefixConflict,
) (evaluation.Row, []evaluation.Finding) {
	row.Decision = evaluation.DecisionViolation
	f := NewFinding(ctl, t, FindingContext{
		Reason: fmt.Sprintf("Protected prefix %q overlaps with allowed prefix %q (config_overlap).", c.Protected, c.Allowed),
		Misconfigs: []policy.Misconfiguration{
			{Property: propExposureSource, ActualValue: valConfigOverlap, Operator: "eq", UnsafeValue: valConfigOverlap},
			{Property: "overlap_with", ActualValue: string(c.Allowed), Operator: "eq", UnsafeValue: string(c.Allowed)},
			{Property: propProtectedPrefix, ActualValue: string(c.Protected), Operator: "eq", UnsafeValue: string(c.Protected)},
		},
	})
	return row, []evaluation.Finding{*f}
}

func prefixExposureSets(ctl *policy.ControlDefinition) (allowed, protected policy.PrefixSet) {
	p := ctl.ExposurePrefixes()
	return policy.NewPrefixSetFromPrefixes(p.AllowedPublicPrefixes),
		policy.NewPrefixSetFromPrefixes(p.ProtectedPrefixes)
}

func msgMissingProtectedPrefixes() string {
	return "No protected prefixes configured. Add protected_prefixes to control params to enable detection."
}
