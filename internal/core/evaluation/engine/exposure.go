package engine

import (
	"fmt"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/exposure"
	"github.com/sufield/stave/internal/core/predicate"
)

const (
	propExposureSource  = "exposure_source"
	propProtectedPrefix = "protected_prefix"
	valNotConfigured    = "not_configured"
	valConfigOverlap    = "config_overlap"
)

// prefixEvaluator groups the timeline and control that travel together
// through every prefix-exposure helper, eliminating repeated parameter passing.
type prefixEvaluator struct {
	timeline *asset.Timeline
	ctl      *policy.ControlDefinition
}

// EvaluatePrefixExposureForRow evaluates whether protected prefixes are publicly readable.
func EvaluatePrefixExposureForRow(
	timeline *asset.Timeline,
	ctl *policy.ControlDefinition,
) (evaluation.Row, []evaluation.Finding) {
	e := prefixEvaluator{timeline: timeline, ctl: ctl}
	return e.evaluate()
}

func (e *prefixEvaluator) evaluate() (evaluation.Row, []evaluation.Finding) {
	row := newPrefixExposureRow(e.timeline, e.ctl)

	// 1. Validate Control Configuration
	allowed, protected := prefixExposureSets(e.ctl)

	if protected.Empty() {
		return e.configIssue(row, msgMissingProtectedPrefixes(), valNotConfigured)
	}

	if conflict := allowed.Overlap(protected); conflict != nil {
		return e.overlapIssue(row, conflict)
	}

	// 2. Evaluate Asset Facts
	return e.assetExposure(row, protected)
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

func (e *prefixEvaluator) assetExposure(
	row evaluation.Row,
	protected policy.PrefixSet,
) (evaluation.Row, []evaluation.Finding) {
	facts := exposure.FactsFromStorage(e.timeline.Asset().Properties)
	var findings []evaluation.Finding

	for _, prefix := range protected.Prefixes() {
		res := facts.CheckExposure(prefix)
		if !res.Exposed {
			continue
		}

		evidence := res.String()
		findings = append(findings, *NewFinding(e.ctl, e.timeline, FindingContext{
			Reason: fmt.Sprintf("Protected prefix %q is publicly readable via %s.", prefix, evidence),
			Misconfigs: []policy.Misconfiguration{
				{Property: predicate.NewFieldPath(propExposureSource), ActualValue: evidence, Operator: predicate.OpEq, UnsafeValue: evidence},
				{Property: predicate.NewFieldPath(propProtectedPrefix), ActualValue: string(prefix), Operator: predicate.OpEq, UnsafeValue: string(prefix)},
			},
		}))
	}

	if len(findings) > 0 {
		row.Decision = evaluation.DecisionViolation
	}

	return row, findings
}

// --- Configuration Error Helpers ---

func (e *prefixEvaluator) configIssue(
	row evaluation.Row,
	why string,
	reasonCode string,
) (evaluation.Row, []evaluation.Finding) {
	row.Decision = evaluation.DecisionViolation
	f := NewFinding(e.ctl, e.timeline, FindingContext{
		Reason: why,
		Misconfigs: []policy.Misconfiguration{
			{Property: predicate.NewFieldPath(propExposureSource), ActualValue: reasonCode, Operator: predicate.OpEq, UnsafeValue: reasonCode},
		},
	})
	return row, []evaluation.Finding{*f}
}

func (e *prefixEvaluator) overlapIssue(
	row evaluation.Row,
	c *policy.PrefixConflict,
) (evaluation.Row, []evaluation.Finding) {
	row.Decision = evaluation.DecisionViolation
	f := NewFinding(e.ctl, e.timeline, FindingContext{
		Reason: fmt.Sprintf("Protected prefix %q overlaps with allowed prefix %q (config_overlap).", c.Protected, c.Allowed),
		Misconfigs: []policy.Misconfiguration{
			{Property: predicate.NewFieldPath(propExposureSource), ActualValue: valConfigOverlap, Operator: predicate.OpEq, UnsafeValue: valConfigOverlap},
			{Property: predicate.NewFieldPath("overlap_with"), ActualValue: string(c.Allowed), Operator: predicate.OpEq, UnsafeValue: string(c.Allowed)},
			{Property: predicate.NewFieldPath(propProtectedPrefix), ActualValue: string(c.Protected), Operator: predicate.OpEq, UnsafeValue: string(c.Protected)},
		},
	})
	return row, []evaluation.Finding{*f}
}

func prefixExposureSets(ctl *policy.ControlDefinition) (allowed, protected policy.PrefixSet) {
	p := ctl.ExposurePrefixes()
	return p.AllowedPublicPrefixes, p.ProtectedPrefixes
}

func msgMissingProtectedPrefixes() string {
	return "No protected prefixes configured. Add protected_prefixes to control params to enable detection."
}
