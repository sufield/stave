package engine

import (
	"fmt"
	"time"

	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/evaluation/exposure"
	"github.com/sufield/stave/internal/domain/policy"
)

// EvaluatePrefixExposureForRow evaluates a prefix_exposure control for a
// single resource. It checks whether any protected prefixes are publicly
// readable using normalized storage.prefix_exposure facts prepared by input
// adapters.
func EvaluatePrefixExposureForRow(
	timeline *asset.Timeline,
	ctl *policy.ControlDefinition,
	_ time.Time,
) (evaluation.Row, []evaluation.Finding) {
	row := newPrefixExposureRow(timeline, ctl)
	allowed, protected := prefixExposureSets(ctl)

	if protected.Empty() {
		return prefixExposureNotConfigured(row, ctl, timeline)
	}

	if conflict := policy.DetectOverlap(allowed, protected); conflict != nil {
		return prefixExposureOverlap(row, ctl, timeline, conflict)
	}
	return prefixExposureFindings(row, ctl, timeline, protected)
}

func newPrefixExposureRow(timeline *asset.Timeline, ctl *policy.ControlDefinition) evaluation.Row {
	resourceType := timeline.Asset().Type
	return evaluation.Row{
		ControlID:   ctl.ID,
		AssetID:     timeline.ID,
		AssetType:   resourceType,
		AssetDomain: resourceType.Domain(),
		Decision:    evaluation.DecisionPass,
		Confidence:  evaluation.ConfidenceHigh,
	}
}

func prefixExposureSets(ctl *policy.ControlDefinition) (policy.PrefixSet, policy.PrefixSet) {
	p := ctl.ExposurePrefixes()
	return policy.NewPrefixSet(p.AllowedPublicPrefixes),
		policy.NewPrefixSet(p.ProtectedPrefixes)
}

func prefixExposureNotConfigured(
	row evaluation.Row,
	ctl *policy.ControlDefinition,
	timeline *asset.Timeline,
) (evaluation.Row, []evaluation.Finding) {
	row.Decision = evaluation.DecisionViolation
	finding := NewFinding(ctl, timeline, FindingContext{
		Why: "No protected prefixes configured. Add prefixes to the control params to activate prefix exposure detection. " +
			"Example:\n  params:\n    protected_prefixes:\n      - \"invoices/\"\n      - \"secrets/\"\n    allowed_public_prefixes:\n      - \"images/\"\n      - \"static/\"",
		Misconfigs: []policy.Misconfiguration{
			{Property: "exposure_source", ActualValue: "not_configured", Operator: "eq", UnsafeValue: "not_configured"},
		},
	})
	return row, []evaluation.Finding{finding}
}

func prefixExposureOverlap(
	row evaluation.Row,
	ctl *policy.ControlDefinition,
	timeline *asset.Timeline,
	conflict *policy.PrefixConflict,
) (evaluation.Row, []evaluation.Finding) {
	row.Decision = evaluation.DecisionViolation
	finding := NewFinding(ctl, timeline, FindingContext{
		Why: fmt.Sprintf("Protected prefix %q overlaps with allowed prefix %q (config_overlap).", conflict.Protected, conflict.Allowed),
		Misconfigs: []policy.Misconfiguration{
			{Property: "exposure_source", ActualValue: "config_overlap", Operator: "eq", UnsafeValue: "config_overlap"},
			{Property: "overlap_with", ActualValue: conflict.Allowed, Operator: "eq", UnsafeValue: conflict.Allowed},
			{Property: "protected_prefix", ActualValue: conflict.Protected, Operator: "eq", UnsafeValue: conflict.Protected},
		},
	})
	return row, []evaluation.Finding{finding}
}

func prefixExposureFindings(
	row evaluation.Row,
	ctl *policy.ControlDefinition,
	timeline *asset.Timeline,
	protected policy.PrefixSet,
) (evaluation.Row, []evaluation.Finding) {
	resource := timeline.Asset()
	facts := exposure.FactsFromStorage(resource.Properties)

	findings := make([]evaluation.Finding, 0)
	for _, prefix := range protected.Paths() {
		result := facts.CheckExposure(prefix)
		if !result.Exposed {
			continue
		}
		evidence := result.String()
		row.Decision = evaluation.DecisionViolation
		finding := NewFinding(ctl, timeline, FindingContext{
			Why: fmt.Sprintf("Protected prefix %q is publicly readable via %s.", prefix, evidence),
			Misconfigs: []policy.Misconfiguration{
				{Property: "exposure_source", ActualValue: evidence, Operator: "eq", UnsafeValue: evidence},
				{Property: "protected_prefix", ActualValue: prefix, Operator: "eq", UnsafeValue: prefix},
			},
		})
		findings = append(findings, finding)
	}
	return row, findings
}
