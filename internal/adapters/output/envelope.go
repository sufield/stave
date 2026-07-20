package output

import (
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/report"
	"github.com/sufield/stave/internal/platform/crypto"
)

// BuildAssessmentFromEnriched assembles an assessment from a
// pipeline-produced EnrichedResult.
//
// Returns nil when enriched is nil — callers downstream of optional
// pipeline stages can pass a nil pointer when the previous stage
// produced no result, and an NPE here would mask the upstream gap.
func BuildAssessmentFromEnriched(enriched *appcontracts.EnrichedResult) *report.Assessment {
	if enriched == nil {
		return nil
	}
	findings := toRemediationFindings(enriched.Findings)
	if findings == nil {
		findings = []remediation.Finding{}
	}

	out := report.NewAssessment(report.AssessmentRequest{
		Run:                enriched.Run,
		Summary:            enriched.Result.Summary,
		SecurityState:      enriched.Result.SecurityState,
		RiskSignals:        enriched.Result.RiskSignals,
		Findings:           findings,
		MarkerFindings:     toRemediationFindings(enriched.MarkerFindings),
		SkippedControls:    enriched.Result.SkippedControls,
		ExemptedAssets:     enriched.ExemptedAssets,
		ChainFindings:      enriched.Result.ChainFindings,
		NearMissChains:     enriched.Result.NearMissChains,
		ChainSuggestions:   enriched.Result.ChainSuggestions,
		AttackStageSummary: enriched.Result.AttackStageSummary,
		TopExposures:       enriched.Result.TopExposures,
		Issues:             enriched.Result.Issues,
	})
	out.Extensions = enriched.Result.Metadata.ToExtensions()
	out.CoveragePosture = enriched.CoveragePosture
	h := crypto.NewHasher()
	remediation.PrepareForGrouping(h, h, findings)
	out.RemediationGroups = remediation.BuildGroups(findings)
	return out
}

// toRemediationFindings converts port-boundary enriched findings to
// remediation.Finding for use by core functions (BuildGroups, etc.).
func toRemediationFindings(fs []appcontracts.EnrichedFinding) []remediation.Finding {
	if fs == nil {
		return nil
	}
	out := make([]remediation.Finding, len(fs))
	for i := range fs {
		f := &fs[i]
		out[i] = remediation.Finding{
			Finding:         f.Finding,
			RemediationSpec: f.RemediationSpec,
			RemediationPlan: f.RemediationPlan,
		}
	}
	return out
}
