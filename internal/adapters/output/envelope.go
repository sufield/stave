package output

import (
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/report"
	"github.com/sufield/stave/internal/platform/crypto"
)

// BuildAssessmentFromEnriched assembles an assessment from a
// pipeline-produced EnrichedResult.
func BuildAssessmentFromEnriched(enriched *appcontracts.EnrichedResult) *report.Assessment {
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
		SkippedControls:    enriched.Result.SkippedControls,
		ExemptedAssets:     enriched.ExemptedAssets,
		ExceptedFindings:   enriched.Result.ExceptedFindings,
		ChainFindings:      enriched.Result.ChainFindings,
		AttackStageSummary: enriched.Result.AttackStageSummary,
		TopExposures:       enriched.Result.TopExposures,
	})
	out.Extensions = enriched.Result.Metadata.ToExtensions()
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
