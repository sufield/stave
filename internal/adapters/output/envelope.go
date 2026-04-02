package output

import (
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/platform/crypto"
	"github.com/sufield/stave/internal/safetyenvelope"
)

// BuildSafetyEnvelopeFromEnriched assembles a safety envelope from a
// pipeline-produced EnrichedResult.
func BuildSafetyEnvelopeFromEnriched(enriched appcontracts.EnrichedResult) *safetyenvelope.Evaluation {
	findings := toRemediationFindings(enriched.Findings)
	if findings == nil {
		findings = []remediation.Finding{}
	}

	out := safetyenvelope.NewEvaluation(safetyenvelope.EvaluationRequest{
		Run:              enriched.Run,
		Summary:          enriched.Result.Summary,
		SafetyStatus:     enriched.Result.SafetyStatus,
		AtRisk:           enriched.Result.AtRisk,
		Findings:         findings,
		Skipped:          enriched.Result.Skipped,
		ExemptedAssets:   enriched.ExemptedAssets,
		ExceptedFindings: enriched.Result.ExceptedFindings,
	})
	out.Extensions = enriched.Result.Metadata.ToExtensions()
	h := crypto.NewHasher()
	out.RemediationGroups = remediation.BuildGroups(h, h, findings)
	return out
}

// toRemediationFindings converts port-boundary enriched findings to
// remediation.Finding for use by core functions (BuildGroups, etc.).
func toRemediationFindings(fs []appcontracts.EnrichedFinding) []remediation.Finding {
	if fs == nil {
		return nil
	}
	out := make([]remediation.Finding, len(fs))
	for i, f := range fs {
		out[i] = remediation.Finding{
			Finding:         f.Finding,
			RemediationSpec: f.RemediationSpec,
			RemediationPlan: f.RemediationPlan,
		}
	}
	return out
}
