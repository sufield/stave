package output

import (
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/domain/evaluation/remediation"
	"github.com/sufield/stave/internal/platform/crypto"
	"github.com/sufield/stave/internal/safetyenvelope"
)

// BuildSafetyEnvelopeFromEnriched assembles a safety envelope from a
// pipeline-produced EnrichedResult.
func BuildSafetyEnvelopeFromEnriched(enriched appcontracts.EnrichedResult) safetyenvelope.Evaluation {
	findings := enriched.Findings
	if findings == nil {
		findings = []remediation.Finding{}
	}

	out := safetyenvelope.NewEvaluation(safetyenvelope.EvaluationRequest{
		Run:                enriched.Run,
		Summary:            enriched.Result.Summary,
		Findings:           findings,
		Skipped:            enriched.Result.Skipped,
		SkippedAssets:      enriched.SkippedAssets,
		SuppressedFindings: enriched.Result.SuppressedFindings,
	})
	out.Extensions = enriched.Result.Metadata.ToExtensions()
	h := crypto.NewHasher()
	out.RemediationGroups = remediation.BuildGroups(h, h, findings)
	return out
}
