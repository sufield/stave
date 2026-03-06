package workflow

import (
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/evaluation/remediation"
	"github.com/sufield/stave/internal/safetyenvelope"
)

// BuildEvaluationEnvelope constructs a safety envelope from an evaluation result.
// It handles finding enrichment (remediation mapping) and envelope normalization.
func BuildEvaluationEnvelope(result evaluation.Result) safetyenvelope.Evaluation {
	mapper := remediation.NewMapper()
	enriched := mapper.EnrichFindings(result)
	return safetyenvelope.NewEvaluation(safetyenvelope.EvaluationRequest{
		Run:                result.Run,
		Summary:            result.Summary,
		Findings:           enriched,
		Skipped:            result.Skipped,
		SkippedAssets:      result.SkippedAssets,
		SuppressedFindings: result.SuppressedFindings,
	})
}
