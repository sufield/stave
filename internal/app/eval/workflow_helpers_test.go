package eval

import (
	"context"
	"fmt"

	"github.com/sufield/stave/internal/core/evaluation"
)

// ExecuteAndWrite runs the full evaluate use case: load artifacts, evaluate, marshal, and write output.
// This is a test helper that combines PerformAssessment with the output pipeline.
func (e *AuditWorkflow) ExecuteAndWrite(ctx context.Context, cfg AssessmentConfig) (evaluation.SecurityState, error) {
	result, status, err := e.PerformAssessment(ctx, cfg)
	if err != nil {
		return "", err
	}

	enriched, enrichErr := e.ContextEnricher(&result)
	if enrichErr != nil {
		return "", fmt.Errorf("enrich: %w", enrichErr)
	}
	data, marshalErr := e.ReportPublisher.MarshalFindings(&enriched)
	if marshalErr != nil {
		return "", fmt.Errorf("marshal: %w", marshalErr)
	}

	if cfg.Output != nil {
		if _, writeErr := cfg.Output.Write(data); writeErr != nil {
			return "", fmt.Errorf("write output: %w", writeErr)
		}
	}

	return status, nil
}
