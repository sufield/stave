package eval

import (
	"context"
	"fmt"

	"github.com/sufield/stave/internal/core/evaluation"
)

// ExecuteAndWrite runs the full evaluate use case: load artifacts, evaluate, marshal, and write output.
// This is a test helper that combines Execute with the output pipeline.
func (e *EvaluateRun) ExecuteAndWrite(ctx context.Context, cfg EvaluateConfig) (evaluation.SafetyStatus, error) {
	result, status, err := e.Execute(ctx, cfg)
	if err != nil {
		return "", err
	}

	enriched, enrichErr := e.EnrichFn(result)
	if enrichErr != nil {
		return "", fmt.Errorf("enrich: %w", enrichErr)
	}
	data, marshalErr := e.Marshaler.MarshalFindings(enriched)
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
