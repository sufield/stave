package eval

import (
	"context"
	"fmt"

	"github.com/sufield/stave/pkg/alpha/domain/evaluation"
)

// Execute runs the full evaluate use case: load artifacts, evaluate, marshal, and write output.
func (e *EvaluateRun) Execute(ctx context.Context, cfg EvaluateConfig) (evaluation.SafetyStatus, error) {
	result, status, err := e.ExecuteAndReturn(ctx, cfg)
	if err != nil {
		return "", err
	}

	enriched, enrichErr := e.EnrichFn(result)
	if enrichErr != nil {
		return "", fmt.Errorf("failed to enrich findings: %w", enrichErr)
	}
	data, marshalErr := e.Marshaler.MarshalFindings(enriched)
	if marshalErr != nil {
		return "", fmt.Errorf("failed to write findings: %w", marshalErr)
	}

	if cfg.Output != nil {
		if _, writeErr := cfg.Output.Write(data); writeErr != nil {
			return "", fmt.Errorf("failed to write output: %w", writeErr)
		}
	}

	return status, nil
}
