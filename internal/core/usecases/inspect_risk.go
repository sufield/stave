package usecases

import (
	"context"
	"fmt"

	"github.com/sufield/stave/internal/core/domain"
)

// RiskScorerPort scores risk from a policy statement context.
type RiskScorerPort interface {
	ScoreRisk(ctx context.Context, inputJSON []byte) (domain.InspectRiskResponse, error)
}

// RiskInputReaderPort reads risk input from a file path.
type RiskInputReaderPort interface {
	ReadInput(ctx context.Context, filePath string) ([]byte, error)
}

// InspectRiskDeps groups the port interfaces for the inspect-risk use case.
type InspectRiskDeps struct {
	Scorer RiskScorerPort
	Reader RiskInputReaderPort
}

// InspectRisk scores risk from a policy statement context.
func InspectRisk(
	ctx context.Context,
	req domain.InspectRiskRequest,
	deps InspectRiskDeps,
) (domain.InspectRiskResponse, error) {
	if err := ctx.Err(); err != nil {
		return domain.InspectRiskResponse{}, fmt.Errorf("inspect-risk: %w", err)
	}

	var input []byte
	if req.FilePath != "" {
		data, err := deps.Reader.ReadInput(ctx, req.FilePath)
		if err != nil {
			return domain.InspectRiskResponse{}, fmt.Errorf("inspect-risk: %w", err)
		}
		input = data
	} else if len(req.InputData) > 0 {
		input = req.InputData
	} else {
		return domain.InspectRiskResponse{}, fmt.Errorf("inspect-risk: no input provided (use --file or stdin)")
	}

	resp, err := deps.Scorer.ScoreRisk(ctx, input)
	if err != nil {
		return domain.InspectRiskResponse{}, fmt.Errorf("inspect-risk: %w", err)
	}

	return resp, nil
}
