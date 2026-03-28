package usecases

import (
	"context"
	"fmt"

	"github.com/sufield/stave/internal/core/domain"
)

// GraphCoverageComputerPort computes the control→asset coverage graph.
type GraphCoverageComputerPort interface {
	ComputeCoverage(ctx context.Context, controlsDir, observationsDir string) (any, error)
}

// GraphCoverageDeps groups the port interfaces for the graph coverage use case.
type GraphCoverageDeps struct {
	Computer GraphCoverageComputerPort
}

// GraphCoverage computes the coverage graph showing control→asset relationships.
func GraphCoverage(
	ctx context.Context,
	req domain.GraphCoverageRequest,
	deps GraphCoverageDeps,
) (domain.GraphCoverageResponse, error) {
	if err := ctx.Err(); err != nil {
		return domain.GraphCoverageResponse{}, fmt.Errorf("graph_coverage: %w", err)
	}

	data, err := deps.Computer.ComputeCoverage(ctx, req.ControlsDir, req.ObservationsDir)
	if err != nil {
		return domain.GraphCoverageResponse{}, fmt.Errorf("graph_coverage: %w", err)
	}

	return domain.GraphCoverageResponse{GraphData: data}, nil
}
