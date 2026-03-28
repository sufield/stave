package usecases

import (
	"context"
	"fmt"

	"github.com/sufield/stave/internal/core/domain"
)

// FixFindingLoaderPort loads a finding by its selector from an evaluation file.
type FixFindingLoaderPort interface {
	LoadFindingWithPlan(ctx context.Context, inputPath, findingRef string) (any, error)
}

// FixDeps groups the port interfaces for the fix use case.
type FixDeps struct {
	Loader FixFindingLoaderPort
}

// Fix loads an evaluation artifact and returns remediation guidance for a single finding.
func Fix(
	ctx context.Context,
	req domain.FixRequest,
	deps FixDeps,
) (domain.FixResponse, error) {
	if err := ctx.Err(); err != nil {
		return domain.FixResponse{}, fmt.Errorf("fix: %w", err)
	}

	if req.FindingRef == "" {
		return domain.FixResponse{}, fmt.Errorf("fix: finding selector cannot be empty")
	}

	data, err := deps.Loader.LoadFindingWithPlan(ctx, req.InputPath, req.FindingRef)
	if err != nil {
		return domain.FixResponse{}, fmt.Errorf("fix: %w", err)
	}

	return domain.FixResponse{Data: data}, nil
}
