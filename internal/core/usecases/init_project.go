package usecases

import (
	"context"
	"fmt"

	"github.com/sufield/stave/internal/core/domain"
)

// ProjectScaffolderPort creates or previews a Stave project scaffold.
type ProjectScaffolderPort interface {
	ScaffoldProject(ctx context.Context, req domain.InitProjectRequest) (domain.InitProjectResponse, error)
}

// InitProjectDeps groups the port interfaces for the init-project use case.
type InitProjectDeps struct {
	Scaffolder ProjectScaffolderPort
}

// InitProject initializes a starter Stave project structure.
func InitProject(
	ctx context.Context,
	req domain.InitProjectRequest,
	deps InitProjectDeps,
) (domain.InitProjectResponse, error) {
	if err := ctx.Err(); err != nil {
		return domain.InitProjectResponse{}, fmt.Errorf("init-project: %w", err)
	}

	if req.Dir == "" {
		return domain.InitProjectResponse{}, fmt.Errorf("init-project: directory is required")
	}

	if req.Profile != "" && req.Profile != "aws-s3" {
		return domain.InitProjectResponse{}, fmt.Errorf("init-project: unsupported profile %q (supported: aws-s3)", req.Profile)
	}

	if req.CaptureCadence != "" && req.CaptureCadence != "daily" && req.CaptureCadence != "hourly" {
		return domain.InitProjectResponse{}, fmt.Errorf("init-project: unsupported capture-cadence %q (supported: daily, hourly)", req.CaptureCadence)
	}

	resp, err := deps.Scaffolder.ScaffoldProject(ctx, req)
	if err != nil {
		return domain.InitProjectResponse{}, fmt.Errorf("init-project: %w", err)
	}

	return resp, nil
}
