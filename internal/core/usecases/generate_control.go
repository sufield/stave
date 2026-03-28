package usecases

import (
	"context"
	"fmt"

	"github.com/sufield/stave/internal/core/domain"
)

// ControlGeneratorPort generates a control template file.
type ControlGeneratorPort interface {
	GenerateControl(ctx context.Context, name, outPath string) (outputPath string, err error)
}

// GenerateControlDeps groups the port interfaces for the generate control use case.
type GenerateControlDeps struct {
	Generator ControlGeneratorPort
}

// GenerateControl scaffolds a control template from a name.
func GenerateControl(
	ctx context.Context,
	req domain.GenerateControlRequest,
	deps GenerateControlDeps,
) (domain.GenerateControlResponse, error) {
	if err := ctx.Err(); err != nil {
		return domain.GenerateControlResponse{}, fmt.Errorf("generate_control: %w", err)
	}

	if req.Name == "" {
		return domain.GenerateControlResponse{}, fmt.Errorf("generate_control: name is required")
	}

	outputPath, err := deps.Generator.GenerateControl(ctx, req.Name, req.OutPath)
	if err != nil {
		return domain.GenerateControlResponse{}, fmt.Errorf("generate_control: %w", err)
	}

	return domain.GenerateControlResponse{OutputPath: outputPath}, nil
}
