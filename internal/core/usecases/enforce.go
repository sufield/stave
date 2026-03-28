package usecases

import (
	"context"
	"fmt"

	"github.com/sufield/stave/internal/core/domain"
)

// EnforceTemplateGeneratorPort generates enforcement templates from evaluation data.
type EnforceTemplateGeneratorPort interface {
	GenerateTemplate(ctx context.Context, inputPath, outDir, mode string, dryRun bool) (outputFile string, targets []string, err error)
}

// EnforceDeps groups the port interfaces for the enforce use case.
type EnforceDeps struct {
	Generator EnforceTemplateGeneratorPort
}

// Enforce generates enforcement templates from evaluation output.
func Enforce(
	ctx context.Context,
	req domain.EnforceRequest,
	deps EnforceDeps,
) (domain.EnforceResponse, error) {
	if err := ctx.Err(); err != nil {
		return domain.EnforceResponse{}, fmt.Errorf("enforce: %w", err)
	}

	outputFile, targets, err := deps.Generator.GenerateTemplate(ctx, req.InputPath, req.OutDir, req.Mode, req.DryRun)
	if err != nil {
		return domain.EnforceResponse{}, fmt.Errorf("enforce: %w", err)
	}

	return domain.EnforceResponse{
		OutputFile: outputFile,
		Targets:    targets,
		DryRun:     req.DryRun,
	}, nil
}
