package usecases

import (
	"context"
	"fmt"

	"github.com/sufield/stave/internal/core/domain"
)

// BundleGeneratorPort generates a sanitized diagnostic bundle.
type BundleGeneratorPort interface {
	GenerateBundle(ctx context.Context, outPath string, tailLines int, includeConfig bool) (bundlePath string, warnings []string, err error)
}

// BugReportDeps groups the port interfaces for the bug-report use case.
type BugReportDeps struct {
	Generator BundleGeneratorPort
}

// BugReport generates a sanitized diagnostic bundle for support and issue filing.
func BugReport(
	ctx context.Context,
	req domain.BugReportRequest,
	deps BugReportDeps,
) (domain.BugReportResponse, error) {
	if err := ctx.Err(); err != nil {
		return domain.BugReportResponse{}, fmt.Errorf("bug-report: %w", err)
	}

	if req.TailLines < 0 {
		return domain.BugReportResponse{}, fmt.Errorf("bug-report: invalid tail-lines %d: must be >= 0", req.TailLines)
	}

	bundlePath, warnings, err := deps.Generator.GenerateBundle(ctx, req.OutPath, req.TailLines, req.IncludeConfig)
	if err != nil {
		return domain.BugReportResponse{}, fmt.Errorf("bug-report: %w", err)
	}

	return domain.BugReportResponse{
		BundlePath: bundlePath,
		Warnings:   warnings,
	}, nil
}
