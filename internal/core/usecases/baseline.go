package usecases

import (
	"context"
	"fmt"
	"time"

	"github.com/sufield/stave/internal/core/domain"
)

// EvaluationLoaderPort loads evaluation findings from a file.
type EvaluationLoaderPort interface {
	LoadFindings(ctx context.Context, path string) ([]domain.BaselineFinding, error)
}

// BaselineLoaderPort loads a saved baseline from a file.
type BaselineLoaderPort interface {
	LoadBaseline(ctx context.Context, path string) ([]domain.BaselineFinding, error)
}

// BaselineWriterPort writes a baseline snapshot to a file.
type BaselineWriterPort interface {
	WriteBaseline(ctx context.Context, path string, findings []domain.BaselineFinding, createdAt time.Time, sourcePath string) error
}

// BaselineSaveDeps groups the port interfaces for the baseline save use case.
type BaselineSaveDeps struct {
	Loader EvaluationLoaderPort
	Writer BaselineWriterPort
	Clock  func() time.Time
}

// BaselineCheckDeps groups the port interfaces for the baseline check use case.
type BaselineCheckDeps struct {
	EvalLoader     EvaluationLoaderPort
	BaselineLoader BaselineLoaderPort
	Clock          func() time.Time
}

// BaselineSave captures current evaluation findings as a baseline snapshot.
func BaselineSave(
	ctx context.Context,
	req domain.BaselineSaveRequest,
	deps BaselineSaveDeps,
) (domain.BaselineSaveResponse, error) {
	if err := ctx.Err(); err != nil {
		return domain.BaselineSaveResponse{}, fmt.Errorf("baseline_save: %w", err)
	}

	findings, err := deps.Loader.LoadFindings(ctx, req.EvaluationPath)
	if err != nil {
		return domain.BaselineSaveResponse{}, fmt.Errorf("baseline_save: load evaluation %s: %w", req.EvaluationPath, err)
	}

	if ctxErr := ctx.Err(); ctxErr != nil {
		return domain.BaselineSaveResponse{}, fmt.Errorf("baseline_save: %w", ctxErr)
	}

	now := deps.Clock()
	if req.Now != nil {
		now = *req.Now
	}
	createdAt := now.UTC()

	if err := deps.Writer.WriteBaseline(ctx, req.OutputPath, findings, createdAt, req.EvaluationPath); err != nil {
		return domain.BaselineSaveResponse{}, fmt.Errorf("baseline_save: write %s: %w", req.OutputPath, err)
	}

	return domain.BaselineSaveResponse{
		OutputPath:    req.OutputPath,
		FindingsCount: len(findings),
		CreatedAt:     createdAt,
	}, nil
}

// BaselineCheck compares current evaluation findings against a saved baseline.
func BaselineCheck(
	ctx context.Context,
	req domain.BaselineCheckRequest,
	deps BaselineCheckDeps,
) (domain.BaselineCheckResponse, error) {
	if err := ctx.Err(); err != nil {
		return domain.BaselineCheckResponse{}, fmt.Errorf("baseline_check: %w", err)
	}

	current, err := deps.EvalLoader.LoadFindings(ctx, req.EvaluationPath)
	if err != nil {
		return domain.BaselineCheckResponse{}, fmt.Errorf("baseline_check: load evaluation %s: %w", req.EvaluationPath, err)
	}

	if ctxErr := ctx.Err(); ctxErr != nil {
		return domain.BaselineCheckResponse{}, fmt.Errorf("baseline_check: %w", ctxErr)
	}

	baseline, err := deps.BaselineLoader.LoadBaseline(ctx, req.BaselinePath)
	if err != nil {
		return domain.BaselineCheckResponse{}, fmt.Errorf("baseline_check: load baseline %s: %w", req.BaselinePath, err)
	}

	newFindings, resolved := compareFindings(baseline, current)

	checkedAt := deps.Clock().UTC()
	hasNew := len(newFindings) > 0

	return domain.BaselineCheckResponse{
		BaselineFile: req.BaselinePath,
		Evaluation:   req.EvaluationPath,
		CheckedAt:    checkedAt,
		Summary: domain.BaselineCheckSummary{
			BaselineFindings: len(baseline),
			CurrentFindings:  len(current),
			NewFindings:      len(newFindings),
			ResolvedFindings: len(resolved),
		},
		NewFindings:      newFindings,
		ResolvedFindings: resolved,
		HasNew:           hasNew,
	}, nil
}

// compareFindings identifies new and resolved findings between a baseline
// and current set. Returns non-nil slices.
func compareFindings(baseline, current []domain.BaselineFinding) (newFindings, resolved []domain.BaselineFinding) {
	type key struct {
		ControlID string
		AssetID   string
	}

	baseMap := make(map[key]domain.BaselineFinding, len(baseline))
	for _, f := range baseline {
		baseMap[key{f.ControlID, f.AssetID}] = f
	}

	curMap := make(map[key]domain.BaselineFinding, len(current))
	for _, f := range current {
		curMap[key{f.ControlID, f.AssetID}] = f
	}

	newFindings = make([]domain.BaselineFinding, 0)
	for k, f := range curMap {
		if _, exists := baseMap[k]; !exists {
			newFindings = append(newFindings, f)
		}
	}

	resolved = make([]domain.BaselineFinding, 0)
	for k, f := range baseMap {
		if _, exists := curMap[k]; !exists {
			resolved = append(resolved, f)
		}
	}

	return newFindings, resolved
}
