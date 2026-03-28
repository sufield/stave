package reporting

import (
	"context"
	"fmt"
	"time"
)

// EvaluationLoaderPort loads evaluation findings from a file.
type EvaluationLoaderPort interface {
	LoadFindings(ctx context.Context, path string) ([]BaselineFinding, error)
}

// BaselineLoaderPort loads a saved baseline from a file.
type BaselineLoaderPort interface {
	LoadBaseline(ctx context.Context, path string) ([]BaselineFinding, error)
}

// BaselineWriterPort writes a baseline snapshot to a file.
type BaselineWriterPort interface {
	WriteBaseline(ctx context.Context, path string, findings []BaselineFinding, createdAt time.Time, sourcePath string) error
}

type BaselineSaveDeps struct {
	Loader EvaluationLoaderPort
	Writer BaselineWriterPort
	Clock  func() time.Time
}

type BaselineCheckDeps struct {
	EvalLoader     EvaluationLoaderPort
	BaselineLoader BaselineLoaderPort
	Clock          func() time.Time
}

// BaselineSave captures current evaluation findings as a baseline snapshot.
func BaselineSave(ctx context.Context, req BaselineSaveRequest, deps BaselineSaveDeps) (BaselineSaveResponse, error) {
	if err := ctx.Err(); err != nil {
		return BaselineSaveResponse{}, fmt.Errorf("baseline_save: %w", err)
	}

	findings, err := deps.Loader.LoadFindings(ctx, req.EvaluationPath)
	if err != nil {
		return BaselineSaveResponse{}, fmt.Errorf("baseline_save: load evaluation %s: %w", req.EvaluationPath, err)
	}

	if ctxErr := ctx.Err(); ctxErr != nil {
		return BaselineSaveResponse{}, fmt.Errorf("baseline_save: %w", ctxErr)
	}

	now := deps.Clock()
	if req.Now != nil {
		now = *req.Now
	}
	createdAt := now.UTC()

	if err := deps.Writer.WriteBaseline(ctx, req.OutputPath, findings, createdAt, req.EvaluationPath); err != nil {
		return BaselineSaveResponse{}, fmt.Errorf("baseline_save: write %s: %w", req.OutputPath, err)
	}

	return BaselineSaveResponse{
		OutputPath:    req.OutputPath,
		FindingsCount: len(findings),
		CreatedAt:     createdAt,
	}, nil
}

// BaselineCheck compares current evaluation findings against a saved baseline.
func BaselineCheck(ctx context.Context, req BaselineCheckRequest, deps BaselineCheckDeps) (BaselineCheckResponse, error) {
	if err := ctx.Err(); err != nil {
		return BaselineCheckResponse{}, fmt.Errorf("baseline_check: %w", err)
	}

	current, err := deps.EvalLoader.LoadFindings(ctx, req.EvaluationPath)
	if err != nil {
		return BaselineCheckResponse{}, fmt.Errorf("baseline_check: load evaluation %s: %w", req.EvaluationPath, err)
	}

	if ctxErr := ctx.Err(); ctxErr != nil {
		return BaselineCheckResponse{}, fmt.Errorf("baseline_check: %w", ctxErr)
	}

	baseline, err := deps.BaselineLoader.LoadBaseline(ctx, req.BaselinePath)
	if err != nil {
		return BaselineCheckResponse{}, fmt.Errorf("baseline_check: load baseline %s: %w", req.BaselinePath, err)
	}

	newFindings, resolved := compareFindings(baseline, current)

	return BaselineCheckResponse{
		BaselineFile: req.BaselinePath,
		Evaluation:   req.EvaluationPath,
		CheckedAt:    deps.Clock().UTC(),
		Summary: BaselineCheckSummary{
			BaselineFindings: len(baseline),
			CurrentFindings:  len(current),
			NewFindings:      len(newFindings),
			ResolvedFindings: len(resolved),
		},
		NewFindings:      newFindings,
		ResolvedFindings: resolved,
		HasNew:           len(newFindings) > 0,
	}, nil
}

// CIDiffDeps groups the port interfaces for the CI diff use case.
type CIDiffDeps struct {
	CurrentLoader  EvaluationLoaderPort
	BaselineLoader EvaluationLoaderPort
	Clock          func() time.Time
}

// CIDiff compares two evaluation artifacts and identifies new and resolved findings.
func CIDiff(ctx context.Context, req CIDiffRequest, deps CIDiffDeps) (CIDiffResponse, error) {
	if err := ctx.Err(); err != nil {
		return CIDiffResponse{}, fmt.Errorf("ci_diff: %w", err)
	}

	current, err := deps.CurrentLoader.LoadFindings(ctx, req.CurrentPath)
	if err != nil {
		return CIDiffResponse{}, fmt.Errorf("ci_diff: load current %s: %w", req.CurrentPath, err)
	}

	if ctxErr := ctx.Err(); ctxErr != nil {
		return CIDiffResponse{}, fmt.Errorf("ci_diff: %w", ctxErr)
	}

	baseline, err := deps.BaselineLoader.LoadFindings(ctx, req.BaselinePath)
	if err != nil {
		return CIDiffResponse{}, fmt.Errorf("ci_diff: load baseline %s: %w", req.BaselinePath, err)
	}

	newFindings, resolved := compareFindings(baseline, current)

	return CIDiffResponse{
		CurrentEvaluation:  req.CurrentPath,
		BaselineEvaluation: req.BaselinePath,
		ComparedAt:         deps.Clock().UTC(),
		Summary: CIDiffSummary{
			BaselineFindings: len(baseline),
			CurrentFindings:  len(current),
			NewFindings:      len(newFindings),
			ResolvedFindings: len(resolved),
		},
		NewFindings:      newFindings,
		ResolvedFindings: resolved,
		HasNew:           len(newFindings) > 0,
	}, nil
}

// compareFindings identifies new and resolved findings between a baseline
// and current set.
func compareFindings(baseline, current []BaselineFinding) (newFindings, resolved []BaselineFinding) {
	type key struct {
		ControlID string
		AssetID   string
	}

	baseMap := make(map[key]BaselineFinding, len(baseline))
	for _, f := range baseline {
		baseMap[key{f.ControlID, f.AssetID}] = f
	}

	curMap := make(map[key]BaselineFinding, len(current))
	for _, f := range current {
		curMap[key{f.ControlID, f.AssetID}] = f
	}

	newFindings = make([]BaselineFinding, 0)
	for k, f := range curMap {
		if _, exists := baseMap[k]; !exists {
			newFindings = append(newFindings, f)
		}
	}

	resolved = make([]BaselineFinding, 0)
	for k, f := range baseMap {
		if _, exists := curMap[k]; !exists {
			resolved = append(resolved, f)
		}
	}

	return newFindings, resolved
}
