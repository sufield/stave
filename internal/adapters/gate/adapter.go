package gate

import (
	"context"
	"fmt"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/evaluation/risk"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/safetyenvelope"
)

// EvaluationLoaderFunc loads a safety envelope evaluation from a path.
type EvaluationLoaderFunc func(ctx context.Context, path string) (*safetyenvelope.Evaluation, error)

// BaselineLoaderFunc loads a baseline from a path.
type BaselineLoaderFunc func(ctx context.Context, path string, expectedKind kernel.OutputKind) (*evaluation.Baseline, error)

// BaselineCompareFunc compares baseline entries against current findings.
type BaselineCompareFunc func(san kernel.Sanitizer, baseEntries []evaluation.BaselineEntry, currentFindings []remediation.Finding) BaselineComparisonResult

// BaselineComparisonResult mirrors the result type from cmd/enforce/artifact
// to avoid the import.
type BaselineComparisonResult struct {
	Current    []evaluation.BaselineEntry
	Comparison evaluation.BaselineComparisonResult
}

// AssetLoaderFunc loads observations and controls concurrently.
type AssetLoaderFunc func(ctx context.Context, obsDir, ctlDir string) (Assets, error)

// CELEvaluatorFactory creates a CEL predicate evaluator.
type CELEvaluatorFactory func() (policy.PredicateEval, error)

// Assets represents the data loaded for an evaluation.
type Assets struct {
	Snapshots []asset.Snapshot
	Controls  []policy.ControlDefinition
}

// FindingsCounter counts findings from a persisted evaluation artifact.
type FindingsCounter struct {
	LoadEvaluation EvaluationLoaderFunc
}

// CountFindings loads an evaluation and returns the number of findings.
func (f *FindingsCounter) CountFindings(ctx context.Context, path string) (int, error) {
	eval, err := f.LoadEvaluation(ctx, path)
	if err != nil {
		return 0, err
	}
	return len(eval.Findings), nil
}

// BaselineComparer compares an evaluation against a baseline artifact.
type BaselineComparer struct {
	Sanitizer      kernel.Sanitizer
	LoadEvaluation EvaluationLoaderFunc
	LoadBaseline   BaselineLoaderFunc
	Compare        BaselineCompareFunc
}

// CompareAgainstBaseline loads evaluation and baseline, returns current and new counts.
func (b *BaselineComparer) CompareAgainstBaseline(ctx context.Context, evalPath, baselinePath string) (currentCount, newCount int, err error) {
	eval, err := b.LoadEvaluation(ctx, evalPath)
	if err != nil {
		return 0, 0, fmt.Errorf("loading evaluation: %w", err)
	}
	base, err := b.LoadBaseline(ctx, baselinePath, kernel.KindBaseline)
	if err != nil {
		return 0, 0, fmt.Errorf("loading baseline: %w", err)
	}
	bc := b.Compare(b.Sanitizer, base.Findings, eval.Findings)
	return len(bc.Current), len(bc.Comparison.New), nil
}

// OverdueCounter counts overdue upcoming risk items.
type OverdueCounter struct {
	LoadAssets      AssetLoaderFunc
	NewCELEvaluator CELEvaluatorFactory
}

// CountOverdue loads assets and computes the number of overdue upcoming actions.
func (o *OverdueCounter) CountOverdue(ctx context.Context, controlsDir, observationsDir string, maxUnsafe time.Duration, now time.Time) (int, error) {
	loaded, err := o.LoadAssets(ctx, observationsDir, controlsDir)
	if err != nil {
		return 0, err
	}
	celEval, err := o.NewCELEvaluator()
	if err != nil {
		return 0, err
	}
	items := risk.ComputeItems(risk.ThresholdRequest{
		Controls:                loaded.Controls,
		Snapshots:               loaded.Snapshots,
		GlobalMaxUnsafeDuration: maxUnsafe,
		Now:                     now,
		PredicateEval:           celEval,
	})
	return items.CountOverdue(), nil
}
