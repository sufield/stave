package gate

import (
	"context"
	"fmt"
	"time"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/enforce/artifact"
	ctlyaml "github.com/sufield/stave/internal/adapters/controls/yaml"
	"github.com/sufield/stave/internal/core/evaluation/risk"
	"github.com/sufield/stave/internal/core/kernel"
)

// FindingsCounter satisfies usecases.GateFindingsCounterPort.
type FindingsCounter struct{}

// CountFindings loads an evaluation and returns the number of findings.
func (f *FindingsCounter) CountFindings(ctx context.Context, path string) (int, error) {
	eval, err := artifact.NewLoader().Evaluation(ctx, path)
	if err != nil {
		return 0, err
	}
	return len(eval.Findings), nil
}

// BaselineComparer satisfies usecases.GateBaselineComparerPort.
type BaselineComparer struct {
	Sanitizer kernel.Sanitizer
}

// CompareAgainstBaseline loads evaluation and baseline, returns current and new counts.
func (b *BaselineComparer) CompareAgainstBaseline(ctx context.Context, evalPath, baselinePath string) (int, int, error) {
	loader := artifact.NewLoader()
	eval, err := loader.Evaluation(ctx, evalPath)
	if err != nil {
		return 0, 0, fmt.Errorf("loading evaluation: %w", err)
	}
	base, err := loader.Baseline(ctx, baselinePath, kernel.KindBaseline)
	if err != nil {
		return 0, 0, fmt.Errorf("loading baseline: %w", err)
	}
	bc := artifact.CompareAgainstBaseline(b.Sanitizer, base.Findings, eval.Findings)
	return len(bc.Current), len(bc.Comparison.New), nil
}

// OverdueCounter satisfies usecases.GateOverdueCounterPort.
type OverdueCounter struct {
	LoadAssets      compose.AssetLoaderFunc
	NewCELEvaluator compose.CELEvaluatorFactory
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
		PredicateParser:         ctlyaml.ParsePredicate,
		PredicateEval:           celEval,
	})
	return items.CountOverdue(), nil
}
