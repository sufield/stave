package gate

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/report"
)

// EvaluationLoaderFunc loads a safety envelope evaluation from a path.
type EvaluationLoaderFunc func(ctx context.Context, path string) (*report.Assessment, error)

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
	loadEvaluation EvaluationLoaderFunc
}

// NewFindingsCounter constructs a FindingsCounter. Returns an error
// when loader is nil so a misconfigured wiring is caught at startup
// rather than panicking on first use.
func NewFindingsCounter(loader EvaluationLoaderFunc) (*FindingsCounter, error) {
	if loader == nil {
		return nil, errors.New("gate.NewFindingsCounter: loader is nil")
	}
	return &FindingsCounter{loadEvaluation: loader}, nil
}

// CountFindings loads an evaluation and returns the number of findings.
func (f *FindingsCounter) CountFindings(ctx context.Context, path string) (int, error) {
	eval, err := f.loadEvaluation(ctx, path)
	if err != nil {
		return 0, err
	}
	return len(eval.Findings), nil
}

// BaselineComparer compares an evaluation against a baseline artifact.
type BaselineComparer struct {
	sanitizer      kernel.Sanitizer
	loadEvaluation EvaluationLoaderFunc
	loadBaseline   BaselineLoaderFunc
	compare        BaselineCompareFunc
}

// NewBaselineComparer constructs a BaselineComparer. The three
// loader/comparator deps are required; san may be nil — the compare
// function decides what nil means (typically: no sanitization).
func NewBaselineComparer(
	san kernel.Sanitizer,
	loadEval EvaluationLoaderFunc,
	loadBaseline BaselineLoaderFunc,
	compare BaselineCompareFunc,
) (*BaselineComparer, error) {
	switch {
	case loadEval == nil:
		return nil, errors.New("gate.NewBaselineComparer: loadEvaluation is nil")
	case loadBaseline == nil:
		return nil, errors.New("gate.NewBaselineComparer: loadBaseline is nil")
	case compare == nil:
		return nil, errors.New("gate.NewBaselineComparer: compare is nil")
	}
	return &BaselineComparer{
		sanitizer:      san,
		loadEvaluation: loadEval,
		loadBaseline:   loadBaseline,
		compare:        compare,
	}, nil
}

// CompareAgainstBaseline loads evaluation and baseline, returns current and new counts.
func (b *BaselineComparer) CompareAgainstBaseline(ctx context.Context, evalPath, baselinePath string) (currentCount, newCount int, err error) {
	eval, err := b.loadEvaluation(ctx, evalPath)
	if err != nil {
		return 0, 0, fmt.Errorf("loading evaluation: %w", err)
	}
	base, err := b.loadBaseline(ctx, baselinePath, kernel.KindBaseline)
	if err != nil {
		return 0, 0, fmt.Errorf("loading baseline: %w", err)
	}
	bc := b.compare(b.sanitizer, base.Findings, eval.Findings)
	return len(bc.Current), len(bc.Comparison.New), nil
}

// OverdueCounter counts overdue upcoming risk items.
type OverdueCounter struct {
	loadAssets      AssetLoaderFunc
	newCELEvaluator CELEvaluatorFactory
}

// NewOverdueCounter constructs an OverdueCounter; both dependencies
// are required.
func NewOverdueCounter(
	loadAssets AssetLoaderFunc,
	newCEL CELEvaluatorFactory,
) (*OverdueCounter, error) {
	switch {
	case loadAssets == nil:
		return nil, errors.New("gate.NewOverdueCounter: loadAssets is nil")
	case newCEL == nil:
		return nil, errors.New("gate.NewOverdueCounter: newCELEvaluator is nil")
	}
	return &OverdueCounter{loadAssets: loadAssets, newCELEvaluator: newCEL}, nil
}

// CountOverdue loads observations + controls + CEL, then delegates
// the overdue-counting business rule to internal/app/gate.
// The adapter owns I/O wiring only.
func (o *OverdueCounter) CountOverdue(ctx context.Context, controlsDir, observationsDir string, maxUnsafe time.Duration, now time.Time) (int, error) {
	loaded, err := o.loadAssets(ctx, observationsDir, controlsDir)
	if err != nil {
		return 0, err
	}
	celEval, err := o.newCELEvaluator()
	if err != nil {
		return 0, err
	}
	return CountOverdue(OverdueRequest{
		Controls:                loaded.Controls,
		Snapshots:               loaded.Snapshots,
		GlobalMaxUnsafeDuration: maxUnsafe,
		Now:                     now,
		PredicateEval:           celEval,
	}), nil
}
