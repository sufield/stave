package fix

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	evaljson "github.com/sufield/stave/internal/adapters/evaluation"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
)

// FindingLoader loads a single finding from an evaluation artifact.
type FindingLoader struct {
	celEvaluator policy.PredicateEval
	readFile     func(string) ([]byte, error) // injected by cmd layer; must enforce size limits
}

// NewFindingLoader constructs a FindingLoader. readFile must be
// non-nil (it MUST enforce size limits at the byte boundary);
// celEvaluator may be nil for callers that don't need predicate
// re-evaluation.
func NewFindingLoader(celEval policy.PredicateEval, readFile func(string) ([]byte, error)) (*FindingLoader, error) {
	if readFile == nil {
		return nil, errors.New("fix.NewFindingLoader: readFile is nil")
	}
	return &FindingLoader{celEvaluator: celEval, readFile: readFile}, nil
}

// LoadFindingWithPlan loads an evaluation, selects the matching finding,
// generates a remediation plan if missing, and returns it.
func (l *FindingLoader) LoadFindingWithPlan(_ context.Context, inputPath, findingRef string) (any, error) {
	path := filepath.Clean(inputPath)
	readFn := l.readFile
	if readFn == nil {
		return nil, errors.New("readFile not configured on FindingLoader")
	}
	data, err := readFn(path)
	if err != nil {
		return nil, fmt.Errorf("reading input file: %w", err)
	}

	findings, err := evaljson.ParseFindings(data)
	if err != nil {
		return nil, fmt.Errorf("parsing evaluation results: %w", err)
	}
	if len(findings) == 0 {
		return nil, fmt.Errorf("no findings found in %s", path)
	}

	selected, err := remediation.SelectFinding(findings, findingRef)
	if err != nil {
		return nil, err
	}

	if selected.RemediationPlan == nil {
		planner := remediation.NewPlanner()
		selected.RemediationPlan = planner.PlanFor(selected)
	}

	return selected, nil
}
