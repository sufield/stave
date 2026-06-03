package fix

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
)

// FindingLoader loads a single finding from an evaluation artifact.
// Both the file reader and the JSON parser are injected so this
// type stays vendor-neutral; cmd composition wires
// observations/IO + adapters/evaluation.ParseFindings.
type FindingLoader struct {
	celEvaluator  policy.PredicateEval
	readFile      func(string) ([]byte, error) // must enforce size limits
	parseFindings func([]byte) ([]remediation.Finding, error)
}

// NewFindingLoader constructs a FindingLoader. readFile and
// parseFindings must be non-nil. celEvaluator may be nil for
// callers that don't need predicate re-evaluation.
func NewFindingLoader(
	celEval policy.PredicateEval,
	readFile func(string) ([]byte, error),
	parseFindings func([]byte) ([]remediation.Finding, error),
) (*FindingLoader, error) {
	switch {
	case readFile == nil:
		return nil, errors.New("fix.NewFindingLoader: readFile is nil")
	case parseFindings == nil:
		return nil, errors.New("fix.NewFindingLoader: parseFindings is nil")
	}
	return &FindingLoader{
		celEvaluator:  celEval,
		readFile:      readFile,
		parseFindings: parseFindings,
	}, nil
}

// LoadFindingWithPlan loads an evaluation, selects the matching finding,
// generates a remediation plan if missing, and returns it.
func (l *FindingLoader) LoadFindingWithPlan(_ context.Context, inputPath, findingRef string) (any, error) {
	path := filepath.Clean(inputPath)
	data, err := l.readFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading input file: %w", err)
	}

	findings, err := l.parseFindings(data)
	if err != nil {
		return nil, fmt.Errorf("parsing evaluation results: %w", err)
	}
	if len(findings) == 0 {
		return nil, fmt.Errorf("no findings found in %s", path)
	}

	selected, err := remediation.SelectFinding(findings, findingRef)
	if err != nil {
		return nil, fmt.Errorf("select finding: %w", err)
	}

	EnsurePlan(&selected)
	return selected, nil
}
