package fix

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	evaljson "github.com/sufield/stave/internal/adapters/evaluation"
	appfix "github.com/sufield/stave/internal/app/fix"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/platform/crypto"
)

// FindingLoader satisfies usecases.FixFindingLoaderPort.
type FindingLoader struct {
	CELEvaluator policy.PredicateEval
}

// LoadFindingWithPlan loads an evaluation, selects the matching finding,
// generates a remediation plan if missing, and returns it.
func (l *FindingLoader) LoadFindingWithPlan(_ context.Context, inputPath, findingRef string) (any, error) {
	path := filepath.Clean(inputPath)
	data, err := os.ReadFile(path)
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

	selected, err := appfix.SelectFinding(findings, findingRef)
	if err != nil {
		return nil, err
	}

	if selected.RemediationPlan == nil {
		planner := remediation.NewPlanner(crypto.NewHasher())
		selected.RemediationPlan = planner.PlanFor(selected)
	}

	return selected, nil
}
