package shared

import (
	"encoding/json"
	"fmt"

	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/internal/safetyenvelope"
)

// Loader handles the retrieval and validation of Stave artifacts from the filesystem.
type Loader struct{}

// NewLoader initializes a standard artifact loader.
func NewLoader() *Loader {
	return &Loader{}
}

// Evaluation loads and validates a JSON safety envelope containing evaluation results.
func (l *Loader) Evaluation(path string) (*safetyenvelope.Evaluation, error) {
	path = fsutil.CleanUserPath(path)

	data, err := fsutil.ReadFileLimited(path)
	if err != nil {
		return nil, fmt.Errorf("reading evaluation file %q: %w", path, err)
	}

	var eval safetyenvelope.Evaluation
	if err := json.Unmarshal(data, &eval); err != nil {
		return nil, fmt.Errorf("parsing evaluation JSON from %q: %w", path, err)
	}

	if eval.Kind != safetyenvelope.KindEvaluation {
		return nil, fmt.Errorf("invalid artifact kind in %q: got %q, expected %q",
			path, eval.Kind, safetyenvelope.KindEvaluation)
	}

	return &eval, nil
}

// Baseline loads a baseline finding file and ensures findings are sorted deterministically.
func (l *Loader) Baseline(path string, expectedKind kernel.OutputKind) (*evaluation.Baseline, error) {
	path = fsutil.CleanUserPath(path)

	data, err := fsutil.ReadFileLimited(path)
	if err != nil {
		return nil, fmt.Errorf("reading baseline file %q: %w", path, err)
	}

	var base evaluation.Baseline
	if err := json.Unmarshal(data, &base); err != nil {
		return nil, fmt.Errorf("parsing baseline JSON from %q: %w", path, err)
	}

	if base.Kind != expectedKind {
		return nil, fmt.Errorf("invalid baseline kind in %q: got %q, expected %q",
			path, base.Kind, expectedKind)
	}

	if base.Findings == nil {
		base.Findings = []evaluation.BaselineEntry{}
	}

	evaluation.SortBaselineEntries(base.Findings)

	return &base, nil
}

// LoadEvaluationEnvelope is a convenience wrapper for one-off loads.
func LoadEvaluationEnvelope(path string) (*safetyenvelope.Evaluation, error) {
	return NewLoader().Evaluation(path)
}

// LoadBaselineFile is a convenience wrapper for one-off loads.
func LoadBaselineFile(path string, expectedKind kernel.OutputKind) (*evaluation.Baseline, error) {
	return NewLoader().Baseline(path, expectedKind)
}
