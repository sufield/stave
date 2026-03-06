package cidiff

import (
	"fmt"
	"io"
	"time"

	"github.com/sufield/stave/cmd/enforce/shared"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/evaluation/remediation"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/platform/fsutil"
)

const kind = "ci_diff"

type options struct {
	CurrentPath  string
	BaselinePath string
	FailOnNew    bool
}

type summary struct {
	BaselineFindings int `json:"baseline_findings"`
	CurrentFindings  int `json:"current_findings"`
	NewFindings      int `json:"new_findings"`
	ResolvedFindings int `json:"resolved_findings"`
}

type result struct {
	SchemaVersion      kernel.Schema              `json:"schema_version"`
	Kind               string                     `json:"kind"`
	ComparedAt         time.Time                  `json:"compared_at"`
	CurrentEvaluation  string                     `json:"current_evaluation"`
	BaselineEvaluation string                     `json:"baseline_evaluation"`
	Summary            summary                    `json:"summary"`
	New                []evaluation.BaselineEntry `json:"new"`
	Resolved           []evaluation.BaselineEntry `json:"resolved"`
}

func run(w io.Writer, opts *options) error {
	currentPath := fsutil.CleanUserPath(opts.CurrentPath)
	baselinePath := fsutil.CleanUserPath(opts.BaselinePath)

	currentEval, err := shared.LoadEvaluationEnvelope(currentPath)
	if err != nil {
		return fmt.Errorf("load current evaluation: %w", err)
	}
	currentEntries := remediation.BaselineEntriesFromFindings(currentEval.Findings)

	baselineEval, err := shared.LoadEvaluationEnvelope(baselinePath)
	if err != nil {
		return fmt.Errorf("load baseline evaluation: %w", err)
	}
	baselineEntries := remediation.BaselineEntriesFromFindings(baselineEval.Findings)

	comparison := evaluation.CompareBaseline(baselineEntries, currentEntries)
	res := result{
		SchemaVersion:      kernel.SchemaCIDiff,
		Kind:               kind,
		ComparedAt:         time.Now().UTC(),
		CurrentEvaluation:  currentPath,
		BaselineEvaluation: baselinePath,
		Summary: summary{
			BaselineFindings: len(baselineEntries),
			CurrentFindings:  len(currentEntries),
			NewFindings:      len(comparison.New),
			ResolvedFindings: len(comparison.Resolved),
		},
		New:      comparison.New,
		Resolved: comparison.Resolved,
	}

	if res.New == nil {
		res.New = []evaluation.BaselineEntry{}
	}
	if res.Resolved == nil {
		res.Resolved = []evaluation.BaselineEntry{}
	}

	if err := shared.WriteJSON(w, res); err != nil {
		return fmt.Errorf("write diff output: %w", err)
	}

	if opts.FailOnNew && comparison.HasNewFindings() {
		return ui.ErrViolationsFound
	}
	return nil
}
