package cidiff

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/sufield/stave/cmd/enforce/shared"
	"github.com/sufield/stave/internal/adapters/output"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/evaluation/remediation"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/ports"
	"github.com/sufield/stave/internal/pkg/jsonutil"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// Config defines the parameters for the CI diff operation.
type Config struct {
	CurrentPath  string
	BaselinePath string
	FailOnNew    bool
}

// Runner orchestrates the comparison of two evaluation results.
type Runner struct {
	Clock     ports.Clock
	Sanitizer kernel.Sanitizer
	Stdout    io.Writer
}

// NewRunner initializes a diff runner with required dependencies.
func NewRunner(clock ports.Clock, san kernel.Sanitizer, stdout io.Writer) *Runner {
	return &Runner{
		Clock:     clock,
		Sanitizer: san,
		Stdout:    stdout,
	}
}

// DiffSummary contains the counts for the comparison result.
type DiffSummary struct {
	BaselineFindings int `json:"baseline_findings"`
	CurrentFindings  int `json:"current_findings"`
	NewFindings      int `json:"new_findings"`
	ResolvedFindings int `json:"resolved_findings"`
}

// DiffReport represents the structured JSON output of the comparison.
type DiffReport struct {
	SchemaVersion      kernel.Schema              `json:"schema_version"`
	Kind               kernel.OutputKind          `json:"kind"`
	ComparedAt         time.Time                  `json:"compared_at"`
	CurrentEvaluation  string                     `json:"current_evaluation"`
	BaselineEvaluation string                     `json:"baseline_evaluation"`
	Summary            DiffSummary                `json:"summary"`
	New                []evaluation.BaselineEntry `json:"new"`
	Resolved           []evaluation.BaselineEntry `json:"resolved"`
}

// Run executes the comparison workflow.
func (r *Runner) Run(_ context.Context, cfg Config) error {
	currentPath := fsutil.CleanUserPath(cfg.CurrentPath)
	baselinePath := fsutil.CleanUserPath(cfg.BaselinePath)

	currentEval, err := shared.NewLoader().Evaluation(currentPath)
	if err != nil {
		return fmt.Errorf("load current evaluation: %w", err)
	}
	currentEntries := remediation.BaselineEntriesFromFindings(currentEval.Findings)

	baselineEval, err := shared.NewLoader().Evaluation(baselinePath)
	if err != nil {
		return fmt.Errorf("load baseline evaluation: %w", err)
	}
	baselineEntries := remediation.BaselineEntriesFromFindings(baselineEval.Findings)

	currentEntries = output.SanitizeBaselineEntries(r.Sanitizer, currentEntries)
	baselineEntries = output.SanitizeBaselineEntries(r.Sanitizer, baselineEntries)

	comparison := evaluation.CompareBaseline(baselineEntries, currentEntries)
	report := DiffReport{
		SchemaVersion:      kernel.SchemaCIDiff,
		Kind:               kernel.KindCIDiff,
		ComparedAt:         r.Clock.Now().UTC(),
		CurrentEvaluation:  sanitizePath(r.Sanitizer, currentPath),
		BaselineEvaluation: sanitizePath(r.Sanitizer, baselinePath),
		Summary: DiffSummary{
			BaselineFindings: len(baselineEntries),
			CurrentFindings:  len(currentEntries),
			NewFindings:      len(comparison.New),
			ResolvedFindings: len(comparison.Resolved),
		},
		New:      comparison.New,
		Resolved: comparison.Resolved,
	}

	if report.New == nil {
		report.New = []evaluation.BaselineEntry{}
	}
	if report.Resolved == nil {
		report.Resolved = []evaluation.BaselineEntry{}
	}

	if err := jsonutil.WriteIndented(r.Stdout, report); err != nil {
		return fmt.Errorf("write diff output: %w", err)
	}

	if cfg.FailOnNew && comparison.HasNewFindings() {
		return ui.ErrViolationsFound
	}
	return nil
}

func sanitizePath(s kernel.Sanitizer, p string) string {
	if s == nil {
		return p
	}
	return s.Path(p)
}
