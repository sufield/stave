package baseline

import (
	"context"
	"fmt"
	"io"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/enforce/shared"
	"github.com/sufield/stave/internal/adapters/output"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/pkg/jsonutil"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation/remediation"
	"github.com/sufield/stave/pkg/alpha/domain/kernel"
	"github.com/sufield/stave/pkg/alpha/domain/ports"
)

// SaveConfig holds the parameters for the baseline save subcommand.
type SaveConfig struct {
	InPath  string
	OutPath string
}

// CheckConfig holds the parameters for the baseline check subcommand.
type CheckConfig struct {
	InPath       string
	BaselinePath string
	FailOnNew    bool
}

// Runner orchestrates the creation and validation of baseline findings.
type Runner struct {
	Clock       ports.Clock
	Sanitizer   kernel.Sanitizer
	FileOptions cmdutil.FileOptions
	Stdout      io.Writer
}

// NewRunner initializes a baseline runner with required dependencies.
func NewRunner(clock ports.Clock, san kernel.Sanitizer, fileOpts cmdutil.FileOptions, stdout io.Writer) *Runner {
	return &Runner{
		Clock:       clock,
		Sanitizer:   san,
		FileOptions: fileOpts,
		Stdout:      stdout,
	}
}

// Save captures current evaluation findings into a baseline file.
func (r *Runner) Save(_ context.Context, cfg SaveConfig) error {
	inPath := fsutil.CleanUserPath(cfg.InPath)
	outPath := fsutil.CleanUserPath(cfg.OutPath)

	eval, err := shared.NewLoader().Evaluation(inPath)
	if err != nil {
		return err
	}
	entries := remediation.BaselineEntriesFromFindings(eval.Findings)
	entries = output.SanitizeBaselineEntries(r.Sanitizer, entries)

	baseline := evaluation.Baseline{
		SchemaVersion:    kernel.SchemaBaseline,
		Kind:             kernel.KindBaseline,
		CreatedAt:        r.Clock.Now().UTC(),
		SourceEvaluation: inPath,
		Findings:         entries,
	}

	f, err := cmdutil.OpenOutputFile(outPath, r.FileOptions)
	if err != nil {
		return fmt.Errorf("create %s: %w", outPath, err)
	}
	defer f.Close()
	if err := jsonutil.WriteIndented(f, baseline); err != nil {
		return fmt.Errorf("write baseline file: %w", err)
	}

	_, _ = fmt.Fprintf(r.Stdout, "Saved baseline: %s (findings=%d)\n", outPath, len(entries))
	return nil
}

// Check compares evaluation findings against an existing baseline.
func (r *Runner) Check(_ context.Context, cfg CheckConfig) error {
	inPath := fsutil.CleanUserPath(cfg.InPath)
	baselinePath := fsutil.CleanUserPath(cfg.BaselinePath)

	eval, err := shared.NewLoader().Evaluation(inPath)
	if err != nil {
		return err
	}
	current := remediation.BaselineEntriesFromFindings(eval.Findings)
	current = output.SanitizeBaselineEntries(r.Sanitizer, current)

	base, err := shared.NewLoader().Baseline(baselinePath, kernel.KindBaseline)
	if err != nil {
		return err
	}

	comparison := evaluation.CompareBaseline(base.Findings, current)
	result := evaluation.BaselineComparison{
		SchemaVersion: kernel.SchemaBaseline,
		Kind:          kernel.KindBaselineCheck,
		CheckedAt:     r.Clock.Now().UTC(),
		BaselineFile:  baselinePath,
		Evaluation:    inPath,
		Summary: evaluation.BaselineComparisonSummary{
			BaselineFindings: len(base.Findings),
			CurrentFindings:  len(current),
			NewFindings:      len(comparison.New),
			ResolvedFindings: len(comparison.Resolved),
		},
		New:      comparison.New,
		Resolved: comparison.Resolved,
	}

	if err := jsonutil.WriteIndented(r.Stdout, result); err != nil {
		return fmt.Errorf("write baseline check output: %w", err)
	}

	if cfg.FailOnNew && comparison.HasNewFindings() {
		return ui.ErrViolationsFound
	}
	return nil
}
