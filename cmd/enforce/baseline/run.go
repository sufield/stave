package baseline

import (
	"context"
	"fmt"
	"io"

	"github.com/sufield/stave/cmd/cmdutil/fileout"
	"github.com/sufield/stave/cmd/enforce/artifact"
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
	FileOptions fileout.FileOptions
	Stdout      io.Writer
}

// NewRunner initializes a baseline runner with required dependencies.
func NewRunner(clock ports.Clock, san kernel.Sanitizer, fileOpts fileout.FileOptions, stdout io.Writer) *Runner {
	return &Runner{
		Clock:       clock,
		Sanitizer:   san,
		FileOptions: fileOpts,
		Stdout:      stdout,
	}
}

// Save captures current evaluation findings into a baseline file.
func (r *Runner) Save(ctx context.Context, cfg SaveConfig) error {
	inPath := fsutil.CleanUserPath(cfg.InPath)
	outPath := fsutil.CleanUserPath(cfg.OutPath)

	eval, err := artifact.NewLoader().Evaluation(ctx, inPath)
	if err != nil {
		return fmt.Errorf("load evaluation %s: %w", inPath, err)
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

	f, err := fileout.OpenOutputFile(outPath, r.FileOptions)
	if err != nil {
		return fmt.Errorf("create baseline file %s: %w", outPath, err)
	}
	defer f.Close()
	if err := jsonutil.WriteIndented(f, baseline); err != nil {
		return fmt.Errorf("write baseline file: %w", err)
	}

	_, _ = fmt.Fprintf(r.Stdout, "Saved baseline: %s (findings=%d)\n", outPath, len(entries))
	return nil
}

// Check compares evaluation findings against an existing baseline.
func (r *Runner) Check(ctx context.Context, cfg CheckConfig) error {
	inPath := fsutil.CleanUserPath(cfg.InPath)
	baselinePath := fsutil.CleanUserPath(cfg.BaselinePath)

	eval, err := artifact.NewLoader().Evaluation(ctx, inPath)
	if err != nil {
		return fmt.Errorf("load evaluation %s: %w", inPath, err)
	}
	current := remediation.BaselineEntriesFromFindings(eval.Findings)
	current = output.SanitizeBaselineEntries(r.Sanitizer, current)

	base, err := artifact.NewLoader().Baseline(ctx, baselinePath, kernel.KindBaseline)
	if err != nil {
		return fmt.Errorf("load baseline %s: %w", baselinePath, err)
	}

	comparison := evaluation.CompareBaseline(base.Findings, current)
	result := comparison.ToReport(
		r.Clock.Now().UTC(), baselinePath, inPath,
		len(base.Findings), len(current),
	)

	if err := jsonutil.WriteIndented(r.Stdout, result); err != nil {
		return fmt.Errorf("write baseline check output: %w", err)
	}

	if cfg.FailOnNew && comparison.HasNewFindings() {
		return ui.ErrViolationsFound
	}
	return nil
}
