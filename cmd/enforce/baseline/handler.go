package baseline

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/enforce/shared"
	"github.com/sufield/stave/internal/adapters/output"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/evaluation/remediation"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/platform/fsutil"
)

const (
	baselineKind      = "baseline"
	baselineCheckKind = "baseline_check"
)

type saveOptions struct {
	InPath  string
	OutPath string
}

type checkOptions struct {
	InPath       string
	BaselinePath string
	FailOnNew    bool
}

func runSave(cmd *cobra.Command, opts *saveOptions) error {
	inPath := fsutil.CleanUserPath(opts.InPath)
	outPath := fsutil.CleanUserPath(opts.OutPath)

	eval, err := shared.LoadEvaluationEnvelope(inPath)
	if err != nil {
		return err
	}
	entries := remediation.BaselineEntriesFromFindings(eval.Findings)
	entries = output.SanitizeBaselineEntries(cmdutil.GetSanitizer(cmd), entries)

	out := evaluation.Baseline{
		SchemaVersion:    kernel.SchemaBaseline,
		Kind:             baselineKind,
		CreatedAt:        time.Now().UTC(),
		SourceEvaluation: inPath,
		Findings:         entries,
	}

	mkErr := fsutil.SafeMkdirAll(filepath.Dir(outPath), fsutil.WriteOptions{Perm: 0o700, AllowSymlink: cmdutil.AllowSymlinkOutEnabled(cmd)})
	if mkErr != nil {
		return fmt.Errorf("create output directory: %w", mkErr)
	}
	writeOpts := fsutil.DefaultWriteOpts()
	writeOpts.Overwrite = cmdutil.ForceEnabled(cmd)
	writeOpts.AllowSymlink = cmdutil.AllowSymlinkOutEnabled(cmd)
	f, err := fsutil.SafeCreateFile(outPath, writeOpts)
	if err != nil {
		return fmt.Errorf("create %s: %w", outPath, err)
	}
	defer f.Close()
	if err := shared.WriteJSON(f, out); err != nil {
		return fmt.Errorf("write baseline file: %w", err)
	}

	if !cmdutil.QuietEnabled(cmd) {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Saved baseline: %s (findings=%d)\n", outPath, len(entries))
	}
	return nil
}

func runCheck(cmd *cobra.Command, opts *checkOptions) error {
	inPath := fsutil.CleanUserPath(opts.InPath)
	baselinePath := fsutil.CleanUserPath(opts.BaselinePath)

	eval, err := shared.LoadEvaluationEnvelope(inPath)
	if err != nil {
		return err
	}
	current := remediation.BaselineEntriesFromFindings(eval.Findings)
	current = output.SanitizeBaselineEntries(cmdutil.GetSanitizer(cmd), current)

	base, err := shared.LoadBaselineFile(baselinePath, baselineKind)
	if err != nil {
		return err
	}

	comparison := evaluation.CompareBaseline(base.Findings, current)
	result := evaluation.BaselineComparison{
		SchemaVersion: kernel.SchemaBaseline,
		Kind:          baselineCheckKind,
		CheckedAt:     time.Now().UTC(),
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

	if err := shared.WriteJSON(cmd.OutOrStdout(), result); err != nil {
		return fmt.Errorf("write baseline check output: %w", err)
	}

	if opts.FailOnNew && comparison.HasNewFindings() {
		return ui.ErrViolationsFound
	}
	return nil
}
