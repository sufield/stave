package baseline

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/enforce/shared"
	"github.com/sufield/stave/internal/adapters/output"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/evaluation/remediation"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/pkg/jsonutil"
	"github.com/sufield/stave/internal/platform/fsutil"
)

const (
	baselineKind      = kernel.KindBaseline
	baselineCheckKind = kernel.KindBaselineCheck
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

func runSave(cmd *cobra.Command, cfg SaveConfig) error {
	gf := cmdutil.GetGlobalFlags(cmd)
	inPath := fsutil.CleanUserPath(cfg.InPath)
	outPath := fsutil.CleanUserPath(cfg.OutPath)

	eval, err := shared.LoadEvaluationEnvelope(inPath)
	if err != nil {
		return err
	}
	entries := remediation.BaselineEntriesFromFindings(eval.Findings)
	entries = output.SanitizeBaselineEntries(gf.GetSanitizer(), entries)

	out := evaluation.Baseline{
		SchemaVersion:    kernel.SchemaBaseline,
		Kind:             baselineKind,
		CreatedAt:        time.Now().UTC(),
		SourceEvaluation: inPath,
		Findings:         entries,
	}

	f, err := cmdutil.PrepareOutputFile(outPath, gf)
	if err != nil {
		return fmt.Errorf("create %s: %w", outPath, err)
	}
	defer f.Close()
	if err := jsonutil.WriteIndented(f, out); err != nil {
		return fmt.Errorf("write baseline file: %w", err)
	}

	if gf.TextOutputEnabled() {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Saved baseline: %s (findings=%d)\n", outPath, len(entries))
	}
	return nil
}

func runCheck(cmd *cobra.Command, cfg CheckConfig) error {
	inPath := fsutil.CleanUserPath(cfg.InPath)
	baselinePath := fsutil.CleanUserPath(cfg.BaselinePath)

	eval, err := shared.LoadEvaluationEnvelope(inPath)
	if err != nil {
		return err
	}
	current := remediation.BaselineEntriesFromFindings(eval.Findings)
	current = output.SanitizeBaselineEntries(cmdutil.GetGlobalFlags(cmd).GetSanitizer(), current)

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

	if err := jsonutil.WriteIndented(cmd.OutOrStdout(), result); err != nil {
		return fmt.Errorf("write baseline check output: %w", err)
	}

	if cfg.FailOnNew && comparison.HasNewFindings() {
		return ui.ErrViolationsFound
	}
	return nil
}
