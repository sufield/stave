package baseline

import (
	"io"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/cmd/cmdutil/fileout"
	"github.com/sufield/stave/internal/metadata"
	"github.com/sufield/stave/pkg/alpha/domain/ports"
)

// NewCmd constructs the baseline command tree.
func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "baseline",
		Short: "Manage baseline findings for fail-on-new CI workflows",
		Long: `Baseline helps CI/CD fail only on newly introduced findings.

Use:
  - baseline save: capture current findings as baseline
  - baseline check: compare current findings against a baseline

Example:
  stave apply --controls ./controls --observations ./observations --format json > output/evaluation.json
  stave ci baseline save --in output/evaluation.json --out output/baseline.json
  stave ci baseline check --in output/evaluation.json --baseline output/baseline.json` + metadata.OfflineHelpSuffix,
		Args: cobra.NoArgs,
	}

	cmd.AddCommand(newSaveCmd())
	cmd.AddCommand(newCheckCmd())

	return cmd
}

func newRunner(cmd *cobra.Command) *Runner {
	gf := cliflags.GetGlobalFlags(cmd)
	stdout := cmd.OutOrStdout()
	if !gf.TextOutputEnabled() {
		stdout = io.Discard
	}
	return NewRunner(
		ports.RealClock{},
		gf.GetSanitizer(),
		fileout.FileOptions{
			Overwrite:     gf.Force,
			AllowSymlinks: gf.AllowSymlinkOut,
			DirPerms:      0o700,
		},
		stdout,
	)
}

// --- Save Subcommand ---

func newSaveCmd() *cobra.Command {
	cfg := SaveConfig{
		OutPath: "output/baseline.json",
	}

	cmd := &cobra.Command{
		Use:   "save",
		Short: "Save evaluation findings as baseline",
		Long: `Save captures the current evaluation findings as a baseline snapshot.
Subsequent runs of 'baseline check' compare new findings against this
baseline so CI only fails on newly introduced violations.

Inputs:
  --in     Path to evaluation JSON from 'stave apply --format json'
  --out    Output path for the baseline file (default: output/baseline.json)

Exit Codes:
  0    Baseline saved successfully
  2    Input error (missing or invalid evaluation file)
  4    Internal error`,
		Example: `  stave ci baseline save --in output/evaluation.json
  stave ci baseline save --in output/evaluation.json --out baselines/2026-03.json`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return newRunner(cmd).Save(cmd.Context(), cfg)
		},
	}

	cmd.Flags().StringVar(&cfg.InPath, "in", "", "Path to evaluation JSON (required)")
	cmd.Flags().StringVar(&cfg.OutPath, "out", cfg.OutPath, "Path to baseline output JSON")
	_ = cmd.MarkFlagRequired("in")

	return cmd
}

// --- Check Subcommand ---

func newCheckCmd() *cobra.Command {
	cfg := CheckConfig{
		FailOnNew: true,
	}

	cmd := &cobra.Command{
		Use:   "check",
		Short: "Compare evaluation findings against baseline and detect new findings",
		Long: `Check compares current evaluation findings against a saved baseline.
New findings (not in the baseline) are reported. Use --fail-on-new to
fail the CI pipeline when new violations appear.

Inputs:
  --in          Path to current evaluation JSON
  --baseline    Path to saved baseline JSON
  --fail-on-new Exit 3 when new findings detected (default: true)

Exit Codes:
  0    No new findings (or --fail-on-new=false)
  2    Input error (missing or invalid files)
  3    New findings detected (when --fail-on-new is true)
  4    Internal error`,
		Example: `  stave ci baseline check --in output/evaluation.json --baseline output/baseline.json
  stave ci baseline check --in output/evaluation.json --baseline output/baseline.json --fail-on-new=false`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return newRunner(cmd).Check(cmd.Context(), cfg)
		},
	}

	cmd.Flags().StringVar(&cfg.InPath, "in", "", "Path to evaluation JSON (required)")
	cmd.Flags().StringVar(&cfg.BaselinePath, "baseline", "", "Path to baseline JSON (required)")
	cmd.Flags().BoolVar(&cfg.FailOnNew, "fail-on-new", cfg.FailOnNew, "Return exit code 3 when new findings are detected")
	_ = cmd.MarkFlagRequired("in")
	_ = cmd.MarkFlagRequired("baseline")

	return cmd
}
