package baseline

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/platform/metadata"
	"github.com/sufield/stave/pkg/stave"
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

// --- Save Subcommand ---

func newSaveCmd() *cobra.Command {
	var (
		inPath  string
		outPath = "output/baseline.json"
	)

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
			out, err := stave.BaselineSave(cmd.Context(), inPath, outPath)
			if err != nil {
				return err //nolint:wrapcheck // facade already wrapped ("save baseline"); preserve exit 4.
			}
			if _, werr := cmd.OutOrStdout().Write(out); werr != nil {
				return fmt.Errorf("write output: %w", werr)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&inPath, "in", "", "Path to evaluation JSON (required)")
	cmd.Flags().StringVar(&outPath, "out", outPath, "Path to baseline output JSON")
	_ = cmd.MarkFlagRequired("in")

	return cmd
}

// --- Check Subcommand ---

func newCheckCmd() *cobra.Command {
	var (
		inPath       string
		baselinePath string
		failOnNew    = true
	)

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
			out, hasNew, err := stave.BaselineCheck(cmd.Context(), inPath, baselinePath, failOnNew)
			if err != nil {
				return err //nolint:wrapcheck // facade already wrapped ("check baseline"/"write output"); preserve exit 4.
			}
			if _, werr := cmd.OutOrStdout().Write(out); werr != nil {
				return fmt.Errorf("write output: %w", werr)
			}
			if hasNew {
				return ui.ErrViolationsFound
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&inPath, "in", "", "Path to evaluation JSON (required)")
	cmd.Flags().StringVar(&baselinePath, "baseline", "", "Path to baseline JSON (required)")
	cmd.Flags().BoolVar(&failOnNew, "fail-on-new", failOnNew, "Return exit code 3 when new findings are detected")
	_ = cmd.MarkFlagRequired("in")
	_ = cmd.MarkFlagRequired("baseline")

	return cmd
}
