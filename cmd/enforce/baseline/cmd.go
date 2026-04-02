package baseline

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/core/reporting"
	"github.com/sufield/stave/internal/metadata"
	"github.com/sufield/stave/internal/util/jsonutil"
)

// Deps groups the infrastructure implementations for the baseline command.
type Deps struct {
	SaveDeps  reporting.BaselineSaveDeps
	CheckDeps reporting.BaselineCheckDeps
}

// NewCmd constructs the baseline command tree.
func NewCmd(deps Deps) *cobra.Command {
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

	cmd.AddCommand(newSaveCmd(deps.SaveDeps))
	cmd.AddCommand(newCheckCmd(deps.CheckDeps))

	return cmd
}

// --- Save Subcommand ---

func newSaveCmd(deps reporting.BaselineSaveDeps) *cobra.Command {
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
			req := reporting.BaselineSaveRequest{
				EvaluationPath: inPath,
				OutputPath:     outPath,
			}

			resp, err := reporting.BaselineSave(cmd.Context(), req, deps)
			if err != nil {
				return err
			}

			_, printErr := fmt.Fprintf(cmd.OutOrStdout(),
				"Saved baseline: %s (findings=%d)\n", resp.OutputPath, resp.FindingsCount)
			return printErr
		},
	}

	cmd.Flags().StringVar(&inPath, "in", "", "Path to evaluation JSON (required)")
	cmd.Flags().StringVar(&outPath, "out", outPath, "Path to baseline output JSON")
	_ = cmd.MarkFlagRequired("in")

	return cmd
}

// --- Check Subcommand ---

func newCheckCmd(deps reporting.BaselineCheckDeps) *cobra.Command {
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
			req := reporting.BaselineCheckRequest{
				EvaluationPath: inPath,
				BaselinePath:   baselinePath,
				FailOnNew:      failOnNew,
			}

			resp, err := reporting.BaselineCheck(cmd.Context(), req, deps)
			if err != nil {
				return err
			}

			if renderErr := jsonutil.WriteIndented(cmd.OutOrStdout(), resp); renderErr != nil {
				return renderErr
			}

			if req.FailOnNew && resp.HasNew {
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
