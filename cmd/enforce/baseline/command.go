package baseline

import (
	"github.com/spf13/cobra"
	"github.com/sufield/stave/internal/metadata"
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
	cfg := SaveConfig{
		OutPath: "output/baseline.json",
	}

	cmd := &cobra.Command{
		Use:   "save",
		Short: "Save evaluation findings as baseline",
		Args:  cobra.NoArgs,
		RunE:  func(cmd *cobra.Command, _ []string) error { return runSave(cmd, cfg) },
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
		Args:  cobra.NoArgs,
		RunE:  func(cmd *cobra.Command, _ []string) error { return runCheck(cmd, cfg) },
	}

	cmd.Flags().StringVar(&cfg.InPath, "in", "", "Path to evaluation JSON (required)")
	cmd.Flags().StringVar(&cfg.BaselinePath, "baseline", "", "Path to baseline JSON (required)")
	cmd.Flags().BoolVar(&cfg.FailOnNew, "fail-on-new", cfg.FailOnNew, "Return exit code 3 when new findings are detected")
	_ = cmd.MarkFlagRequired("in")
	_ = cmd.MarkFlagRequired("baseline")

	return cmd
}
