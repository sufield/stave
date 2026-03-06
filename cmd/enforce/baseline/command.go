package baseline

import (
	"github.com/spf13/cobra"
	"github.com/sufield/stave/internal/metadata"
)

func NewCmd() *cobra.Command {
	saveOpts := &saveOptions{OutPath: "output/baseline.json"}
	checkOpts := &checkOptions{FailOnNew: true}

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

	saveCmd := &cobra.Command{
		Use:   "save",
		Short: "Save evaluation findings as baseline",
		Args:  cobra.NoArgs,
		RunE:  func(cmd *cobra.Command, _ []string) error { return runSave(cmd, saveOpts) },
	}
	saveCmd.Flags().StringVar(&saveOpts.InPath, "in", "", "Path to evaluation JSON (required)")
	saveCmd.Flags().StringVar(&saveOpts.OutPath, "out", saveOpts.OutPath, "Path to baseline output JSON")
	_ = saveCmd.MarkFlagRequired("in")

	checkCmd := &cobra.Command{
		Use:   "check",
		Short: "Compare evaluation findings against baseline and detect new findings",
		Args:  cobra.NoArgs,
		RunE:  func(cmd *cobra.Command, _ []string) error { return runCheck(cmd, checkOpts) },
	}
	checkCmd.Flags().StringVar(&checkOpts.InPath, "in", "", "Path to evaluation JSON (required)")
	checkCmd.Flags().StringVar(&checkOpts.BaselinePath, "baseline", "", "Path to baseline JSON (required)")
	checkCmd.Flags().BoolVar(&checkOpts.FailOnNew, "fail-on-new", checkOpts.FailOnNew, "Return exit code 3 when new findings are detected")
	_ = checkCmd.MarkFlagRequired("in")
	_ = checkCmd.MarkFlagRequired("baseline")

	cmd.AddCommand(saveCmd)
	cmd.AddCommand(checkCmd)
	return cmd
}
