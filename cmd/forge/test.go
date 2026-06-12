package forge

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/pkg/stave"
)

func newTestCmd() *cobra.Command {
	var controlPath, passFixture, failFixture, snapshotPath string
	var watch, verbose bool

	cmd := &cobra.Command{
		Use:   "test",
		Short: "Run fixture-based assertions against a control",
		Long: `Evaluate a control predicate against pass and fail fixture files
and assert the expected verdict. Shows predicate trace on failure.

Exit Codes:
  0   All assertions passed
  1   One or more assertions failed
  2   Invalid input
  4   Internal error`,
		Example: `  stave forge test \
    --control controls/ad/CTL.AD.PASS.MINLEN.001.yaml \
    --pass testdata/fixture-pass.json \
    --fail testdata/fixture-fail.json`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if passFixture == "" && failFixture == "" && snapshotPath == "" {
				return errors.New("at least one of --pass, --fail, or --snapshot is required")
			}
			out, err := stave.ForgeTest(controlPath, passFixture, failFixture, snapshotPath, verbose)
			if _, werr := cmd.OutOrStdout().Write(out); werr != nil && err == nil {
				return fmt.Errorf("write test output: %w", werr)
			}
			return err //nolint:wrapcheck // facade already wrapped; preserve exit codes.
		},
	}

	cmd.Flags().StringVar(&controlPath, "control", "", "path to control YAML file (required)")
	cmd.Flags().StringVar(&passFixture, "pass", "", "fixture that must produce verdict: pass")
	cmd.Flags().StringVar(&failFixture, "fail", "", "fixture that must produce verdict: fail")
	cmd.Flags().StringVar(&snapshotPath, "snapshot", "", "real snapshot for smoke test")
	cmd.Flags().BoolVar(&watch, "watch", false, "re-run on control file change")
	cmd.Flags().BoolVar(&verbose, "verbose", false, "show trace on pass")
	_ = cmd.MarkFlagRequired("control")

	return cmd
}
