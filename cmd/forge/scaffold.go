package forge

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/pkg/stave"
)

func newScaffoldCmd() *cobra.Command {
	var controlPath, snapshotPath, outDir string

	cmd := &cobra.Command{
		Use:   "scaffold",
		Short: "Generate test fixtures from a real snapshot",
		Long: `Generate minimal pass and fail fixture files for use with
stave forge test. Extracts only properties referenced by the
control's predicate.

Exit Codes:
  0   Fixtures generated
  2   Invalid input
  4   Internal error`,
		Example: `  stave forge scaffold \
    --control controls/ad/CTL.AD.PASS.MINLEN.001.yaml \
    --snapshot snapshots/acme-dc.json`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out, err := stave.ForgeScaffold(controlPath, snapshotPath, outDir)
			if _, werr := cmd.OutOrStdout().Write(out); werr != nil && err == nil {
				return fmt.Errorf("write scaffold output: %w", werr)
			}
			return err //nolint:wrapcheck // facade already wrapped; preserve exit codes.
		},
	}

	cmd.Flags().StringVar(&controlPath, "control", "", "path to control YAML file (required)")
	cmd.Flags().StringVar(&snapshotPath, "snapshot", "", "path to snapshot file (required)")
	cmd.Flags().StringVar(&outDir, "out-dir", "", "output directory (default: testdata/<control_id>/)")
	_ = cmd.MarkFlagRequired("control")
	_ = cmd.MarkFlagRequired("snapshot")

	return cmd
}
