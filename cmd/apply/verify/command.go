package verify

import (
	"github.com/spf13/cobra"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/metadata"
)

// VerifyCmd is the package-level command for existing callers.
var VerifyCmd = NewCmd(ui.NewRuntime(nil, nil))

// NewCmd builds the verify command.
func NewCmd(rt *ui.Runtime) *cobra.Command {
	if rt == nil {
		rt = ui.NewRuntime(nil, nil)
	}

	opts := defaultOptions()

	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Compare before/after evaluations to check remediation",
		Long: `Verify runs the same controls against two sets of observations
(before and after remediation) and reports which findings were resolved,
which remain, and which are newly introduced.

Input:
  --before      Directory containing before-remediation observations
  --after       Directory containing after-remediation observations
  --controls  Directory containing control definitions

Output:
  stdout  JSON comparison result with resolved/remaining/introduced findings

Exit Codes:
  0   - No remaining or introduced violations
  3   - Remaining or introduced violations exist

Examples:
  # 1. Compare before and after observations to measure remediation progress.
  stave verify --before ./obs-before --after ./obs-after --controls ./controls --now 2026-01-11T00:00:00Z

  # 2. Save verification results for CI artifacts.
  stave verify --before ./obs-before --after ./obs-after --controls ./controls --now 2026-01-11T00:00:00Z > results/verification.json

  # 3. Pipe output to jq to inspect resolved violations.
  stave verify --before ./obs-before --after ./obs-after --controls ./controls | jq '.resolved[]'

    Sample output (resolved entry):
      { "control_id": "CTL.S3.PUBLIC.001", "asset_id": "my-bucket", ... }` + metadata.OfflineHelpSuffix,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runVerify(cmd, rt, opts)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	opts.BindFlags(cmd)
	return cmd
}
