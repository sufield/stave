package manifest

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/internal/metadata"
	"github.com/sufield/stave/internal/platform/fsutil"
)

func newGenerateCmd() *cobra.Command {
	var observationsDir, outPath string

	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate unsigned manifest JSON for observation files",
		Long: `Generate creates an unsigned manifest JSON file containing content hashes
for each observation file in the specified directory. The manifest can
later be signed with 'manifest sign' for integrity verification.

Inputs:
  --observations, -o  Path to observation snapshots directory (default: observations)
  --out               Output manifest file path (default: manifest.json)

Outputs:
  file                Unsigned manifest JSON at the --out path
  stdout              Confirmation message (text mode)

Exit Codes:
  0   - Manifest generated successfully
  2   - Invalid input (directory not found, permission error)
  4   - Internal error
  130 - Interrupted (SIGINT)

Examples:
  stave manifest generate --observations ./observations
  stave manifest generate --observations ./observations --out build/manifest.json` + metadata.OfflineHelpSuffix,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			gf := cliflags.GetGlobalFlags(cmd)
			runner := &GenerateRunner{}
			return runner.Run(cmd.Context(), GenerateConfig{
				ObservationsDir: fsutil.CleanUserPath(observationsDir),
				OutPath:         fsutil.CleanUserPath(outPath),
				TextOutput:      gf.TextOutputEnabled(),
				Stdout:          cmd.OutOrStdout(),
			})
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.Flags().StringVarP(&observationsDir, "observations", "o", "observations", "Path to observation snapshots directory")
	cmd.Flags().StringVar(&outPath, "out", "manifest.json", "Output manifest file path")

	return cmd
}
