package manifest

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/internal/platform/fsutil"
)

func newGenerateCmd() *cobra.Command {
	var observationsDir, outPath string

	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate unsigned manifest JSON for observation files",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			gf := cmdutil.GetGlobalFlags(cmd)
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
