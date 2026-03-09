package manifest

import "github.com/spf13/cobra"

func newGenerateCmd() *cobra.Command {
	var observationsDir, outPath string

	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate unsigned manifest JSON for observation files",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runSnapshotManifestGenerate(cmd, observationsDir, outPath)
		},
	}

	cmd.Flags().StringVarP(&observationsDir, "observations", "o", "observations", "Path to observation snapshots directory")
	cmd.Flags().StringVar(&outPath, "out", "manifest.json", "Output manifest file path")

	return cmd
}
