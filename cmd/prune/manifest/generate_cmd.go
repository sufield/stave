package manifest

import "github.com/spf13/cobra"

var GenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate unsigned manifest JSON for observation files",
	Args:  cobra.NoArgs,
	RunE:  runSnapshotManifestGenerate,
}

func init() {
	GenerateCmd.Flags().StringVarP(&snapshotManifestObservationsDir, "observations", "o", "observations", "Path to observation snapshots directory")
	GenerateCmd.Flags().StringVar(&snapshotManifestOutPath, "out", "manifest.json", "Output manifest file path")
}
