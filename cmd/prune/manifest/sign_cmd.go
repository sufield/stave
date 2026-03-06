package manifest

import "github.com/spf13/cobra"

var SignCmd = &cobra.Command{
	Use:   "sign",
	Short: "Sign manifest JSON with an Ed25519 private key",
	Args:  cobra.NoArgs,
	RunE:  runSnapshotManifestSign,
}

func init() {
	SignCmd.Flags().StringVar(&snapshotManifestInPath, "in", "", "Input unsigned manifest file path (required)")
	SignCmd.Flags().StringVar(&snapshotManifestPrivateKeyPath, "private-key", "", "Ed25519 private key path (PEM; required)")
	SignCmd.Flags().StringVar(&snapshotManifestOutPath, "out", "signed-manifest.json", "Output signed manifest file path")
	_ = SignCmd.MarkFlagRequired("in")
	_ = SignCmd.MarkFlagRequired("private-key")
}
