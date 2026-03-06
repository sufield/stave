package manifest

import "github.com/spf13/cobra"

var KeygenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Generate an Ed25519 keypair for manifest signing",
	Args:  cobra.NoArgs,
	RunE:  runSnapshotManifestKeygen,
}

func init() {
	KeygenCmd.Flags().StringVar(&snapshotManifestPrivateKeyPath, "private-key-out", "manifest.private", "Output private key path")
	KeygenCmd.Flags().StringVar(&snapshotManifestPublicKeyOut, "public-key-out", "manifest.public", "Output public key path")
}
