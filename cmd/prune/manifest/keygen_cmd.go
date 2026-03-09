package manifest

import "github.com/spf13/cobra"

func newKeygenCmd() *cobra.Command {
	var privateKeyOut, publicKeyOut string

	cmd := &cobra.Command{
		Use:   "keygen",
		Short: "Generate an Ed25519 keypair for manifest signing",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runSnapshotManifestKeygen(cmd, privateKeyOut, publicKeyOut)
		},
	}

	cmd.Flags().StringVar(&privateKeyOut, "private-key-out", "manifest.private", "Output private key path")
	cmd.Flags().StringVar(&publicKeyOut, "public-key-out", "manifest.public", "Output public key path")

	return cmd
}
