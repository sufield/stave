package manifest

import "github.com/spf13/cobra"

func newSignCmd() *cobra.Command {
	var inPath, privateKeyPath, outPath string

	cmd := &cobra.Command{
		Use:   "sign",
		Short: "Sign manifest JSON with an Ed25519 private key",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runSnapshotManifestSign(cmd, inPath, privateKeyPath, outPath)
		},
	}

	cmd.Flags().StringVar(&inPath, "in", "", "Input unsigned manifest file path (required)")
	cmd.Flags().StringVar(&privateKeyPath, "private-key", "", "Ed25519 private key path (PEM; required)")
	cmd.Flags().StringVar(&outPath, "out", "signed-manifest.json", "Output signed manifest file path")
	_ = cmd.MarkFlagRequired("in")
	_ = cmd.MarkFlagRequired("private-key")

	return cmd
}
