package manifest

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/internal/platform/fsutil"
)

func newKeygenCmd() *cobra.Command {
	var privateKeyOut, publicKeyOut string

	cmd := &cobra.Command{
		Use:   "keygen",
		Short: "Generate an Ed25519 keypair for manifest signing",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			gf := cmdutil.GetGlobalFlags(cmd)
			runner := &KeygenRunner{}
			return runner.Run(KeygenConfig{
				PrivateKeyPath: fsutil.CleanUserPath(privateKeyOut),
				PublicKeyPath:  fsutil.CleanUserPath(publicKeyOut),
				TextOutput:     gf.TextOutputEnabled(),
				Stdout:         cmd.OutOrStdout(),
			})
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.Flags().StringVar(&privateKeyOut, "private-key-out", "manifest.private", "Output private key path")
	cmd.Flags().StringVar(&publicKeyOut, "public-key-out", "manifest.public", "Output public key path")

	return cmd
}
