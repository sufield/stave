package manifest

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/internal/metadata"
	"github.com/sufield/stave/internal/platform/fsutil"
)

func newKeygenCmd() *cobra.Command {
	var privateKeyOut, publicKeyOut string

	cmd := &cobra.Command{
		Use:   "keygen",
		Short: "Generate an Ed25519 keypair for manifest signing",
		Long: `Keygen creates an Ed25519 keypair for use with 'manifest sign' and
'stave verify'. The private key signs manifests; the public key is
distributed for verification.

Inputs:
  --private-key-out  Output private key path (default: manifest.private)
  --public-key-out   Output public key path (default: manifest.public)

Outputs:
  file               Ed25519 private key (PEM) at --private-key-out
  file               Ed25519 public key (PEM) at --public-key-out
  stdout             Confirmation message (text mode)

Exit Codes:
  0   - Keypair generated successfully
  2   - Invalid input (path conflict, permission error)
  4   - Internal error
  130 - Interrupted (SIGINT)

Examples:
  stave manifest keygen
  stave manifest keygen --private-key-out keys/sign.pem --public-key-out keys/verify.pem` + metadata.OfflineHelpSuffix,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			gf := cliflags.GetGlobalFlags(cmd)
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
