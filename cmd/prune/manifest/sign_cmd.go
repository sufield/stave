package manifest

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/internal/metadata"
	"github.com/sufield/stave/internal/platform/fsutil"
)

func newSignCmd() *cobra.Command {
	var inPath, privateKeyPath, outPath string

	cmd := &cobra.Command{
		Use:   "sign",
		Short: "Sign manifest JSON with an Ed25519 private key",
		Long: `Sign reads an unsigned manifest JSON file and produces a signed version
using an Ed25519 private key. The signed manifest can be verified with
'stave verify' during evaluation.

Inputs:
  --in            Input unsigned manifest file path (required)
  --private-key   Ed25519 private key path in PEM format (required)
  --out           Output signed manifest file path (default: signed-manifest.json)

Outputs:
  file            Signed manifest JSON at the --out path
  stdout          Confirmation message (text mode)

Exit Codes:
  0   - Manifest signed successfully
  2   - Invalid input (missing file, bad key format)
  4   - Internal error
  130 - Interrupted (SIGINT)

Examples:
  stave manifest sign --in manifest.json --private-key manifest.private
  stave manifest sign --in manifest.json --private-key keys/sign.pem --out build/signed.json` + metadata.OfflineHelpSuffix,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			gf := cliflags.GetGlobalFlags(cmd)
			runner := &SignRunner{}
			return runner.Run(SignConfig{
				InPath:         fsutil.CleanUserPath(inPath),
				PrivateKeyPath: fsutil.CleanUserPath(privateKeyPath),
				OutPath:        fsutil.CleanUserPath(outPath),
				TextOutput:     gf.TextOutputEnabled(),
				Stdout:         cmd.OutOrStdout(),
			})
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.Flags().StringVar(&inPath, "in", "", "Input unsigned manifest file path (required)")
	cmd.Flags().StringVar(&privateKeyPath, "private-key", "", "Ed25519 private key path (PEM; required)")
	cmd.Flags().StringVar(&outPath, "out", "signed-manifest.json", "Output signed manifest file path")
	_ = cmd.MarkFlagRequired("in")
	_ = cmd.MarkFlagRequired("private-key")

	return cmd
}
