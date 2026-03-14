package manifest

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/internal/platform/fsutil"
)

func newSignCmd() *cobra.Command {
	var inPath, privateKeyPath, outPath string

	cmd := &cobra.Command{
		Use:   "sign",
		Short: "Sign manifest JSON with an Ed25519 private key",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			gf := cmdutil.GetGlobalFlags(cmd)
			runner := &SignRunner{}
			return runner.Run(cmd.Context(), SignConfig{
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
