package initcmd

import (
	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/internal/metadata"
)

// NewGenerateCmd constructs the generate command tree.
func NewGenerateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:         "generate",
		Short:       "Generate starter artifacts",
		Long:        "Generate creates minimal deterministic templates for observations." + metadata.OfflineHelpSuffix,
		Args:        cobra.NoArgs,
		Annotations: map[string]string{cmdutil.AnnotationConfigOptional: "true"},
	}

	cmd.AddCommand(newGenerateObservationCmd())

	return cmd
}

func newGenerateObservationCmd() *cobra.Command {
	var req GenerateRequest

	cmd := &cobra.Command{
		Use:   "observation <name>",
		Short: "Generate an observation template",
		Long: `Generate observation creates an obs.v0.1 JSON template in observations/.

Exit Codes:
  0   - Success
  2   - Input error
  4   - Internal error` + metadata.OfflineHelpSuffix,
		Example: `  stave generate observation my-obs --out observations/snap.json`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			req.Name = args[0]
			gf := cliflags.GetGlobalFlags(cmd)
			runner := &GenerateRunner{
				Out:          cmd.OutOrStdout(),
				Force:        gf.Force,
				Quiet:        gf.Quiet,
				AllowSymlink: gf.AllowSymlinkOut,
			}
			return runner.RunObservation(req)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.Flags().StringVar(&req.Out, "out", "", "Output file path (default: observations/<name>.json)")

	return cmd
}
