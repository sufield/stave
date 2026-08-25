package catalog

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/pkg/stave"
)

func newInspectCmd() *cobra.Command {
	opts := &options{
		Format: "text",
	}
	cmd := &cobra.Command{
		Use:   "inspect <control-id>",
		Short: "Show full metadata for a single control",
		Long: `Inspect prints the complete metadata for one control: severity,
domain, scope, compliance mappings, applicable asset types, observation
fields, chains that reference it, and remediation guidance.

Inputs:
  <control-id>     The control ID to inspect (positional, required)
  --format F       text (default) | json
  --controls DIR   Control catalog directory (default: controls)
  --chains DIR     Chain catalog directory (default: chains)

Exit codes:
  0   Success
  2   Invalid input (unknown control ID)
  4   Internal error
`,
		Example: `  stave catalog inspect CTL.S3.PUBLIC.001
  stave catalog inspect CTL.IAM.ESCALATE.SSOOAUTH.001 --format json`,
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if opts.Format != "json" && opts.Format != "text" && opts.Format != "" {
				return &ui.UserError{Err: fmt.Errorf("--format must be text | json (got %q)", opts.Format)}
			}
			out, err := stave.RenderCatalogInspect(cmd.Context(), stave.CatalogInspectOptions{
				ControlID:   stave.ControlID(args[0]),
				ControlsDir: opts.ControlsDir,
				ChainsDir:   opts.ChainsDir,
				Format:      opts.Format,
			})
			if err != nil {
				if errors.Is(err, stave.ErrInvalidInput) {
					return &ui.UserError{Err: err}
				}
				return err //nolint:wrapcheck // facade already wrapped; preserve exit 4.
			}
			_, err = cmd.OutOrStdout().Write(out)
			return err
		},
	}
	cmd.Flags().StringVarP(&opts.Format, "format", "f", "text", "output format: text | json")
	cmd.Flags().StringVarP(&opts.ControlsDir, "controls", "i", "", "control catalog directory (default: embedded catalog)")
	cmd.Flags().StringVar(&opts.ChainsDir, "chains", "", "chain catalog directory (default: embedded chains)")
	return cmd
}
