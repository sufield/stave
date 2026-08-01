package catalog

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/pkg/stave"
)

func newMatrixCmd() *cobra.Command {
	opts := &options{
		Format: "text",
	}
	cmd := &cobra.Command{
		Use:   "matrix",
		Short: "Show taxonomy × service cross-product with gap cells",
		Long: `Matrix builds the taxonomy × service cross-product from the control
catalog. Each row is a taxonomy category; columns show how many services
and controls use that category. Gap cells highlight services where a
widely-used category has zero controls.

Inputs:
  --format F       text (default) | json
  --controls DIR   Control catalog directory (default: controls)

Output:
  Summary table: CATEGORY | SERVICES | CONTROLS
  Gap cells: (category, service) pairs missing coverage

Exit codes:
  0   Success
  4   Internal error
`,
		Example: `  stave catalog matrix
  stave catalog matrix --format json | jq '.gaps'`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if opts.Format != "json" && opts.Format != "text" && opts.Format != "" {
				return &ui.UserError{Err: fmt.Errorf("--format must be text | json (got %q)", opts.Format)}
			}
			out, err := stave.RenderMatrix(cmd.Context(), stave.MatrixOptions{
				ControlsDir: opts.ControlsDir,
				Format:      opts.Format,
			})
			if err != nil {
				return err //nolint:wrapcheck // facade already wrapped; preserve exit 4.
			}
			_, err = cmd.OutOrStdout().Write(out)
			return err
		},
	}
	cmd.Flags().StringVarP(&opts.Format, "format", "f", "text", "output format: text | json")
	cmd.Flags().StringVarP(&opts.ControlsDir, "controls", "i", "", "control catalog directory (default: embedded catalog)")
	return cmd
}
