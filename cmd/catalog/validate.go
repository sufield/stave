package catalog

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/pkg/stave"
)

func newValidateCmd() *cobra.Command {
	opts := &options{
		Format:      "text",
		ControlsDir: "controls",
		ChainsDir:   "chains",
	}
	var semantic, strict bool
	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate the entire control and chain catalog",
		Long: `Validate runs combined structural checks across the control and
chain catalog in a single pass:

  1. Control lint   — schema, CEL syntax, completeness (forge lint)
  2. Chain lint     — structure, member controls, capabilities
  3. Cross-reference — chain ControlIDs exist in the loaded catalog
  4. Duplicate detection — no two chains share the same ID

With --semantic, control lint includes always-firing and impossible
condition checks. With --strict, warnings are treated as errors.

Inputs:
  --controls DIR   Control catalog directory (default: controls)
  --chains DIR     Chain catalog directory (default: chains)
  --format F       text (default) | json
  --semantic       Enable semantic analysis on controls
  --strict         Treat warnings as errors

Exit codes:
  0   No errors
  2   Invalid input (bad flags)
  3   Validation errors found
  4   Internal error
`,
		Example: `  stave catalog validate
  stave catalog validate --semantic --strict
  stave catalog validate --format json | jq '.total_errors'
  stave catalog validate --controls controls/s3`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			renderer, fmtErr := newValidateRenderer(opts.Format)
			if fmtErr != nil {
				return &ui.UserError{Err: fmtErr}
			}
			result, err := stave.CatalogValidate(cmd.Context(), stave.CatalogValidateOptions{
				ControlsDir: opts.ControlsDir,
				ChainsDir:   opts.ChainsDir,
				Semantic:    semantic,
				Strict:      strict,
			})
			if err != nil {
				return err //nolint:wrapcheck // facade already wrapped; preserve exit 4.
			}
			if renderErr := renderer.Render(cmd.OutOrStdout(), result); renderErr != nil {
				return fmt.Errorf("render validate output: %w", renderErr)
			}
			if result.TotalErrors > 0 {
				return fmt.Errorf("%d catalog validation error(s): %w",
					result.TotalErrors, ui.ErrViolationsFound)
			}
			if strict && result.TotalWarnings > 0 {
				return fmt.Errorf("%d catalog validation warning(s) (--strict): %w",
					result.TotalWarnings, ui.ErrViolationsFound)
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&opts.Format, "format", "f", "text", "output format: text | json")
	cmd.Flags().StringVarP(&opts.ControlsDir, "controls", "i", "controls", "control catalog directory")
	cmd.Flags().StringVar(&opts.ChainsDir, "chains", "chains", "chain catalog directory")
	cmd.Flags().BoolVar(&semantic, "semantic", false, "enable semantic analysis on controls")
	cmd.Flags().BoolVar(&strict, "strict", false, "treat warnings as errors")
	return cmd
}
