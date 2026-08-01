package catalog

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/pkg/stave"
)

func newGapsCmd() *cobra.Command {
	opts := &options{
		Format: "text",
	}
	var strict bool
	cmd := &cobra.Command{
		Use:   "gaps <checklist-file>",
		Short: "Compare catalog against an external checklist",
		Long: `Gaps loads an external YAML checklist and reports which items
have matching controls in the catalog (COVERED) and which do not
(UNCOVERED). Ambiguous matches (multiple controls match) are marked
with "?".

Checklist format:
  checks:
    - id: iam-mfa-root
      service: IAM
      description: "Root account has MFA enabled"
      reference: "CIS 1.5"

Matching logic: same service + keyword overlap on description.
Use --strict for exact control-ID matching only.

Inputs:
  <checklist-file>   Path to the YAML checklist (positional, required)
  --format F         text (default) | json
  --strict           Exact ID match only, no fuzzy matching
  --controls DIR     Control catalog directory (default: controls)

Exit codes:
  0   Success
  2   Invalid input (bad checklist file)
  4   Internal error
`,
		Example: `  stave catalog gaps checklist.yaml
  stave catalog gaps cis-benchmark.yaml --strict
  stave catalog gaps prowler-checks.yaml --format json`,
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if opts.Format != "json" && opts.Format != "text" && opts.Format != "" {
				return &ui.UserError{Err: fmt.Errorf("--format must be text | json (got %q)", opts.Format)}
			}
			out, err := stave.RenderCatalogGaps(cmd.Context(), stave.CatalogGapsOptions{
				ChecklistPath: args[0],
				ControlsDir:   opts.ControlsDir,
				Format:        opts.Format,
				Strict:        strict,
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
	cmd.Flags().BoolVar(&strict, "strict", false, "exact control-ID match only, no fuzzy matching")
	return cmd
}
