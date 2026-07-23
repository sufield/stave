package forge

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/pkg/stave"
)

func newLintCmd() *cobra.Command {
	var controlPath, format string
	var semantic, strict bool

	cmd := &cobra.Command{
		Use:   "lint",
		Short: "Static analysis for control YAML files",
		Long: `Validate control YAML files for schema correctness, CEL predicate
syntax, and completeness. With --semantic, performs additional
checks for always-firing predicates and impossible conditions.

Exit Codes:
  0   No errors, no warnings
  1   Warnings only (errors with --strict)
  2   Errors present
  4   Internal error`,
		Example: `  stave forge lint --control controls/ad/CTL.AD.PASS.MINLEN.001.yaml
  stave forge lint --control controls/ --semantic --strict
  stave forge lint --control controls/ --format json`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out, err := stave.ForgeLintWithFormat(controlPath, semantic, strict, format)
			if _, werr := cmd.OutOrStdout().Write(out); werr != nil && err == nil {
				return fmt.Errorf("write lint output: %w", werr)
			}
			return err //nolint:wrapcheck // facade already wrapped; preserve exit codes.
		},
	}

	cmd.Flags().StringVar(&controlPath, "control", "", "control YAML file or directory (required)")
	cmd.Flags().BoolVar(&semantic, "semantic", false, "enable semantic analysis (always-firing, never-firing)")
	cmd.Flags().BoolVar(&strict, "strict", false, "treat warnings as errors")
	cmd.Flags().StringVarP(&format, "format", "f", "text", "output format: text | json")
	_ = cmd.MarkFlagRequired("control")

	return cmd
}
