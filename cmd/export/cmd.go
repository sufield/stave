// Package export groups data export subcommands for external tool integration.
package export

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/export/compliance"
)

// NewCmd creates the export parent command with rego and compliance subcommands.
func NewCmd(newCtlRepo compose.CtlRepoFactory, newCELEvaluator compose.CELEvaluatorFactory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export controls and compliance evidence",
		Long: `Export Stave data to external formats.

Subcommands:
  rego         Export controls to OPA Rego policy rules
  compliance   Export compliance evidence package as JSON`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.AddCommand(newRegoCmd(newCtlRepo))
	cmd.AddCommand(compliance.NewCmd(newCtlRepo, newCELEvaluator))
	cmd.AddCommand(newOCSFCmd())
	cmd.AddCommand(newOSCALCmd())

	return cmd
}
