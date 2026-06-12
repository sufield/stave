// Package export groups data export subcommands for external tool integration.
package export

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/export/compliance"
)

// NewCmd creates the export parent command with compliance and standards subcommands.
func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export controls and compliance evidence",
		Long: `Export Stave data to external formats.

Subcommands:
  compliance   Export compliance evidence package as JSON
  ocsf         Export findings as OCSF 1.1 events
  oscal        Export findings as OSCAL 1.1.2 documents
  changes      Export remediation property changes for external tooling`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.AddCommand(compliance.NewCmd())
	cmd.AddCommand(newOCSFCmd())
	cmd.AddCommand(newOSCALCmd())
	cmd.AddCommand(newChangesCmd())
	cmd.AddCommand(newTicketsCmd())

	return cmd
}
