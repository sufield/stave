// Package export groups data export subcommands for external tool integration.
package export

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/export/compliance"
	exportinvariants "github.com/sufield/stave/cmd/exportinvariants"
	exportsir "github.com/sufield/stave/cmd/exportsir"
)

// NewCmd creates the export parent command with compliance and standards subcommands.
func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export controls and compliance evidence",
		Long: `Export Stave data to external formats.

Subcommands:
  sir          Export the Stave Intermediate Representation as JSON
  compliance   Export compliance evidence package as JSON
  controls     Export the control catalog for external solver consumption
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

	sirCmd := exportsir.NewCmd()
	sirCmd.Use = "sir"
	cmd.AddCommand(sirCmd)

	controlsExportCmd := exportinvariants.NewCmd()
	controlsExportCmd.Use = "controls"
	cmd.AddCommand(controlsExportCmd)

	return cmd
}
