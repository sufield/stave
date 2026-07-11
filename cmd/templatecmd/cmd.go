package templatecmd

import (
	"github.com/spf13/cobra"
)

// NewCmd constructs the template parent command.
func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "template",
		Short: "Manage assessment templates",
		Long: `Assessment templates are JTBD bundles that package everything
needed to run a specific security assessment job: control selection,
chain configuration, parameters, and fixture-based verification.

Subcommands:
  init     Instantiate a template with parameters
  verify   Run fixture-based semantic verification
  eject    Fork a template for local customization`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	return cmd
}
