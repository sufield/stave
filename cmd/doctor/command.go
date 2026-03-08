package doctor

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/metadata"
)

var doctorFormat string

var Cmd = &cobra.Command{
	Use:   "doctor",
	Short: "Check local environment readiness for Stave workflows",
	Long: `Doctor runs a quick local readiness check for first-time usage and day-to-day
developer workflows.

It validates local prerequisites and reports copy-paste fixes when something is
missing.

Examples:
  stave doctor
  stave doctor --format json` + metadata.OfflineHelpSuffix,
	Args:          cobra.NoArgs,
	RunE:          runDoctor,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	Cmd.Flags().StringVarP(&doctorFormat, "format", "f", "text", "Output format: text or json")
}
