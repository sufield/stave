package doctor

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/metadata"
)

// NewCmd constructs the doctor command with closure-scoped flags.
func NewCmd() *cobra.Command {
	var format string

	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Check local environment readiness for Stave workflows",
		Long: `Doctor runs a quick local readiness check for first-time usage and day-to-day
developer workflows.

It validates local prerequisites and reports copy-paste fixes when something is
missing.

Examples:
  stave doctor
  stave doctor --format json` + metadata.OfflineHelpSuffix,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runDoctor(cmd, format)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.Flags().StringVarP(&format, "format", "f", "text", "Output format: text or json")

	return cmd
}
