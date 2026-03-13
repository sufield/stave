package diagnose

import (
	"github.com/spf13/cobra"
)

// GetRootCmd builds a minimal root command with diagnose subcommands attached.
// Used by package-level tests that exercise commands via root.Execute()
// without importing the parent cmd package (circular dependency).
func GetRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "stave",
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	root.PersistentFlags().String("output", "text", "Output format")
	root.PersistentFlags().Bool("quiet", false, "Suppress output")
	root.PersistentFlags().CountP("verbose", "v", "Increase verbosity")
	root.PersistentFlags().Bool("force", false, "Allow overwrite")
	root.PersistentFlags().Bool("sanitize", false, "Sanitize identifiers")
	root.PersistentFlags().String("path-mode", "base", "Path rendering mode")
	root.PersistentFlags().String("log-file", "", "Log file path")

	root.AddCommand(NewDiagnoseCmd())
	root.AddCommand(NewExplainCmd())

	return root
}
