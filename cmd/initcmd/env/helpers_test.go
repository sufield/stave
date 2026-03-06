package env

import (
	"github.com/spf13/cobra"
)

// getTestRootCmd builds a minimal root *cobra.Command with env subcommands
// for use in tests.
func getTestRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "stave",
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	root.PersistentFlags().String("output", "text", "Output format: json or text")
	root.PersistentFlags().Bool("quiet", false, "Suppress output")
	root.PersistentFlags().CountP("verbose", "v", "Increase verbosity")
	root.PersistentFlags().Bool("force", false, "Allow overwrite operations")
	root.PersistentFlags().Bool("allow-symlink-output", false, "Allow writing through symlinks")
	root.PersistentFlags().Bool("sanitize", false, "Sanitize identifiers")
	root.PersistentFlags().String("path-mode", "base", "Path rendering mode")
	root.PersistentFlags().String("log-file", "", "Log file path")
	root.PersistentFlags().Bool("require-offline", false, "Require offline execution")
	root.AddCommand(EnvCmd)
	return root
}
