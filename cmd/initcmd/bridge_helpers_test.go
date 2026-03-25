package initcmd

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	initconfig "github.com/sufield/stave/cmd/initcmd/config"
	"github.com/sufield/stave/internal/cli/ui"
)

// GetRootCmd builds a minimal root *cobra.Command with initcmd subcommands
// attached. It is used by package-level tests that need to exercise commands
// via root.Execute() without importing the parent cmd package (which would
// create a circular dependency).
func GetRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "stave",
		SilenceErrors: true,
		SilenceUsage:  true,
	}

	p := root.PersistentFlags()
	p.Bool(cliflags.FlagQuiet, false, "Suppress output")
	p.CountP("verbose", "v", "Increase verbosity")
	p.Bool(cliflags.FlagForce, false, "Allow overwrite operations")
	p.Bool(cliflags.FlagSymlink, false, "Allow writing through symlinks")
	p.Bool(cliflags.FlagSanitize, false, "Sanitize identifiers")
	p.String(cliflags.FlagPathMode, "base", "Path rendering mode")
	p.String(cliflags.FlagLogFile, "", "Log file path")
	p.Bool(cliflags.FlagOffline, false, "Require offline execution")

	root.AddCommand(NewInitCmd())
	root.AddCommand(NewGenerateCmd())
	root.AddCommand(initconfig.NewConfigCmd(ui.DefaultRuntime()))

	return root
}
