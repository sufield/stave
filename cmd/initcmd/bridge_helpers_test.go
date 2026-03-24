package initcmd

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
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
	p.Bool(cmdutil.FlagQuiet, false, "Suppress output")
	p.CountP("verbose", "v", "Increase verbosity")
	p.Bool(cmdutil.FlagForce, false, "Allow overwrite operations")
	p.Bool(cmdutil.FlagSymlink, false, "Allow writing through symlinks")
	p.Bool(cmdutil.FlagSanitize, false, "Sanitize identifiers")
	p.String(cmdutil.FlagPathMode, "base", "Path rendering mode")
	p.String(cmdutil.FlagLogFile, "", "Log file path")
	p.Bool(cmdutil.FlagOffline, false, "Require offline execution")

	root.AddCommand(NewInitCmd())
	root.AddCommand(NewGenerateCmd())
	root.AddCommand(initconfig.NewConfigCmd(ui.DefaultRuntime()))

	return root
}
