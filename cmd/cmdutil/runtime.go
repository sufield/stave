package cmdutil

import (
	"github.com/spf13/cobra"
	"github.com/sufield/stave/internal/cli/ui"
)

// NewRuntime creates a ui.Runtime wired to the command's output streams
// with Quiet resolved from the --quiet flag.
func NewRuntime(cmd *cobra.Command) *ui.Runtime {
	rt := ui.NewRuntime(cmd.OutOrStdout(), cmd.ErrOrStderr())
	rt.Quiet = QuietEnabled(cmd)
	return rt
}
