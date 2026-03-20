package prune

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/prune/cleanup"
)

// DevCommands returns snapshot commands that are too destructive for production.
func DevCommands(p *compose.Provider) []*cobra.Command {
	return []*cobra.Command{
		cleanup.NewCmd(p),
	}
}
