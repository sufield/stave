package prune

import (
	"github.com/spf13/cobra"

	archivecmd "github.com/sufield/stave/cmd/prune/archive"
	cleanupcmd "github.com/sufield/stave/cmd/prune/cleanup"
	hygienecmd "github.com/sufield/stave/cmd/prune/hygiene"
	snapshotcmd "github.com/sufield/stave/cmd/prune/snapshot"
	upcomingcmd "github.com/sufield/stave/cmd/prune/upcoming"
)

// Commands returns the aggregate list of snapshot lifecycle commands in this package.
func Commands() []*cobra.Command {
	return []*cobra.Command{
		cleanupcmd.NewCmd(),
		archivecmd.NewCmd(),
		upcomingcmd.Cmd,
		snapshotcmd.Quality,
		snapshotcmd.Plan,
		hygienecmd.Cmd,
	}
}
