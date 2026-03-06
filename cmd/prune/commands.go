package prune

import (
	"github.com/spf13/cobra"

	archivecmd "github.com/sufield/stave/cmd/prune/archive"
	cleanupcmd "github.com/sufield/stave/cmd/prune/cleanup"
	hygienecmd "github.com/sufield/stave/cmd/prune/hygiene"
	snapshotcmd "github.com/sufield/stave/cmd/prune/snapshot"
	upcomingcmd "github.com/sufield/stave/cmd/prune/upcoming"
)

// Commands is the aggregate list of snapshot lifecycle commands in this package.
var Commands = []*cobra.Command{
	cleanupcmd.Cmd,
	archivecmd.Cmd,
	upcomingcmd.Cmd,
	snapshotcmd.Quality,
	snapshotcmd.Plan,
	hygienecmd.Cmd,
}
