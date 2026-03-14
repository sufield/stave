package prune

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/prune/archive"
	"github.com/sufield/stave/cmd/prune/cleanup"
	"github.com/sufield/stave/cmd/prune/hygiene"
	"github.com/sufield/stave/cmd/prune/manifest"
	"github.com/sufield/stave/cmd/prune/snapshot"
	"github.com/sufield/stave/cmd/prune/upcoming"
)

// Commands returns the snapshot lifecycle commands in this package.
func Commands() []*cobra.Command {
	return []*cobra.Command{
		cleanup.NewCmd(),
		archive.NewCmd(),
		upcoming.NewCmd(),
		snapshot.NewQualityCmd(),
		snapshot.NewPlanCmd(),
		hygiene.NewCmd(),
		manifest.NewCmd(),
	}
}
