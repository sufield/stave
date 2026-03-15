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

// Commands returns the production snapshot lifecycle commands.
// Prune is excluded — it permanently deletes evidence and belongs in the dev binary.
func Commands() []*cobra.Command {
	return []*cobra.Command{
		archive.NewCmd(),
		upcoming.NewCmd(),
		snapshot.NewQualityCmd(),
		snapshot.NewPlanCmd(),
		hygiene.NewCmd(),
		manifest.NewCmd(),
	}
}

// DevCommands returns snapshot commands that are too destructive for production.
func DevCommands() []*cobra.Command {
	return []*cobra.Command{
		cleanup.NewCmd(),
	}
}
