package prune

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/prune/archive"
	"github.com/sufield/stave/cmd/prune/hygiene"
	"github.com/sufield/stave/cmd/prune/manifest"
	"github.com/sufield/stave/cmd/prune/snapshot"
	"github.com/sufield/stave/cmd/prune/upcoming"
)

// Commands returns the production snapshot lifecycle commands.
// Prune is excluded — it permanently deletes evidence and belongs in the dev binary.
func Commands(p *compose.Provider) []*cobra.Command {
	return []*cobra.Command{
		archive.NewCmd(p),
		upcoming.NewCmd(p),
		snapshot.NewQualityCmd(p),
		snapshot.NewPlanCmd(p),
		hygiene.NewCmd(p),
		manifest.NewCmd(),
	}
}
