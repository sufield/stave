// Package prune implements snapshot lifecycle commands: archive, prune, plan,
// quality, upcoming, hygiene, manifest, and diff.
package prune

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/prune/archive"
	"github.com/sufield/stave/cmd/prune/cleanup"
	"github.com/sufield/stave/cmd/prune/hygiene"
	"github.com/sufield/stave/cmd/prune/manifest"
	"github.com/sufield/stave/cmd/prune/snapshot"
	"github.com/sufield/stave/cmd/prune/upcoming"
)

// Commands returns the snapshot lifecycle commands.
func Commands(p *compose.Provider) []*cobra.Command {
	return []*cobra.Command{
		archive.NewCmd(p.NewSnapshotRepo),
		upcoming.NewCmd(p.LoadAssets),
		snapshot.NewQualityCmd(p.LoadSnapshots),
		snapshot.NewPlanCmd(p.NewSnapshotRepo),
		hygiene.NewCmd(p.LoadAssets, p.NewObservationRepo, p.NewSnapshotRepo),
		manifest.NewCmd(),
	}
}

// DevCommands returns snapshot commands that are destructive and
// guarded by the production safety check.
func DevCommands(p *compose.Provider) []*cobra.Command {
	return []*cobra.Command{
		cleanup.NewCmd(p.NewSnapshotRepo),
	}
}
