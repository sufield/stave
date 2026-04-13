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
func Commands(
	newObs compose.ObsRepoFactory,
	newSnapshot compose.SnapshotRepoFactory,
	loadAssets compose.AssetLoaderFunc,
	loadSnapshots compose.SnapshotLoader,
) []*cobra.Command {
	return []*cobra.Command{
		archive.NewCmd(newSnapshot),
		upcoming.NewCmd(loadAssets),
		snapshot.NewQualityCmd(loadSnapshots),
		snapshot.NewPlanCmd(newSnapshot),
		hygiene.NewStatusCmd(newObs, newSnapshot),
		hygiene.NewRiskCmd(loadAssets),
		manifest.NewCmd(),
	}
}

// DevCommands returns snapshot commands that are destructive and
// guarded by the production safety check.
func DevCommands(newSnapshot compose.SnapshotRepoFactory) []*cobra.Command {
	return []*cobra.Command{
		cleanup.NewCmd(newSnapshot),
	}
}
