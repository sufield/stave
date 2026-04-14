// Package prune implements snapshot intelligence commands: quality,
// upcoming, hygiene, and diff.
package prune

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/prune/hygiene"
	"github.com/sufield/stave/cmd/prune/snapshot"
	"github.com/sufield/stave/cmd/prune/upcoming"
)

// Commands returns the snapshot intelligence commands.
func Commands(
	newObs compose.ObsRepoFactory,
	newSnapshot compose.SnapshotRepoFactory,
	loadAssets compose.AssetLoaderFunc,
	loadSnapshots compose.SnapshotLoader,
) []*cobra.Command {
	return []*cobra.Command{
		upcoming.NewCmd(loadAssets),
		snapshot.NewQualityCmd(loadSnapshots),
		snapshot.NewPlanCmd(newSnapshot),
		hygiene.NewStatusCmd(newObs, newSnapshot),
		hygiene.NewRiskCmd(loadAssets),
	}
}

// DevCommands returns snapshot commands guarded by the production safety check.
func DevCommands(_ compose.SnapshotRepoFactory) []*cobra.Command {
	return nil
}
