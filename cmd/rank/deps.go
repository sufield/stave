package rank

import "github.com/sufield/stave/cmd/cmdutil/compose"

// Deps holds the adapter factories required by the rank command.
// Constructed at registration time in cmd/commands.go.
type Deps struct {
	NewSnapshotBundleLoader compose.SnapshotBundleLoaderFactory
}
