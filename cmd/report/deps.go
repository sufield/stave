package report

import "github.com/sufield/stave/cmd/cmdutil/compose"

// Deps holds the adapter factories the report command depends on.
// Constructed at registration time in cmd/commands.go.
type Deps struct {
	NewChainLoader          compose.ChainLoaderFactory
	NewSLALoader            compose.SLALoaderFactory
	NewArtifactLoader       compose.ArtifactLoaderFactory
	NewSnapshotBundleLoader compose.SnapshotBundleLoaderFactory
	NewCtlRepo              compose.CtlRepoFactory
}
