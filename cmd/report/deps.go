package report

import (
	"fmt"

	"github.com/sufield/stave/cmd/cmdutil/compose"
)

// Deps holds the adapter factories the report command depends on.
// Constructed at registration time in cmd/commands.go.
type Deps struct {
	NewChainLoader          compose.ChainLoaderFactory
	NewSLALoader            compose.SLALoaderFactory
	NewArtifactLoader       compose.ArtifactLoaderFactory
	NewSnapshotBundleLoader compose.SnapshotBundleLoaderFactory
	NewCtlRepo              compose.CtlRepoFactory
}

// Validate checks that all required factory fields are non-nil.
func (d Deps) Validate() error {
	var missing []string
	if d.NewChainLoader == nil {
		missing = append(missing, "NewChainLoader")
	}
	if d.NewSLALoader == nil {
		missing = append(missing, "NewSLALoader")
	}
	if d.NewArtifactLoader == nil {
		missing = append(missing, "NewArtifactLoader")
	}
	if d.NewSnapshotBundleLoader == nil {
		missing = append(missing, "NewSnapshotBundleLoader")
	}
	if d.NewCtlRepo == nil {
		missing = append(missing, "NewCtlRepo")
	}
	if len(missing) > 0 {
		return fmt.Errorf("report.Deps: nil factory fields: %v", missing)
	}
	return nil
}
