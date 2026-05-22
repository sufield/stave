package stave

import (
	"context"
	"fmt"

	ctlbuiltin "github.com/sufield/stave/internal/adapters/controls/builtin"
	"github.com/sufield/stave/internal/adapters/observations"
	builtinpredicate "github.com/sufield/stave/internal/adapters/predicate"
	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
)

// builtinControls loads the embedded builtin control catalog with the
// alias resolver wired. Shared by the capability, search, and gaps
// accessors so the catalog is constructed one way everywhere.
func builtinControls() ([]policy.ControlDefinition, error) {
	store := ctlbuiltin.NewControlStore(
		ctlbuiltin.EmbeddedFS(),
		"embedded",
		ctlbuiltin.WithAliasResolver(builtinpredicate.ResolverFunc()),
	)
	controls, err := store.All()
	if err != nil {
		return nil, fmt.Errorf("load builtin controls: %w", err)
	}
	return controls, nil
}

// loadSnapshots loads every snapshot in dir via the observation
// loader. Errors if the directory holds no snapshots.
func loadSnapshots(ctx context.Context, dir string) ([]asset.Snapshot, error) {
	res, err := observations.NewObservationLoader().LoadSnapshots(ctx, dir)
	if err != nil {
		return nil, err
	}
	if len(res.Snapshots) == 0 {
		return nil, fmt.Errorf("no snapshots found in %s", dir)
	}
	return res.Snapshots, nil
}
