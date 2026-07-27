package stave

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	ctlbuiltin "github.com/sufield/stave/internal/adapters/controls/builtin"
	ctlloader "github.com/sufield/stave/internal/adapters/controls/yaml"
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
		return nil, fmt.Errorf("load snapshots: %w", err)
	}
	if len(res.Snapshots) == 0 {
		return nil, fmt.Errorf("no snapshots found in %s", dir)
	}
	return res.Snapshots, nil
}

// LoadSnapshots loads every observation snapshot from dir. Returns
// an error if the directory holds no snapshots or cannot be read.
func LoadSnapshots(ctx context.Context, dir string) ([]asset.Snapshot, error) {
	return loadSnapshots(ctx, dir)
}

// LoadControlsFromDisk loads all control definitions from a root
// directory by walking its subdirectories. The alias resolver is wired
// automatically.
func LoadControlsFromDisk(rootDir string) ([]policy.ControlDefinition, error) {
	loader := ctlloader.NewControlLoader(ctlloader.WithAliasResolver(builtinpredicate.ResolverFunc()))
	var dirs []string
	err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() && path != rootDir {
			dirs = append(dirs, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk %s: %w", rootDir, err)
	}
	if len(dirs) == 0 {
		dirs = []string{rootDir}
	}

	var all []policy.ControlDefinition
	for _, d := range dirs {
		controls, loadErr := loader.LoadControls(context.Background(), d)
		if loadErr != nil {
			continue
		}
		all = append(all, controls...)
	}
	return all, nil
}
