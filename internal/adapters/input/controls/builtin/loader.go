package builtin

import (
	"cmp"
	"context"
	"embed"
	"fmt"
	"io/fs"
	"slices"
	"strings"
	"sync"

	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/policy"
	"gopkg.in/yaml.v3"
)

//go:embed embedded/s3/**/*.yaml
var embeddedControls embed.FS

var (
	cache     []policy.ControlDefinition
	cacheErr  error
	cacheOnce sync.Once
)

// LoadAll loads all embedded control definitions.
func LoadAll(_ context.Context) ([]policy.ControlDefinition, error) {
	cacheOnce.Do(func() {
		cache, cacheErr = loadFromFS(embeddedControls, "embedded")
	})
	return slices.Clone(cache), cacheErr
}

// LoadFiltered loads embedded controls matching at least one selector.
// If selectors is empty, all controls are returned.
func LoadFiltered(ctx context.Context, selectors []BuiltinSelector) ([]policy.ControlDefinition, error) {
	all, err := LoadAll(ctx)
	if err != nil || len(selectors) == 0 {
		return all, err
	}
	return slices.DeleteFunc(all, func(ctl policy.ControlDefinition) bool {
		return !MatchesAny(ctl, selectors)
	}), nil
}

func loadFromFS(fsys fs.FS, root string) ([]policy.ControlDefinition, error) {
	var controls []policy.ControlDefinition
	idSources := make(map[kernel.ControlID]string)

	err := fs.WalkDir(fsys, root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !isYAML(path) {
			return nil
		}

		data, readErr := fs.ReadFile(fsys, path)
		if readErr != nil {
			return fmt.Errorf("read embedded control %s: %w", path, readErr)
		}

		ctl, unmarshalErr := unmarshalAndPrepareControl(path, data, idSources)
		if unmarshalErr != nil {
			return unmarshalErr
		}
		idSources[ctl.ID] = path
		controls = append(controls, ctl)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk embedded controls: %w", err)
	}

	slices.SortFunc(controls, func(a, b policy.ControlDefinition) int {
		return cmp.Compare(a.ID, b.ID)
	})

	return controls, nil
}

func unmarshalAndPrepareControl(path string, data []byte, idSources map[kernel.ControlID]string) (policy.ControlDefinition, error) {
	var ctl policy.ControlDefinition
	if err := yaml.Unmarshal(data, &ctl); err != nil {
		return policy.ControlDefinition{}, fmt.Errorf("parse embedded control %s: %w", path, err)
	}
	if err := ctl.Prepare(); err != nil {
		return policy.ControlDefinition{}, fmt.Errorf("prepare embedded control %s: %w", path, err)
	}
	if existing, ok := idSources[ctl.ID]; ok {
		return policy.ControlDefinition{}, fmt.Errorf("duplicate embedded control ID %q: %s and %s", ctl.ID, existing, path)
	}
	return ctl, nil
}

func isYAML(path string) bool {
	return strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml")
}

// EmbeddedFS exposes the bundled built-in control files for cross-package validation tests.
func EmbeddedFS() embed.FS {
	return embeddedControls
}
