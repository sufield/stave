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

// EmbeddedRegistry holds the lifecycle and retrieval logic for embedded control definitions.
type EmbeddedRegistry struct {
	fsys  fs.FS
	root  string
	cache []policy.ControlDefinition
	err   error
	once  sync.Once
}

// NewEmbeddedRegistry creates a registry backed by the given filesystem.
func NewEmbeddedRegistry(fsys fs.FS, root string) *EmbeddedRegistry {
	return &EmbeddedRegistry{fsys: fsys, root: root}
}

// defaultRegistry is the singleton used by the package-level API.
var defaultRegistry = NewEmbeddedRegistry(embeddedControls, "embedded")

// LoadAll loads all embedded control definitions.
func LoadAll(ctx context.Context) ([]policy.ControlDefinition, error) {
	return defaultRegistry.All(ctx)
}

// LoadFiltered loads embedded controls matching at least one selector.
// If selectors is empty, all controls are returned.
func LoadFiltered(ctx context.Context, selectors []BuiltinSelector) ([]policy.ControlDefinition, error) {
	return defaultRegistry.Filtered(ctx, selectors)
}

// All returns all control definitions, loading them on first call.
func (r *EmbeddedRegistry) All(_ context.Context) ([]policy.ControlDefinition, error) {
	r.once.Do(func() {
		r.cache, r.err = loadFromFS(r.fsys, r.root)
	})
	if r.err != nil {
		return nil, r.err
	}
	return slices.Clone(r.cache), nil
}

// Filtered returns controls matching at least one selector.
func (r *EmbeddedRegistry) Filtered(ctx context.Context, selectors []BuiltinSelector) ([]policy.ControlDefinition, error) {
	all, err := r.All(ctx)
	if err != nil || len(selectors) == 0 {
		return all, err
	}
	return slices.DeleteFunc(all, func(ctl policy.ControlDefinition) bool {
		return !MatchesAny(ctl, selectors)
	}), nil
}

// --- Internal Loading ---

func loadFromFS(fsys fs.FS, root string) ([]policy.ControlDefinition, error) {
	var controls []policy.ControlDefinition
	idSources := make(map[kernel.ControlID]string)

	err := fs.WalkDir(fsys, root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !isYAML(path) {
			return nil
		}

		data, readErr := fs.ReadFile(fsys, path)
		if readErr != nil {
			return fmt.Errorf("reading embedded control %q: %w", path, readErr)
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
		return nil, fmt.Errorf("loading built-in controls: %w", err)
	}

	slices.SortFunc(controls, func(a, b policy.ControlDefinition) int {
		return cmp.Compare(a.ID, b.ID)
	})

	return controls, nil
}

func unmarshalAndPrepareControl(path string, data []byte, idSources map[kernel.ControlID]string) (policy.ControlDefinition, error) {
	var ctl policy.ControlDefinition
	if err := yaml.Unmarshal(data, &ctl); err != nil {
		return policy.ControlDefinition{}, fmt.Errorf("parsing embedded control %q: %w", path, err)
	}
	if err := ctl.Prepare(); err != nil {
		return policy.ControlDefinition{}, fmt.Errorf("preparing embedded control %q: %w", path, err)
	}
	if existing, ok := idSources[ctl.ID]; ok {
		return policy.ControlDefinition{}, fmt.Errorf("duplicate embedded control ID %q: %q and %q", ctl.ID, existing, path)
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
