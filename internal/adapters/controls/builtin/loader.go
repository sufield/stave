package builtin

import (
	"cmp"
	"embed"
	"fmt"
	"io/fs"
	"slices"
	"strings"
	"sync"

	controlyaml "github.com/sufield/stave/internal/adapters/controls/yaml"
	"github.com/sufield/stave/internal/controldata"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

// Registry manages the lifecycle and retrieval of embedded control definitions.
// It loads controls lazily on first access and returns cloned slices to prevent
// callers from mutating the shared cache.
type Registry struct {
	fsys          fs.FS
	root          string
	aliasResolver policy.AliasResolver

	mu    sync.RWMutex
	cache []policy.ControlDefinition
	err   error
	once  sync.Once
}

// NewRegistry creates a registry backed by the given filesystem.
// Pass any fs.FS (embed.FS, fstest.MapFS, os.DirFS) for testing flexibility.
func NewRegistry(fsys fs.FS, root string, opts ...RegistryOption) *Registry {
	r := &Registry{fsys: fsys, root: root}
	for _, o := range opts {
		o(r)
	}
	return r
}

// RegistryOption configures optional behavior for the builtin registry.
type RegistryOption func(*Registry)

// WithAliasResolver sets the predicate alias resolver used to expand
// unsafe_predicate_alias fields in embedded control definitions.
func WithAliasResolver(resolver policy.AliasResolver) RegistryOption {
	return func(r *Registry) { r.aliasResolver = resolver }
}

// All returns all control definitions. It performs a lazy load on the first
// call and returns a shallow clone of the cache for subsequent calls.
func (r *Registry) All() ([]policy.ControlDefinition, error) {
	r.once.Do(func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.cache, r.err = r.load()
	})

	if r.err != nil {
		return nil, r.err
	}

	r.mu.RLock()
	defer r.mu.RUnlock()
	return slices.Clone(r.cache), nil
}

// Filtered returns controls matching at least one selector.
func (r *Registry) Filtered(selectors []Selector) ([]policy.ControlDefinition, error) {
	all, err := r.All()
	if err != nil || len(selectors) == 0 {
		return all, err
	}
	return slices.DeleteFunc(all, func(ctl policy.ControlDefinition) bool {
		return !MatchesAny(ctl, selectors)
	}), nil
}

// --- Internal implementation ---

func (r *Registry) load() ([]policy.ControlDefinition, error) {
	var controls []policy.ControlDefinition
	idSources := make(map[kernel.ControlID]string)

	err := fs.WalkDir(r.fsys, r.root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !r.isYAML(path) {
			return nil
		}

		data, readErr := fs.ReadFile(r.fsys, path)
		if readErr != nil {
			return fmt.Errorf("reading %q: %w", path, readErr)
		}

		ctl, unmarshalErr := r.unmarshal(path, data)
		if unmarshalErr != nil {
			return unmarshalErr
		}

		if existing, ok := idSources[ctl.ID]; ok {
			return fmt.Errorf("duplicate control ID %q: found in %q and %q", ctl.ID, existing, path)
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

func (r *Registry) unmarshal(path string, data []byte) (policy.ControlDefinition, error) {
	ctl, err := controlyaml.UnmarshalControlDefinition(data)
	if err != nil {
		return policy.ControlDefinition{}, fmt.Errorf("parsing YAML in %q: %w", path, err)
	}
	if err := r.resolveAlias(&ctl); err != nil {
		return policy.ControlDefinition{}, fmt.Errorf("resolving alias in %q: %w", path, err)
	}
	if err := ctl.Prepare(); err != nil {
		return policy.ControlDefinition{}, fmt.Errorf("preparing %q: %w", path, err)
	}
	return ctl, nil
}

// resolveAlias expands unsafe_predicate_alias into unsafe_predicate.
func (r *Registry) resolveAlias(ctl *policy.ControlDefinition) error {
	alias := strings.TrimSpace(ctl.UnsafePredicateAlias)
	if alias == "" {
		return nil
	}
	if r.aliasResolver == nil {
		return fmt.Errorf("unsafe_predicate_alias %q requires an alias resolver", alias)
	}
	expanded, ok := r.aliasResolver(alias)
	if !ok {
		return fmt.Errorf("unknown unsafe_predicate_alias %q", alias)
	}
	ctl.UnsafePredicate = expanded
	return nil
}

func (r *Registry) isYAML(path string) bool {
	return strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml")
}

// EmbeddedFS exposes the bundled built-in control files for cross-package
// validation and strict integrity checks.
func EmbeddedFS() embed.FS {
	return controldata.FS
}
