package builtin

import (
	"cmp"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	controlyaml "github.com/sufield/stave/internal/adapters/controls/yaml"
	"github.com/sufield/stave/internal/contracts/validator"
	"github.com/sufield/stave/internal/controldata"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

// embeddedValidator is the JSON-schema validator used to defend
// against malformed embedded control YAML at startup. Built once
// via sync.OnceValue so the schema-compile cost is paid one time
// for the process lifetime — the embedded catalog is loaded eagerly
// at first access, so a per-control validator allocation would
// repeat the compile work for every file in the catalog.
var embeddedValidator = sync.OnceValue(validator.New)

// ControlStore manages the lifecycle and retrieval of embedded control definitions.
// It loads controls lazily on first access and returns cloned slices to prevent
// callers from mutating the shared cache.
type ControlStore struct {
	fsys          fs.FS
	root          string
	aliasResolver policy.AliasResolver

	// mu guards loaded / cache / err. Lazy init follows the
	// double-checked locking pattern from internal/adapters/cel/trace.go
	// — the previous sync.Once memoised transient load failures and
	// locked the registry into a permanent error state. The new shape
	// retries on each call until load succeeds, then takes the
	// read-locked fast path.
	mu     sync.RWMutex
	loaded bool
	cache  []policy.ControlDefinition
	err    error
}

// NewControlStore creates a registry backed by the given filesystem.
// Pass any fs.FS (embed.FS, fstest.MapFS, os.DirFS) for testing flexibility.
func NewControlStore(fsys fs.FS, root string, opts ...StoreOption) *ControlStore {
	r := &ControlStore{fsys: fsys, root: root}
	for _, o := range opts {
		o(r)
	}
	return r
}

// StoreOption configures optional behavior for the builtin registry.
type StoreOption func(*ControlStore)

// WithAliasResolver sets the predicate alias resolver used to expand
// unsafe_predicate_alias fields in embedded control definitions.
func WithAliasResolver(resolver policy.AliasResolver) StoreOption {
	return func(r *ControlStore) { r.aliasResolver = resolver }
}

// All returns all control definitions. It performs a lazy load on the first
// call and returns a shallow clone of the cache for subsequent calls.
//
// Concurrency: double-checked locking — RLock fast path returns the
// cached slice once `loaded` is true; a writer takes the full Lock,
// re-checks `loaded` (another goroutine may have raced ahead), and
// runs load() once. A transient load() failure clears `loaded`
// before returning so the next call retries instead of memoising
// the failure (the previous sync.Once shape locked the registry
// into a permanent error state on first-call init failure).
func (r *ControlStore) All() ([]policy.ControlDefinition, error) {
	r.mu.RLock()
	if r.loaded {
		clone := slices.Clone(r.cache)
		err := r.err
		r.mu.RUnlock()
		if err != nil {
			return nil, err
		}
		return clone, nil
	}
	r.mu.RUnlock()

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.loaded {
		// Another goroutine raced ahead and finished the load.
		if r.err != nil {
			return nil, r.err
		}
		return slices.Clone(r.cache), nil
	}
	cache, err := r.load()
	if err != nil {
		// Don't mark loaded on failure — let the next call retry
		// rather than pinning the failure for the process lifetime.
		r.err = err
		return nil, err
	}
	r.cache = cache
	r.err = nil
	r.loaded = true
	return slices.Clone(r.cache), nil
}

// Filtered returns controls matching at least one selector.
func (r *ControlStore) Filtered(selectors []Selector) ([]policy.ControlDefinition, error) {
	all, err := r.All()
	if err != nil || len(selectors) == 0 {
		return all, err
	}
	return slices.DeleteFunc(all, func(ctl policy.ControlDefinition) bool {
		return !MatchesAny(ctl, selectors)
	}), nil
}

// --- Internal implementation ---

func (r *ControlStore) load() ([]policy.ControlDefinition, error) {
	var controls []policy.ControlDefinition
	idSources := make(map[kernel.ControlID]string)

	err := fs.WalkDir(r.fsys, r.root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if path != r.root && (strings.HasPrefix(name, "_") || strings.HasPrefix(name, ".")) {
				return fs.SkipDir
			}
			return nil
		}
		if !r.isYAML(path) {
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

	// Triage data is optional. fs.Sub returns ErrNotExist when the
	// triage directory genuinely doesn't exist in the embedded
	// filesystem (a binary built without triage data is valid).
	// Other Sub errors (filesystem corruption, invalid path) should
	// surface — the earlier shape silently swallowed every Sub
	// failure under one branch, hiding real problems.
	triageSub, subErr := fs.Sub(r.fsys, filepath.Join(r.root, controlyaml.TriageDir))
	switch {
	case subErr == nil:
		triageIdx, triageErr := controlyaml.LoadTriageIndexFS(triageSub, ".")
		if triageErr != nil {
			return nil, fmt.Errorf("loading built-in triage: %w", triageErr)
		}
		if triageIdx != nil {
			controlyaml.ApplyTriage(controls, triageIdx)
		}
	case errors.Is(subErr, fs.ErrNotExist):
		// Optional directory not present — proceed without triage.
	default:
		return nil, fmt.Errorf("loading built-in triage subdirectory: %w", subErr)
	}

	return controls, nil
}

func (r *ControlStore) unmarshal(path string, data []byte) (policy.ControlDefinition, error) {
	// Schema-validate before unmarshal so a malformed embedded
	// control YAML (missing required field, wrong type) fails
	// loud at startup with a precise diagnostic rather than
	// loading with zero-value fields and producing confusing
	// downstream evaluation errors. The validator is shared
	// process-wide via embeddedValidator so the per-call cost is
	// just the validate step, not a fresh schema compile.
	issues, valErr := embeddedValidator().ValidateControlYAML(data, validator.WithPrefix(path))
	if valErr != nil {
		return policy.ControlDefinition{}, fmt.Errorf("validating YAML in %q: %w", path, valErr)
	}
	if issues.Failed() {
		return policy.ControlDefinition{}, fmt.Errorf("validating YAML in %q: %w", path, issues)
	}
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
func (r *ControlStore) resolveAlias(ctl *policy.ControlDefinition) error {
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

func (r *ControlStore) isYAML(path string) bool {
	return strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml")
}

// EmbeddedFS exposes the bundled built-in control files for cross-package
// validation and strict integrity checks.
func EmbeddedFS() embed.FS {
	return controldata.FS
}
