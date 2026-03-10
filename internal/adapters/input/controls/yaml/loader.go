// Package yaml provides YAML-based loading functionality for control definitions.
// It handles parsing and validation of control YAML files used in safety evaluations,
// using JSON Schema validation for contract enforcement.
package yaml

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	predicates "github.com/sufield/stave/internal/builtin/predicate"
	contractvalidator "github.com/sufield/stave/internal/contracts/validator"
	"github.com/sufield/stave/internal/domain/diag"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/policy"
	"github.com/sufield/stave/internal/platform/fsutil"
	"gopkg.in/yaml.v3"
)

// SchemaValidator validates raw control YAML against the contract schema.
type SchemaValidator interface {
	ValidateControlYAML(raw []byte, opts ...contractvalidator.Option) (*diag.Result, error)
}

// LoaderOption configures a ControlLoader.
type LoaderOption func(*ControlLoader)

// ControlLoader loads control definitions from YAML files.
type ControlLoader struct {
	validator SchemaValidator
	// OnProgress is called after each file is processed with (processed, total) counts.
	// It is optional and safe to leave nil.
	OnProgress func(processed, total int)
}

var _ appcontracts.ControlRepository = (*ControlLoader)(nil)

func (l *ControlLoader) ensureInit() {
	if l.validator == nil {
		l.validator = contractvalidator.New()
	}
}

// NewControlLoader creates a new YAML control loader.
func NewControlLoader(opts ...LoaderOption) (*ControlLoader, error) {
	l := &ControlLoader{}
	for _, opt := range opts {
		opt(l)
	}
	if l.validator == nil {
		l.validator = contractvalidator.New()
	}
	return l, nil
}

// SetOnProgress sets a callback that is called after each file is processed
// with (processed, total) counts. Pass nil to disable.
func (l *ControlLoader) SetOnProgress(fn func(processed, total int)) {
	l.OnProgress = fn
}

// LoadControls loads all YAML control definitions from the given directory,
// recursively traversing subdirectories. Directories prefixed with "_" are skipped.
// It supports an optional _registry/controls.index.json fast-path for large sets.
// Results are sorted by control ID for deterministic output.
func (l *ControlLoader) LoadControls(ctx context.Context, dir string) ([]policy.ControlDefinition, error) {
	l.ensureInit()

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	paths, err := resolveControlPaths(ctx, dir)
	if err != nil {
		return nil, err
	}

	controls := make([]policy.ControlDefinition, 0, len(paths))
	idSources := make(map[kernel.ControlID]string, len(paths))
	total := len(paths)
	for i, path := range paths {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		ctl, err := l.loadControl(path)
		if err != nil {
			return nil, fmt.Errorf("failed to load control %s: %w", path, err)
		}

		if existing, ok := idSources[ctl.ID]; ok {
			return nil, fmt.Errorf("duplicate control ID %q: found in %s and %s", ctl.ID, existing, path)
		}
		idSources[ctl.ID] = path
		controls = append(controls, ctl)

		if l.OnProgress != nil {
			l.OnProgress(i+1, total)
		}
	}

	// Sort by control ID for deterministic output
	slices.SortFunc(controls, func(a, b policy.ControlDefinition) int {
		return cmp.Compare(a.ID, b.ID)
	})

	return controls, nil
}

// loadControl loads a single control definition from a YAML file.
// It reads the file, validates against JSON Schema, and unmarshals into domain type.
func (l *ControlLoader) loadControl(path string) (policy.ControlDefinition, error) {
	data, err := fsutil.ReadFileLimited(path)
	if err != nil {
		return policy.ControlDefinition{}, err
	}

	// Validate against JSON Schema
	issues, err := l.validator.ValidateControlYAML(data, contractvalidator.WithPrefix(path))
	if err != nil {
		return policy.ControlDefinition{}, fmt.Errorf("schema validation error: %w", err)
	}
	if issues.HasErrors() || issues.HasWarnings() {
		return policy.ControlDefinition{}, fmt.Errorf("schema validation failed: %w", issues)
	}

	// Schema passed, unmarshal into domain type
	var ctl policy.ControlDefinition
	if err := yaml.Unmarshal(data, &ctl); err != nil {
		return policy.ControlDefinition{}, fmt.Errorf("failed to unmarshal control: %w", err)
	}
	if err := l.expandAndPrepare(&ctl); err != nil {
		return policy.ControlDefinition{}, fmt.Errorf("invalid control semantics: %w", err)
	}

	return ctl, nil
}

// expandAndPrepare resolves predicate aliases and prepares the control for use.
// Alias expansion lives in the adapter layer because moving it to the domain
// would create a circular dependency: policy → predicate → policy.
func (l *ControlLoader) expandAndPrepare(ctl *policy.ControlDefinition) error {
	alias := strings.TrimSpace(ctl.UnsafePredicateAlias)
	if alias != "" {
		if len(ctl.UnsafePredicate.Any) > 0 || len(ctl.UnsafePredicate.All) > 0 {
			return fmt.Errorf("unsafe_predicate_alias and unsafe_predicate cannot both be set")
		}
		expanded, ok := predicates.Resolve(alias)
		if !ok {
			return fmt.Errorf("unknown unsafe_predicate_alias %q (available: %s)", alias, strings.Join(predicates.ListAliases(), ", "))
		}
		ctl.UnsafePredicate = expanded
	}

	if err := ctl.Prepare(); err != nil {
		return err
	}

	return nil
}
