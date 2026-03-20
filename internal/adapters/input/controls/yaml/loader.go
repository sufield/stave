// Package yaml provides YAML-based loading functionality for control definitions.
// It handles parsing and validation of control YAML files used in safety evaluations,
// using JSON Schema validation for contract enforcement.
package yaml

import (
	"cmp"
	"context"
	"fmt"
	"slices"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	contractvalidator "github.com/sufield/stave/internal/contracts/validator"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/pkg/alpha/domain/diag"
	"github.com/sufield/stave/pkg/alpha/domain/kernel"
	"github.com/sufield/stave/pkg/alpha/domain/policy"
	"gopkg.in/yaml.v3"
)

// SchemaValidator validates raw control YAML against the contract schema.
type SchemaValidator interface {
	ValidateControlYAML(raw []byte, opts ...contractvalidator.Option) (*diag.Result, error)
}

// ControlLoader loads control definitions from YAML files.
type ControlLoader struct {
	validator     SchemaValidator
	aliasResolver policy.AliasResolver
	onProgress    func(processed, total int)
}

// Ensure ControlLoader satisfies the ControlRepository interface at compile time.
var _ appcontracts.ControlRepository = (*ControlLoader)(nil)

// LoaderOption configures a ControlLoader.
type LoaderOption func(*ControlLoader)

// WithAliasResolver sets the predicate alias resolver used during control loading.
func WithAliasResolver(r policy.AliasResolver) LoaderOption {
	return func(l *ControlLoader) { l.aliasResolver = r }
}

// NewControlLoader creates a new YAML control loader.
// It initializes with a default validator unless overridden by options.
// The returned loader is ready to use immediately — no lazy initialization.
func NewControlLoader(opts ...LoaderOption) (*ControlLoader, error) {
	l := &ControlLoader{
		validator: contractvalidator.New(),
	}
	for _, opt := range opts {
		opt(l)
	}
	return l, nil
}

// SetOnProgress sets a callback that is called after each file is processed
// with (processed, total) counts. Pass nil to disable.
func (l *ControlLoader) SetOnProgress(fn func(processed, total int)) {
	l.onProgress = fn
}

// LoadControls loads all YAML control definitions from the given directory,
// recursively traversing subdirectories. Directories prefixed with "_" are skipped.
// It supports an optional _registry/controls.index.json fast-path for large sets.
// Results are sorted by control ID for deterministic output.
func (l *ControlLoader) LoadControls(ctx context.Context, dir string) ([]policy.ControlDefinition, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	paths, err := resolveControlPaths(ctx, dir)
	if err != nil {
		return nil, fmt.Errorf("resolving control paths in %q: %w", dir, err)
	}

	total := len(paths)
	controls := make([]policy.ControlDefinition, 0, total)
	idSources := make(map[kernel.ControlID]string, total)

	for i, path := range paths {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		ctl, err := l.loadOne(path)
		if err != nil {
			return nil, fmt.Errorf("control %q: %w", path, err)
		}

		if existing, ok := idSources[ctl.ID]; ok {
			return nil, fmt.Errorf("duplicate control ID %q found in %q and %q", ctl.ID, existing, path)
		}
		idSources[ctl.ID] = path
		controls = append(controls, ctl)

		if l.onProgress != nil {
			l.onProgress(i+1, total)
		}
	}

	slices.SortFunc(controls, func(a, b policy.ControlDefinition) int {
		return cmp.Compare(a.ID, b.ID)
	})

	return controls, nil
}

// loadOne performs IO, schema validation, unmarshal, and semantic enrichment
// for a single control file.
func (l *ControlLoader) loadOne(path string) (policy.ControlDefinition, error) {
	data, err := fsutil.ReadFileLimited(path)
	if err != nil {
		return policy.ControlDefinition{}, err
	}

	issues, err := l.validator.ValidateControlYAML(data, contractvalidator.WithPrefix(path))
	if err != nil {
		return policy.ControlDefinition{}, fmt.Errorf("schema validation error: %w", err)
	}
	if issues.HasErrors() || issues.HasWarnings() {
		return policy.ControlDefinition{}, fmt.Errorf("%w: %w", contractvalidator.ErrSchemaValidationFailed, issues)
	}

	var dto yamlControlDefinition
	if err := yaml.Unmarshal(data, &dto); err != nil {
		return policy.ControlDefinition{}, fmt.Errorf("yaml parse error: %w", err)
	}
	ctl := controlDefinitionToDomain(dto)

	if err := l.enrichAndPrepare(&ctl); err != nil {
		return policy.ControlDefinition{}, err
	}

	return ctl, nil
}

// enrichAndPrepare resolves predicate aliases and prepares the control for use.
func (l *ControlLoader) enrichAndPrepare(ctl *policy.ControlDefinition) error {
	if err := ctl.ResolveAndPrepare(l.aliasResolver); err != nil {
		return fmt.Errorf("semantic error: %w", err)
	}
	return nil
}
