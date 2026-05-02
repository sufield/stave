// Package yaml provides YAML-based loading functionality for control definitions.
// It handles parsing and validation of control YAML files used in safety evaluations,
// using JSON Schema validation for contract enforcement.
package yaml

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/archetype"
	contractvalidator "github.com/sufield/stave/internal/contracts/validator"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/diag"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// ControlLoader loads control definitions from YAML files.
type ControlLoader struct {
	validator     contractvalidator.ControlYAMLValidator
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
//
// The signature does not return an error: contractvalidator.New() and
// every existing LoaderOption are total, so no failure mode exists.
// The earlier shape returned (*ControlLoader, error) anyway and every
// caller checked for an error that never fired. Reduced to the
// natural signature so call sites are simpler. If a future option
// needs to fail at construction, return an error from that option
// itself and surface it from a constructor variant.
func NewControlLoader(opts ...LoaderOption) *ControlLoader {
	l := &ControlLoader{
		validator: contractvalidator.New(),
	}
	for _, opt := range opts {
		opt(l)
	}
	return l
}

// LoadControls loads all YAML control definitions from the given directory,
// recursively traversing subdirectories. Directories prefixed with "_" are skipped.
// It supports an optional _registry/controls.index.json fast-path for large sets.
// Results are sorted by control ID for deterministic output.
func (l *ControlLoader) LoadControls(ctx context.Context, dir string) ([]policy.ControlDefinition, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Empty dir means the caller forgot to set --controls or
	// passed through a zero string. resolveControlPaths would
	// scan cwd and return whatever YAML happened to be sitting
	// there — a silent surprise that produced phantom controls
	// without a clear cause. Reject up-front.
	if strings.TrimSpace(dir) == "" {
		return nil, fmt.Errorf("controls/yaml.LoadControls: dir is empty (set --controls or pass an explicit path)")
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

	triageIdx, triageErr := LoadTriageIndex(dir)
	if triageErr != nil {
		return nil, fmt.Errorf("loading triage from %q: %w", dir, triageErr)
	}
	if triageIdx != nil {
		ApplyTriage(controls, triageIdx)
	}

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
	if issues.Failed() || issues.HasWarnings() {
		return policy.ControlDefinition{}, fmt.Errorf("%w: %w", contractvalidator.ErrSchemaValidationFailed, issues)
	}

	ctl, unmarshalErr := UnmarshalControlDefinition(data)
	if unmarshalErr != nil {
		return policy.ControlDefinition{}, fmt.Errorf("yaml parse error: %w", unmarshalErr)
	}

	if err := l.enrichAndPrepare(&ctl); err != nil {
		return policy.ControlDefinition{}, err
	}

	return ctl, nil
}

// enrichAndPrepare resolves predicate aliases, prepares the control, and
// validates it. Validation runs at load time so user-authored controls
// fail fast with clear errors instead of silently producing wrong results.
//
// Errors abort the load with a descriptive message; SeverityWarning
// issues are emitted via slog at warn level so operators can see
// non-fatal problems (e.g. a deprecated field, a control marked for
// removal) without losing the affected control. The earlier shape
// dropped warning-level issues silently, which left authoring
// problems invisible until they escalated.
func (l *ControlLoader) enrichAndPrepare(ctl *policy.ControlDefinition) error {
	if err := l.resolveAlias(ctl); err != nil {
		return fmt.Errorf("semantic error: %w", err)
	}
	if err := validateArchetype(ctl); err != nil {
		return err
	}
	if err := ctl.Prepare(); err != nil {
		return fmt.Errorf("semantic error: %w", err)
	}
	if issues := ctl.Validate(); len(issues) > 0 {
		for _, issue := range issues {
			switch issue.Severity {
			case diag.SeverityError:
				return fmt.Errorf("control %s: %s", ctl.ID, issue.Message)
			case diag.SeverityWarn:
				slog.Warn("control validation warning",
					"control_id", ctl.ID,
					"message", issue.Message)
			default:
				// An unknown Severity value almost always means
				// someone added a new severity tier upstream and
				// didn't update this switch. Log so the gap is
				// visible instead of silently dropped.
				slog.Warn("control validation: unknown severity level",
					"control_id", ctl.ID,
					"severity", string(issue.Severity),
					"message", issue.Message)
			}
		}
	}
	return nil
}

// validateArchetype rejects any control whose archetype field references
// an ID that the catalog does not know about. Control authors typo
// archetype IDs frequently (silent_failure vs silent-failure, etc.);
// without load-time validation those typos either disappear into a
// generic "no archetype" branch downstream or surface as broken expand
// outputs, depending on the consumer. Surface the error here so the
// failing control file is named in the diagnostic.
func validateArchetype(ctl *policy.ControlDefinition) error {
	id := strings.TrimSpace(ctl.Archetype)
	if id == "" {
		return nil
	}
	if _, ok := archetype.Lookup(id); !ok {
		return fmt.Errorf("control %s: unknown archetype %q (run `stave expand --list` to see valid IDs)", ctl.ID, id)
	}
	return nil
}

// resolveAlias expands a predicate alias if set on the control definition.
func (l *ControlLoader) resolveAlias(ctl *policy.ControlDefinition) error {
	alias := strings.TrimSpace(ctl.UnsafePredicateAlias)
	if alias == "" {
		return nil
	}
	if l.aliasResolver == nil {
		return fmt.Errorf("unsafe_predicate_alias %q requires an alias resolver", alias)
	}
	if len(ctl.UnsafePredicate.Any) > 0 || len(ctl.UnsafePredicate.All) > 0 {
		return errors.New("cannot set both unsafe_predicate and unsafe_predicate_alias")
	}
	expanded, ok := l.aliasResolver(alias)
	if !ok {
		return fmt.Errorf("unknown unsafe_predicate_alias %q", alias)
	}
	ctl.UnsafePredicate = expanded
	return nil
}
