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
	"path/filepath"
	"slices"
	"strings"

	"github.com/sufield/stave/internal/adapters/controls/archetype"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	contractvalidator "github.com/sufield/stave/internal/contracts/validator"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/diag"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/taxonomy"
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
		return nil, fmt.Errorf("load controls: %w", err)
	}
	// Empty dir, ".", "./", or any other cwd-equivalent value means
	// the caller forgot to set --controls or passed through a zero
	// string. resolveControlPaths would walk the working directory
	// and return whatever YAML happened to be sitting there — a
	// silent surprise that produced phantom controls without a
	// clear cause. Reject every form that resolves to "the current
	// working directory" so the failure mode is the same regardless
	// of how the caller spelled the cwd.
	trimmed := strings.TrimSpace(dir)
	if isCwdEquivalent(trimmed) {
		return nil, fmt.Errorf("controls/yaml.LoadControls: %q resolves to the current working directory; set --controls or pass an explicit non-cwd path", dir)
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
			return nil, fmt.Errorf("load controls: %w", err)
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

	autoClassify(controls)

	triageIdx, triageErr := LoadTriageIndex(dir)
	if triageErr != nil {
		return nil, fmt.Errorf("loading triage from %q: %w", dir, triageErr)
	}
	if triageIdx != nil {
		ApplyTriage(controls, triageIdx)
	}

	return controls, nil
}

// isCwdEquivalent reports whether the trimmed input would resolve to
// the current working directory if passed to filepath.Walk. The set
// covers the empty string, ".", "./", and the canonical form
// returned by filepath.Clean for any of those — every spelling of
// "the directory I'm running from". Surfacing this as a single
// predicate keeps the LoadControls guard readable and gives a
// future caller exactly one place to extend if a new cwd alias
// surfaces.
func isCwdEquivalent(p string) bool {
	if p == "" {
		return true
	}
	cleaned := filepath.Clean(p)
	return cleaned == "." || cleaned == "./"
}

// loadOne performs IO, schema validation, unmarshal, and semantic enrichment
// for a single control file.
func (l *ControlLoader) loadOne(path string) (policy.ControlDefinition, error) {
	data, err := fsutil.ReadFileLimited(path)
	if err != nil {
		return policy.ControlDefinition{}, fmt.Errorf("read control file %s: %w", path, err)
	}

	issues, err := l.validator.ValidateControlYAML(data, contractvalidator.WithPrefix(path))
	if err != nil {
		return policy.ControlDefinition{}, fmt.Errorf("schema validation error: %w", err)
	}
	if issues.Failed() {
		return policy.ControlDefinition{}, fmt.Errorf("%w: %w", contractvalidator.ErrSchemaValidationFailed, issues)
	}
	// Schema warnings are advisory: surface them via slog so the
	// authoring problem is visible without losing the control. Mirrors
	// the SeverityWarn handling in enrichAndPrepare below — the
	// previous shape collapsed warnings into hard failures, so a
	// non-fatal schema annotation could silently drop an entire
	// control.
	if issues.HasWarnings() {
		slog.Warn("control schema validation warning",
			"path", path, "issues", issues.Error())
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
	if err := validateScopeCorpus(ctl); err != nil {
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
				// Demoted from slog.Warn → slog.Debug. These fire on
				// SHIPPED controls (the embedded catalog), not on
				// user-authored YAML. End users can't act on
				// "CTL.X has a malformed severity field" because they
				// didn't author CTL.X. Surfaced at DEBUG so the
				// developer running -vv during catalog work still
				// sees them, but `stave apply` no longer prints a
				// wall of warnings about controls the user didn't
				// touch. The remediation field is included so the
				// developer sees what's wrong without re-deriving
				// it from the rule ID.
				slog.Debug("control validation warning",
					"control_id", ctl.ID,
					"rule", string(issue.RuleID),
					"message", issue.Message,
					"remediation", issue.Remediation)
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
	if ctl.Archetype.IsEmpty() {
		return nil
	}
	if _, ok := archetype.Lookup(ctl.Archetype.String()); !ok {
		return fmt.Errorf("control %s: unknown archetype %q (run `stave expand --list` to see valid IDs)", ctl.ID, ctl.Archetype)
	}
	return nil
}

// validateScopeCorpus enforces the I0 contract from the
// AWS compound control authoring plan: any control with
// scope == "compound" must carry an attribution — either
// corpus_reference (external citation) or archetype (the
// catalog's own structural taxonomy entry). The Goodhart guard:
// without this, "compound count" as a metric invites synthetic
// compounds that pass the classifier's structural heuristic
// without representing a real attack pattern.
//
// Why archetype counts. The shipped catalog uses archetype to
// classify structural defect families (ghost-reference,
// confused-deputy, etc.). An archetype-tagged control IS
// referencing a documented pattern — it's just the catalog's own
// codification rather than an external one. Requiring an
// external citation in addition would force a synthetic
// "archetype:ghost-reference" citation prefix that re-states what
// the archetype field already says. The rule treats either
// attribution mechanism as sufficient.
//
// Scope values other than "atomic" / "compound" / empty are
// rejected upstream by the JSON Schema validator that runs
// before the YAML loader; this function only handles the
// conditional attribution rule.
func validateScopeCorpus(ctl *policy.ControlDefinition) error {
	if strings.TrimSpace(ctl.Scope) != "compound" {
		return nil
	}
	hasCorpus := strings.TrimSpace(ctl.CorpusReference) != ""
	hasArchetype := !ctl.Archetype.IsEmpty()
	if hasCorpus || hasArchetype {
		return nil
	}
	return fmt.Errorf(
		"control %s: scope=compound requires either corpus_reference "+
			"(MITRE:<id>, incident:<slug-year>, stratus:<technique>, "+
			"rhino:<technique>, csa:<doc>:<section>, hackerone:<id>, "+
			"snyk:<slug>, triz:<id>) or archetype (the catalog's own "+
			"structural taxonomy) — see docs/taxonomies/iam-compound.md "+
			"for the canonical schema",
		ctl.ID,
	)
}

// autoClassify runs the taxonomy classifier on controls that have no
// explicit taxonomy tags. Explicit YAML tags take precedence.
func autoClassify(controls []policy.ControlDefinition) {
	cl := taxonomy.NewClassifier()
	for i := range controls {
		if len(controls[i].Taxonomy) > 0 {
			continue
		}
		controls[i].Taxonomy = cl.ClassifyFields(
			string(controls[i].ID),
			controls[i].Name,
			controls[i].Description,
			nil,
		)
	}
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
