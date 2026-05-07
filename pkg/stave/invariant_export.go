package stave

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/sufield/stave/internal/core/controldef"
)

// InvariantExportConfig configures an invariant export.
//
// ControlsDir mirrors [Config.ControlsDir]: empty means "use the
// embedded built-in catalog"; a non-empty path loads controls from
// disk via the same YAML loader the evaluation pipeline uses.
type InvariantExportConfig struct {
	ControlsDir string
}

// InvariantExport is the structured projection of Stave's control
// catalog as solver-ready invariants. Each [InvariantDefinition]
// names the property — "this asset configuration is unsafe when X"
// — that an external solver can encode as the negation of a
// safety conjecture: "prove that no reachable configuration
// satisfies X".
//
// Composes with [PolicyExport] (the facts) and [GraphExport] (the
// relationships): together they form Stave's complete projection
// of "what is", "what reaches what", and "what should not be".
type InvariantExport struct {
	Invariants []InvariantDefinition
}

// InvariantDefinition is one solver-ready security property
// derived from a control's metadata and unsafe-predicate tree.
//
// ID matches the control's catalog ID so consumers can join an
// invariant back to the originating control. Description is the
// authored prose; for solvers that emit human-readable output the
// description is what surfaces in proof reports.
//
// IntentRationale carries the authored "why" prose — distinct
// from Description (which states what the control checks).
// AI agents and reasoning traces use IntentRationale to decide
// whether a triggered finding actually matters in context.
// Empty when the control YAML does not author it.
//
// ForbiddenState is the high-level invariant the control declares
// must never hold. The Z3 / SMT compiler reads it as a
// satisfiability conjecture: SAT means a configuration exists that
// violates the invariant; UNSAT proves the invariant safe.
// Distinct from Predicate (the per-asset CEL match expression):
// ForbiddenState carries the same predicate vocabulary but is
// authored as a system-level claim rather than a per-asset trigger.
// IsLeaf() on the zero PredicateExport returns true; consumers
// can branch on Combine == "" to detect "no forbidden_state
// authored on this control".
//
// Assets lists the asset types the control declares as applicable.
// An empty Assets means "applies to all asset types" — the
// catalog's legacy default.
type InvariantDefinition struct {
	ID              ControlID
	Description     string
	IntentRationale string
	Severity        Severity
	Scope           InvariantScope
	Predicate       PredicateExport
	ForbiddenState  PredicateExport
	Assets          []AssetConstraint
}

// InvariantScope classifies how the predicate reaches across the
// asset graph. Today every catalog predicate reads only from the
// current asset's property bag — ScopeSingleAsset is the only
// value emitted. Cross-asset and cross-service scopes belong to
// chain-derived invariants and are introduced when that export
// path lands.
type InvariantScope string

const (
	// ScopeSingleAsset means the predicate reads only properties of
	// the asset under evaluation. Every value in the unsafe
	// predicate's field paths resolves against that asset's own
	// observation map.
	ScopeSingleAsset InvariantScope = "single_asset"
)

// AssetConstraint names an asset type the invariant applies to.
type AssetConstraint struct {
	Type AssetType
}

// PredicateExport is the structured form of a control's
// unsafe_predicate tree. Solver consumers translate the tree into
// SMT assertions: leaves become field-path comparisons, Combine
// nodes become conjunctions ("all") or disjunctions ("any").
//
// Combine, Children, and (Property, Operator, Expected) are
// mutually exclusive at the same node:
//
//   - A leaf node has Combine == "" and carries
//     (Property, Operator, Expected).
//   - An internal node has Combine == "all" or "any" and a
//     non-empty Children slice.
//
// A consumer walks the tree by checking Combine first; "" means
// the leaf fields are valid.
type PredicateExport struct {
	// Combine is "all", "any", or "" (leaf).
	Combine string

	// Children is populated when Combine != "".
	Children []PredicateExport

	// Property is the observation field path for a leaf, e.g.
	// "properties.storage.access.policy_is_effectively_public".
	Property string

	// Operator is the leaf's comparison operator (eq, ne, gt,
	// present, contains, etc.) — the wire form a CEL or external
	// engine recognises.
	Operator string

	// Expected is the value the leaf compares against. For
	// param-bound leaves this is the parameter reference string
	// (e.g. "params.allowed_accounts"); for literal leaves it is
	// the literal value.
	Expected any
}

// IsLeaf reports whether the node carries a leaf comparison
// rather than a combined Children slice. Convenient for
// recursive walkers that need to branch on shape.
func (p PredicateExport) IsLeaf() bool {
	return p.Combine == ""
}

// ExportInvariants loads Stave's control catalog and projects
// every control's metadata + unsafe-predicate tree into a typed
// [InvariantExport]. Controls are loaded the same way [Apply]
// loads them: from cfg.ControlsDir when set, otherwise from the
// embedded built-in catalog.
//
// The export carries no evaluation state — no findings, no
// snapshot reads, no clock — so external solvers receive a pure
// description of "the rules Stave checks" without inheriting any
// of Stave's evaluation semantics.
func ExportInvariants(ctx context.Context, cfg InvariantExportConfig) (*InvariantExport, error) {
	if ctx == nil {
		return nil, errors.New("stave.ExportInvariants: ctx is required")
	}
	controls, err := loadInvariantControls(ctx, cfg.ControlsDir)
	if err != nil {
		return nil, err
	}

	out := &InvariantExport{
		Invariants: make([]InvariantDefinition, 0, len(controls)),
	}
	for i := range controls {
		out.Invariants = append(out.Invariants, projectControl(&controls[i]))
	}
	sort.Slice(out.Invariants, func(i, j int) bool {
		return out.Invariants[i].ID < out.Invariants[j].ID
	})
	return out, nil
}

// loadInvariantControls reuses the same control-resolution path
// the rest of pkg/stave uses (embedded catalog when dir empty;
// YAML loader otherwise). Returns the materialised slice — the
// repository view is internal-only.
func loadInvariantControls(ctx context.Context, dir string) ([]controldef.ControlDefinition, error) {
	controls, repo, err := resolveControls(dir)
	if err != nil {
		return nil, fmt.Errorf("load controls: %w", err)
	}
	if len(controls) > 0 {
		return controls, nil
	}
	if repo == nil {
		return nil, errors.New("no controls available")
	}
	loaded, err := repo.LoadControls(ctx, dir)
	if err != nil {
		return nil, fmt.Errorf("load controls from %q: %w", dir, err)
	}
	return loaded, nil
}

// projectControl builds an InvariantDefinition from a single
// control. Severity uses the catalog's lowercase string form to
// stay consistent with the [Finding] surface.
func projectControl(ctl *controldef.ControlDefinition) InvariantDefinition {
	def := InvariantDefinition{
		ID:              ctl.ID,
		Description:     strings.TrimSpace(ctl.Description),
		IntentRationale: strings.TrimSpace(ctl.IntentRationale),
		Severity:        Severity(ctl.Severity.String()),
		Scope:           ScopeSingleAsset,
		Predicate:       projectPredicate(ctl.UnsafePredicate),
		ForbiddenState:  projectPredicate(ctl.ForbiddenState),
	}
	if len(ctl.ApplicableAssetTypes) > 0 {
		def.Assets = make([]AssetConstraint, len(ctl.ApplicableAssetTypes))
		for i, t := range ctl.ApplicableAssetTypes {
			def.Assets[i] = AssetConstraint{Type: t}
		}
	}
	return def
}

// projectPredicate walks a control's UnsafePredicate tree and
// produces the public PredicateExport projection. The internal
// shape carries either Any-rules or All-rules at the root; only
// one is non-empty at a given level by construction.
func projectPredicate(p controldef.UnsafePredicate) PredicateExport {
	switch {
	case len(p.All) > 0:
		return PredicateExport{
			Combine:  "all",
			Children: projectRules(p.All),
		}
	case len(p.Any) > 0:
		return PredicateExport{
			Combine:  "any",
			Children: projectRules(p.Any),
		}
	default:
		return PredicateExport{}
	}
}

func projectRules(rules []controldef.PredicateRule) []PredicateExport {
	out := make([]PredicateExport, len(rules))
	for i := range rules {
		out[i] = projectRule(&rules[i])
	}
	return out
}

// projectRule converts one PredicateRule. A rule is either a
// nested combine block (Any/All) or a leaf field comparison; the
// ValueFromParam path encodes "expected value comes from a
// runtime param" by stamping a "params.<name>" reference into the
// leaf's Expected field so the structured output keeps the
// param-binding visible.
func projectRule(r *controldef.PredicateRule) PredicateExport {
	switch {
	case len(r.All) > 0:
		return PredicateExport{Combine: "all", Children: projectRules(r.All)}
	case len(r.Any) > 0:
		return PredicateExport{Combine: "any", Children: projectRules(r.Any)}
	}
	return PredicateExport{
		Property: r.Field.String(),
		Operator: string(r.Op),
		Expected: leafExpected(r),
	}
}

// leafExpected returns the value the leaf compares against. A
// param-bound leaf surfaces the reference string ("params.<name>")
// so consumers see that the leaf is parameterised; a literal leaf
// returns the raw operand value.
func leafExpected(r *controldef.PredicateRule) any {
	if !r.ValueFromParam.IsZero() {
		return "params." + r.ValueFromParam.String()
	}
	return r.Value.Raw()
}
