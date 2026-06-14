package sirfacts

import (
	"strings"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/predindex"
	"github.com/sufield/stave/internal/core/sir"
)

// AutoPropertyFacts is the Option C experiment: instead of the
// hand-curated propertyAllowlist (59 entries, 41 of which overlap
// with the catalog's 2,954 read paths), walk the predicate index
// and emit one triple per (control-read path, asset, scalar value).
//
// # Scope of the experiment
//
// Auto-generated facts use the predicate-name prefix "auto_prop_"
// so they live in a separate namespace from the curated has_*
// predicates. Downstream solvers (Z3, cvc5, Soufflé, etc.) reading
// has_public_read / can_assume / has_allow_action see no new
// assertions on the predicates they know about — only new unknown
// predicates they will ignore unless they choose to consume them.
//
// This means "--allowlist-mode full" CANNOT break any consumer
// that was working with --allowlist-mode curated. It strictly
// adds facts. The cost is solving time and file size; the
// experimental README at experiments/sir-coverage-expansion/
// documents the measurement method and the decision rule for
// promoting "full" to the default.
//
// # Coverage shape
//
// For every (assetType, path) pair in predindex.Index.TypeToPaths
// where the snapshot contains at least one asset of that type AND
// the asset's properties JSON contains a scalar (bool / number /
// string) at that path, emit:
//
//	auto_prop_<normalized_path>(asset_id, value)
//
// where normalized_path strips the "properties." prefix and
// replaces "." with "_". Map / slice leaves are skipped (the
// curated projector's same rule) because closed-world axioms
// over non-scalar values are ill-defined.
func AutoPropertyFacts(assets []sir.AssetFact, controls []policy.ControlDefinition) []Fact {
	idx := predindex.Build(controls, nil)

	// pathsByType maps every asset type to the deduplicated set
	// of property paths read by controls applicable to that type.
	// predindex.TypeToPaths already gives us this — we just need
	// the membership check.
	pathsByType := idx.TypeToPaths
	if len(pathsByType) == 0 {
		return nil
	}

	var out []Fact
	for i := range assets {
		a := &assets[i]
		paths, ok := pathsByType[kernel.AssetType(a.Type)]
		if !ok || len(paths) == 0 {
			continue
		}
		for _, p := range paths {
			value, found := lookupScalar(a.Properties, p)
			if !found {
				continue
			}
			predicate := "auto_prop_" + sanitizeAutoPredicate(p)
			out = append(out, Fact{
				Subject:   a.ID,
				Predicate: predicate,
				Object:    scalarString(value),
				Source:    "auto_property",
				Evidence:  "assets." + a.ID + "." + p,
			})
		}
	}
	return out
}

// lookupScalar walks the dot-separated path into the asset's
// Properties map, stopping at the first scalar (bool / number /
// string). Returns (value, true) on a scalar hit, (nil, false)
// when any segment is missing, the leaf is a map / slice, or the
// path doesn't resolve. Mirrors the curated propertyFacts walker's
// "scalars only" rule so the two projectors agree on what counts
// as a fact.
func lookupScalar(properties map[string]any, path string) (any, bool) {
	const prefix = "properties."
	if !strings.HasPrefix(path, prefix) {
		return nil, false
	}
	p := strings.TrimPrefix(path, prefix)
	var cursor any = properties
	for p != "" {
		var seg string
		seg, p, _ = strings.Cut(p, ".")
		m, ok := cursor.(map[string]any)
		if !ok {
			return nil, false
		}
		next, present := m[seg]
		if !present {
			return nil, false
		}
		cursor = next
	}
	switch cursor.(type) {
	case map[string]any, []any:
		return nil, false
	case nil:
		return nil, false
	}
	return cursor, true
}

// sanitizeAutoPredicate turns a property path into a stable
// predicate-name suffix. Dots become underscores and any
// non-alphanumeric character collapses to underscore — same
// shape SMT-LIB tolerates as an unquoted identifier without
// resorting to |…| escapes. Empty segments are dropped so a
// path like "properties..foo" still produces a parseable name.
func sanitizeAutoPredicate(path string) string {
	stripped := strings.TrimPrefix(path, "properties.")
	var b strings.Builder
	b.Grow(len(stripped))
	prevUnderscore := false
	for _, r := range stripped {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
			prevUnderscore = false
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r + 32) // lowercase
			prevUnderscore = false
		case !prevUnderscore:
			b.WriteRune('_')
			prevUnderscore = true
		}
	}
	return strings.Trim(b.String(), "_")
}
