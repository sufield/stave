// SIR projection-coverage validator.
//
// The validator answers a single question: for every control that
// fires on a given fixture, are the observation properties the
// control evaluated also projected as SIR facts? When the answer
// is "no" the SMT/JSONL export carries no triple that
// distinguishes vulnerable from remediated for that control —
// any query the operator writes against the export will report
// the same verdict on both. This is the projection gap that cost
// 13 fixture-debugging cycles before this iteration; the warning
// catches it at export time.
//
// Why structural walking, not regex
//
// The original spec proposed extracting property paths from CEL
// predicates with a regex. Stave's controls do not store
// free-form CEL strings — they store an `UnsafePredicate` AST
// with explicit `Field` paths, traversable via the existing
// `UnsafePredicate.Walk` method. The structured walk is exact,
// handles nested any/all blocks, and matches what the engine
// itself reads at evaluation time. A regex would lose nested
// branches and array indexing.

package exportsir

import (
	"fmt"
	"sort"
	"strings"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/sirfacts"
)

// ValidationWarning is one (control, asset, property-path) tuple
// that fired in CEL but lacks a covering SIR fact for the asset.
// Subjects, paths, and messages are stable strings — callers can
// grep by ControlID or AssetID to scope diagnostics.
type ValidationWarning struct {
	ControlID string `json:"control_id"`
	AssetID   string `json:"asset_id"`
	CELPath   string `json:"cel_path"`
	Message   string `json:"message"`
}

// ValidateSIRCompleteness compares the property paths each fired
// control evaluates (from its UnsafePredicate AST) against the
// property paths the SIR fact projection emits (from each fact's
// provenance). Returns one ValidationWarning per (finding,
// uncovered path) pair.
//
// Coverage matching is substring-based on the
// "properties."-stripped path:
//
//	control predicate field: "properties.identity.governance.self_registration_restricted"
//	→ stripped:              "identity.governance.self_registration_restricted"
//	fact provenance path:    "identity.governance.self_registration_restricted"
//	→ covered (exact suffix match)
//
//	control predicate field: "properties.identity.policies.attached_policies"
//	fact provenance path:    "identity.policies.attached_policies[0].statements[0].Action"
//	→ covered (control path is a prefix of fact path)
//
// The substring direction is bidirectional because some
// projectors emit a deeper path (a leaf inside a nested array)
// while the control evaluates a shallower predicate that takes
// the array as input. Either direction matching counts as
// coverage; the warning only fires when neither direction holds.
//
// Findings whose ControlID is not in the supplied catalog are
// skipped silently — that's a load-time bug, not a coverage gap.
func ValidateSIRCompleteness(
	findings []evaluation.Finding,
	facts []sirfacts.Fact,
	controls []policy.ControlDefinition,
) []ValidationWarning {
	if len(findings) == 0 || len(facts) == 0 {
		return nil
	}

	// Index facts by Subject → set of provenance property paths.
	// The set form lets us answer "any fact path covers this CEL
	// path?" with a single map iteration per finding.
	factPathsByAsset := make(map[string]map[string]bool)
	for _, f := range facts {
		if f.Provenance == nil || f.Provenance.PropertyPath == "" {
			continue
		}
		set := factPathsByAsset[f.Subject]
		if set == nil {
			set = make(map[string]bool)
			factPathsByAsset[f.Subject] = set
		}
		set[f.Provenance.PropertyPath] = true
	}

	// Index controls by ID → predicate field paths. Walking the
	// predicate AST once per control (rather than per finding)
	// keeps the cost O(controls * predicate-size) instead of
	// O(findings * predicate-size).
	pathsByControl := make(map[kernel.ControlID][]string)
	for i := range controls {
		c := &controls[i]
		paths := extractPredicateFieldPaths(c.UnsafePredicate)
		if len(paths) > 0 {
			pathsByControl[c.ID] = paths
		}
	}

	var warnings []ValidationWarning
	for i := range findings {
		f := &findings[i]
		celPaths, ok := pathsByControl[f.ControlID]
		if !ok || len(celPaths) == 0 {
			continue
		}
		assetPaths := factPathsByAsset[string(f.AssetID)]
		for _, celPath := range celPaths {
			if pathCovered(celPath, assetPaths) {
				continue
			}
			warnings = append(warnings, ValidationWarning{
				ControlID: string(f.ControlID),
				AssetID:   string(f.AssetID),
				CELPath:   celPath,
				Message: fmt.Sprintf(
					"Control %s evaluates %s but no SIR fact covers this property path. "+
						"SMT queries cannot distinguish vulnerable from remediated for this control.",
					f.ControlID, celPath),
			})
		}
	}

	// Determinism: warnings sorted by ControlID then AssetID then
	// CELPath so the same (findings, facts, controls) triple
	// produces byte-identical stderr output across runs.
	sort.Slice(warnings, func(i, j int) bool {
		a, b := &warnings[i], &warnings[j]
		if a.ControlID != b.ControlID {
			return a.ControlID < b.ControlID
		}
		if a.AssetID != b.AssetID {
			return a.AssetID < b.AssetID
		}
		return a.CELPath < b.CELPath
	})

	return warnings
}

// extractPredicateFieldPaths walks an UnsafePredicate AST and
// returns every `Field` path stripped of the leading
// "properties." prefix that observations carry but provenance
// paths do not. Empty Field values (parent any/all nodes) are
// skipped — only leaf rules contribute.
//
// Determinism: returned paths are deduplicated and sorted so
// downstream comparison is stable.
func extractPredicateFieldPaths(p policy.UnsafePredicate) []string {
	seen := make(map[string]bool)
	p.Walk(func(rule policy.PredicateRule) {
		if rule.Field.IsZero() {
			return
		}
		path := strings.TrimPrefix(rule.Field.String(), "properties.")
		if path == "" {
			return
		}
		seen[path] = true
	})
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// pathCovered reports whether any fact path in `assetPaths`
// covers the supplied control predicate path. Coverage is
// substring-based in either direction (control-as-prefix-of-fact
// for nested-array projection, fact-as-prefix-of-control for
// shallow projections that summarise a deeper field).
func pathCovered(celPath string, assetPaths map[string]bool) bool {
	for factPath := range assetPaths {
		if factPath == celPath {
			return true
		}
		if strings.Contains(factPath, celPath) {
			return true
		}
		if strings.Contains(celPath, factPath) {
			return true
		}
	}
	return false
}

// renderValidationWarnings writes the human-readable summary used
// by the --validate flag. Output goes to the supplied writer
// (stderr in the CLI). The format is grep-friendly: each warning
// fits on two lines (Message line + Asset line) with a leading
// "  WARNING:" tag so CI scripts can `grep -c "WARNING:"` for a
// gap count without parsing structured output.
//
// Returning nil for an empty warning slice keeps the writer's
// output unchanged on the happy path; the no-gaps banner is
// emitted by the caller (it's an information line, not a
// warning, and the caller decides whether the user should see
// it).
func renderValidationWarnings(w stringWriter, warnings []ValidationWarning) {
	if len(warnings) == 0 {
		return
	}
	fmt.Fprintf(w, "\n%d SIR projection gap(s) detected:\n\n", len(warnings))
	for i := range warnings {
		fmt.Fprintf(w, "  WARNING: %s\n", warnings[i].Message)
		fmt.Fprintf(w, "           Asset: %s\n\n", warnings[i].AssetID)
	}
	fmt.Fprintf(w, "These controls fire in CEL but the properties they evaluate\n")
	fmt.Fprintf(w, "are not projected into the SIR. Add projector entries in\n")
	fmt.Fprintf(w, "cmd/exportsir/facts.go to close these gaps.\n\n")
}

// stringWriter is the io.Writer subset renderValidationWarnings
// needs. The narrower interface keeps tests from depending on
// the full io package and documents that the renderer never
// reads.
type stringWriter interface {
	Write(p []byte) (n int, err error)
}

// Re-exports for the unused compile-checks; keeps `asset`
// imported even when the file's helpers don't directly mention
// the package symbol. The validator API uses asset.ID-typed
// AssetID fields on findings.
var _ = asset.ID("")
