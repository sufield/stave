// Package conflict analyzes control catalog coherence. It enumerates
// pairs of controls whose predicates read overlapping property paths
// and classifies the dependency relationship. Overlap analysis is the
// first pass of full conflict detection: pairs with no shared inputs
// cannot conflict semantically, so they are discarded before any
// fixture evaluation. A later pass (Node 3b) evaluates the candidate
// pairs against the fixture corpus; classification into the taxonomy
// categories (CONTRADICTION, REDUNDANCY, EMPIRICAL_SUBSUMPTION,
// DIVERGENCE) happens in Node 3c.
package conflict

import (
	"errors"
	"fmt"
	"slices"

	"github.com/sufield/stave/internal/cel/deps"
	policy "github.com/sufield/stave/internal/core/controldef"
)

// DependencyRelation describes how the two controls' dependency sets
// relate. It is an enum over three disjoint cases plus the implicit
// "no overlap" case, which is filtered out before emitting a candidate
// pair.
type DependencyRelation int

const (
	// RelationIdentical: A.deps == B.deps. Precondition for REDUNDANCY.
	RelationIdentical DependencyRelation = iota

	// RelationSubset: one control's deps are a strict subset of the
	// other's. Precondition for EMPIRICAL_SUBSUMPTION. The NarrowerIdx
	// / BrowderIdx fields on CandidatePair disambiguate which is which.
	RelationSubset

	// RelationOverlapping: nonempty intersection, but neither set is a
	// subset of the other. Precondition for CONTRADICTION (with missing
	// guard) and DIVERGENCE.
	RelationOverlapping
)

// String renders the relation as a stable token for logs and reports.
func (r DependencyRelation) String() string {
	switch r {
	case RelationIdentical:
		return "IDENTICAL"
	case RelationSubset:
		return "SUBSET"
	case RelationOverlapping:
		return "OVERLAPPING"
	default:
		return fmt.Sprintf("unknown(%d)", int(r))
	}
}

// CandidatePair is one control pair surviving the overlap filter. The
// (ControlA, ControlB) pair is canonicalized so ControlA <= ControlB
// lexicographically; the pair appears at most once per analysis run.
type CandidatePair struct {
	ControlA string
	ControlB string

	// DepsA and DepsB are the full dependency sets of each control,
	// sorted lexicographically. Stored on the pair so later passes do
	// not re-extract.
	DepsA []string
	DepsB []string

	// Overlap is the set intersection of DepsA and DepsB, sorted.
	// Non-empty by construction (empty overlap filters the pair out).
	Overlap []string

	// Relation is the dependency-set relationship.
	Relation DependencyRelation

	// Narrower and Broader are the control IDs of the narrower and
	// broader control when Relation is RelationSubset. Empty strings
	// otherwise. Narrower always has strictly fewer dependencies.
	Narrower string
	Broader  string
}

// AnalysisStats summarizes an overlap analysis run. The stats surface
// the shape of the catalog itself: if the ratio of candidate pairs to
// total pairs is high (>10%), the catalog's dependency paths are too
// coarse and downstream conflict detection will be noisy. The stats
// are the diagnostic; fixing them is a catalog-authoring concern, not
// an analyzer concern.
type AnalysisStats struct {
	// TotalControls is the catalog size fed into the analyzer.
	TotalControls int

	// TotalPairs is the number of unordered pairs considered, i.e.,
	// N*(N-1)/2 where N = number of controls with extractable deps.
	TotalPairs int

	// CandidatePairs is the count of pairs with non-empty overlap.
	CandidatePairs int

	// ByRelation distributes candidate pairs across the three
	// dependency relationships.
	ByRelation map[DependencyRelation]int

	// SkippedAliased is the count of controls whose predicates could
	// not be statically analyzed (unsafe_predicate_alias). These
	// controls are excluded from pair enumeration entirely. Surfaced
	// so corpus-honesty is preserved — a missing control is not a
	// zero-conflict control.
	SkippedAliased []string

	// SkippedEmptyDeps is the count of controls with no extractable
	// dependencies (e.g., non-state-based rules). Also excluded from
	// pair enumeration.
	SkippedEmptyDeps []string

	// SkippedMetadataOnly is the count of pairs whose dependency
	// intersection consisted entirely of asset-routing metadata paths
	// (see metadataOnlyPaths). These pairs are not real overlap — each
	// control reads the metadata path to gate which asset class it
	// applies to, not to evaluate the asset's security state. Surfaced
	// for corpus honesty: a pair filtered here is structurally not a
	// conflict, distinct from a pair that genuinely had no shared deps.
	SkippedMetadataOnly int
}

// CandidateRatio returns the fraction of total pairs that survived the
// overlap filter. A value above 0.10 suggests the catalog's property
// paths are too coarse-grained and downstream conflict detection will
// produce noise.
func (s AnalysisStats) CandidateRatio() float64 {
	if s.TotalPairs == 0 {
		return 0
	}
	return float64(s.CandidatePairs) / float64(s.TotalPairs)
}

// AnalyzeOverlap runs the overlap analysis pass against the supplied
// catalog. Controls whose predicates cannot be statically analyzed are
// skipped (surfaced in stats.SkippedAliased). Controls with no
// extractable dependencies are skipped (surfaced in stats.SkippedEmptyDeps).
// The returned pairs are sorted by (ControlA, ControlB) for determinism.
//
// This is a pure function of its input: the same catalog always
// produces the same pairs and stats. No fixture evaluation happens
// here.
func AnalyzeOverlap(controls []policy.ControlDefinition) ([]CandidatePair, AnalysisStats, error) {
	stats := AnalysisStats{
		TotalControls: len(controls),
		ByRelation:    map[DependencyRelation]int{},
	}

	type controlWithDeps struct {
		id   string
		deps []string
	}
	usable := make([]controlWithDeps, 0, len(controls))

	for i := range controls {
		ctl := &controls[i]
		id := string(ctl.ID)

		extracted, err := deps.ExtractFromControl(ctl)
		if err != nil {
			if errors.Is(err, deps.ErrAliasedPredicate) {
				stats.SkippedAliased = append(stats.SkippedAliased, id)
				continue
			}
			return nil, stats, fmt.Errorf("extract deps for %s: %w", id, err)
		}
		if len(extracted) == 0 {
			stats.SkippedEmptyDeps = append(stats.SkippedEmptyDeps, id)
			continue
		}
		usable = append(usable, controlWithDeps{id: id, deps: extracted})
	}
	slices.Sort(stats.SkippedAliased)
	slices.Sort(stats.SkippedEmptyDeps)

	// Sort usable by control ID so pair enumeration produces canonical
	// (ControlA <= ControlB) pairs regardless of input order.
	slices.SortFunc(usable, func(a, b controlWithDeps) int {
		return compareString(a.id, b.id)
	})

	n := len(usable)
	stats.TotalPairs = n * (n - 1) / 2

	var pairs []CandidatePair
	for i := range n {
		for j := i + 1; j < n; j++ {
			a, b := usable[i], usable[j]

			fullOverlap := intersectSorted(a.deps, b.deps)
			if len(fullOverlap) == 0 {
				continue
			}
			overlap := stripMetadataPaths(fullOverlap)
			if len(overlap) == 0 {
				stats.SkippedMetadataOnly++
				continue
			}

			// Relation is computed against the full intersection so an
			// IDENTICAL dep-set pair is still labeled IDENTICAL even if
			// some of its shared paths are metadata routers. Overlap (the
			// substantive subset) is what evaluation/classification reads.
			rel := classifyRelation(a.deps, b.deps, fullOverlap)
			pair := CandidatePair{
				ControlA: a.id,
				ControlB: b.id,
				DepsA:    append([]string(nil), a.deps...),
				DepsB:    append([]string(nil), b.deps...),
				Overlap:  overlap,
				Relation: rel,
			}
			if rel == RelationSubset {
				if len(a.deps) < len(b.deps) {
					pair.Narrower, pair.Broader = a.id, b.id
				} else {
					pair.Narrower, pair.Broader = b.id, a.id
				}
			}
			pairs = append(pairs, pair)
			stats.ByRelation[rel]++
		}
	}
	stats.CandidatePairs = len(pairs)

	slices.SortFunc(pairs, func(x, y CandidatePair) int {
		if x.ControlA != y.ControlA {
			return compareString(x.ControlA, y.ControlA)
		}
		return compareString(x.ControlB, y.ControlB)
	})

	return pairs, stats, nil
}

// metadataOnlyPaths is the closed set of dependency paths that controls
// read for asset-class routing rather than evaluation. A pair whose
// overlap consists entirely of these paths is not a semantic conflict
// candidate — each side reads the path to decide whether the control
// applies, and CEL absent-value semantics on assets of the wrong class
// produce verdicts that the classifier would mistake for disagreement.
//
// Audited from the 630-control catalog (Iteration 3.6, 2026-04-17):
// `type` is the only metadata path that actually appears as a shared
// dependency. `id` exists as a bare extracted path but only inside
// `identities[]` predicates (substantive identity inspection, not
// asset routing) so it is not included. `arn`, `region`, `account_id`
// were considered but do not appear as extracted deps in this catalog.
//
// This denylist is the in-overlap workaround for a structural gap:
// the CEL dependency extractor (internal/cel/deps) does not distinguish
// reads-for-routing from reads-for-evaluation. The principled fix is
// an extractor extension (out of scope for 3.6 — see PRECEDENCE.md
// "conceptual distinctions"). Until then, extending this list when a
// new routing-only field appears in the catalog is the right move;
// adding fields speculatively is not.
var metadataOnlyPaths = map[string]struct{}{
	"type": {},
}

// stripMetadataPaths returns paths with metadata-only entries removed.
// Input is assumed sorted; output remains sorted. Returns the input
// slice unchanged if no entries were filtered, to avoid allocation in
// the common case.
func stripMetadataPaths(paths []string) []string {
	keep := paths[:0:0] // nil slice with paths' cap=0 — never aliases input
	dropped := 0
	for _, p := range paths {
		if _, isMeta := metadataOnlyPaths[p]; isMeta {
			dropped++
			continue
		}
		keep = append(keep, p)
	}
	if dropped == 0 {
		return paths
	}
	return keep
}

// intersectSorted returns the sorted intersection of two lexicographically
// sorted dependency path lists. Inputs are assumed sorted (the deps
// extractor guarantees this).
func intersectSorted(a, b []string) []string {
	var out []string
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		switch {
		case a[i] == b[j]:
			out = append(out, a[i])
			i++
			j++
		case a[i] < b[j]:
			i++
		default:
			j++
		}
	}
	return out
}

// classifyRelation determines the dependency-set relationship given
// both full dep lists and their overlap. Precondition: overlap is
// non-empty.
func classifyRelation(a, b, overlap []string) DependencyRelation {
	aIsSubset := len(overlap) == len(a)
	bIsSubset := len(overlap) == len(b)
	switch {
	case aIsSubset && bIsSubset:
		return RelationIdentical
	case aIsSubset || bIsSubset:
		return RelationSubset
	default:
		return RelationOverlapping
	}
}

func compareString(a, b string) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}
