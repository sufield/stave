package conflict

import (
	"fmt"
	"slices"
)

// ConflictCategory matches the schema enum on ConflictPair.category.
type ConflictCategory string

const (
	CategoryContradiction        ConflictCategory = "CONTRADICTION"
	CategoryRedundancy           ConflictCategory = "REDUNDANCY"
	CategoryEmpiricalSubsumption ConflictCategory = "EMPIRICAL_SUBSUMPTION"
	CategoryDivergence           ConflictCategory = "DIVERGENCE"
)

// ContradictionSubcategory matches the schema enum on
// ContradictionPayload.subcategory.
type ContradictionSubcategory string

const (
	SubcategoryLogicBug               ContradictionSubcategory = "LOGIC_BUG"
	SubcategoryMissingAssetClassGuard ContradictionSubcategory = "MISSING_ASSET_CLASS_GUARD"
)

// ControlMetadata is the per-control comparison surface the classifier
// needs to determine REDUNDANCY. The renderer (Node 3d) hashes these
// for the schema payload; the classifier compares them as canonical
// strings for equivalence. Caller is responsible for producing
// canonical (sorted, deduped) inputs.
type ControlMetadata struct {
	ControlID            string
	AttackStage          string
	ComplianceCanonical  string // canonical sorted compliance mapping string
	RemediationCanonical string // canonical sorted remediation string
}

// ClassifiedPair extends EvaluatedPair with the chosen category and
// the inputs the report renderer needs for that category's payload.
// A pair with empty Category is uncategorized — agreed but not
// metadata-equivalent (no semantic conflict to report).
type ClassifiedPair struct {
	EvaluatedPair

	// Category is the assigned category, or "" for uncategorized pairs.
	Category ConflictCategory

	// ContradictionSubcategory is set when Category == CONTRADICTION.
	ContradictionSubcategory ContradictionSubcategory

	// MetadataA / MetadataB are the metadata views the classifier
	// compared. Stored on the pair so the renderer can produce hashes
	// without re-reading the catalog.
	MetadataA ControlMetadata
	MetadataB ControlMetadata
}

// Classify assigns a ConflictCategory to each EvaluatedPair using the
// precedence
//
//	CONTRADICTION > REDUNDANCY > EMPIRICAL_SUBSUMPTION > DIVERGENCE
//
// applied as a *disqualifying* rule, not first-match. The disqualifying
// semantics are correctness-critical and easy to silently break (a
// well-meaning "REDUNDANCY tolerance threshold" feature would
// reintroduce the bug). The rationale, the specific invariants, and the
// pinning tests that guard them are documented in
// `internal/catalog/conflict/PRECEDENCE.md`, which sits next to this
// file. Read it before changing this function.
//
// The disqualifying rules in detail:
//
//   - REDUNDANCY requires unanimous agreement across every evaluated
//     fixture. Any disagreement, however rare, classifies the pair as
//     CONTRADICTION (LOGIC_BUG or MISSING_ASSET_CLASS_GUARD).
//
//   - EMPIRICAL_SUBSUMPTION (B subsumes A, A is narrower) requires:
//     no fixture where A=VIOLATION and B=PASS. Fixtures where
//     A=PASS and B=VIOLATION are *consistent* with B being stricter
//     and do not disqualify subsumption. A single A=VIOLATION,B=PASS
//     witness disqualifies subsumption and classifies the pair as
//     CONTRADICTION.
//
//   - CONTRADICTION subcategory: MISSING_ASSET_CLASS_GUARD if the
//     disagreement witnesses span more than one asset_class
//     (asset.Type), LOGIC_BUG otherwise. See feedback memory for why
//     this isn't a "statistical explanatory variable" detector.
//
// Pairs with zero co-evaluations are returned with empty Category;
// callers should surface them in analysis_gaps[] with reason
// NO_FIXTURE_COVERAGE.
//
// metadata must contain entries for every ControlID referenced by the
// input pairs; missing entries are a fail-loud programmer error
// (REDUNDANCY classification cannot be reached without metadata).
func Classify(
	evaluated []EvaluatedPair,
	metadata map[string]ControlMetadata,
) ([]ClassifiedPair, error) {
	out := make([]ClassifiedPair, 0, len(evaluated))
	for i := range evaluated {
		ep := &evaluated[i]
		mdA, okA := metadata[ep.ControlA]
		mdB, okB := metadata[ep.ControlB]
		if !okA || !okB {
			missing := ep.ControlA
			if okA {
				missing = ep.ControlB
			}
			return nil, fmt.Errorf(
				"Classify: pair (%s, %s) references control %s with no metadata entry",
				ep.ControlA, ep.ControlB, missing)
		}

		cp := ClassifiedPair{
			EvaluatedPair: *ep,
			MetadataA:     mdA,
			MetadataB:     mdB,
		}
		cp.Category, cp.ContradictionSubcategory = classifyOne(ep, mdA, mdB)
		out = append(out, cp)
	}
	return out, nil
}

// classifyOne implements the precedence rule for a single pair. It is
// ordered to make the disqualifying semantics explicit: each branch
// either commits to a category and returns, or falls through. There is
// no later branch that can override an earlier commitment.
func classifyOne(ep *EvaluatedPair, mdA, mdB ControlMetadata) (ConflictCategory, ContradictionSubcategory) {
	if len(ep.CoEvaluations) == 0 {
		return "", ""
	}

	disagreements := disagreementWitnesses(ep.CoEvaluations)

	if ep.Relation == RelationSubset {
		// Direction: ep.Narrower is A_eff, ep.Broader is B_eff.
		// Subsumption claim: every (A_eff=VIOLATION) implies (B_eff=VIOLATION).
		// A witness where A_eff=VIOLATION and B_eff=PASS disqualifies it.
		if !subsumptionViolated(ep) {
			return CategoryEmpiricalSubsumption, ""
		}
		// Subsumption violated → CONTRADICTION; fall through to
		// subcategory selection below.
	}

	if len(disagreements) > 0 {
		// CONTRADICTION wins over everything that follows. Subcategory
		// is determined by asset_class diversity in disagreement
		// witnesses — see feedback memory for the rationale.
		if assetClassesVary(disagreements) {
			return CategoryContradiction, SubcategoryMissingAssetClassGuard
		}
		// For OVERLAPPING (not subset, not identical) deps, disagreement
		// without asset_class diversity is the DIVERGENCE case: the
		// non-shared dep paths likely explain the split.
		if ep.Relation == RelationOverlapping {
			return CategoryDivergence, ""
		}
		return CategoryContradiction, SubcategoryLogicBug
	}

	// 100% agreement. REDUNDANCY only when deps are IDENTICAL and
	// metadata matches. Anything else (OVERLAPPING with full agreement,
	// or IDENTICAL deps with mismatched compliance/attack_stage/
	// remediation) is operational alignment without semantic
	// equivalence — surface as uncategorized rather than over-claim.
	if ep.Relation == RelationIdentical && metadataEquivalent(mdA, mdB) {
		return CategoryRedundancy, ""
	}
	return "", ""
}

// disagreementWitnesses returns the subset of co-evaluations where the
// two controls reached different verdicts. Order is preserved (already
// lexicographic by (FixturePath, AssetID) per EvaluatePairs).
func disagreementWitnesses(coevals []CoEvaluation) []CoEvaluation {
	var out []CoEvaluation
	for _, ce := range coevals {
		if ce.UnsafeA != ce.UnsafeB {
			out = append(out, ce)
		}
	}
	return out
}

// subsumptionViolated returns true if there is any fixture where the
// narrower control fires VIOLATION but the broader control does not.
// That single witness disqualifies the broader from subsuming the
// narrower. The reverse direction (narrower=PASS, broader=VIOLATION)
// is consistent with subsumption (broader is stricter) and does not
// disqualify.
//
// Precondition: ep.Relation == RelationSubset and ep.Narrower /
// ep.Broader are populated.
func subsumptionViolated(ep *EvaluatedPair) bool {
	narrowerIsA := ep.Narrower == ep.ControlA
	for _, ce := range ep.CoEvaluations {
		var unsafeNarrower, unsafeBroader bool
		if narrowerIsA {
			unsafeNarrower, unsafeBroader = ce.UnsafeA, ce.UnsafeB
		} else {
			unsafeNarrower, unsafeBroader = ce.UnsafeB, ce.UnsafeA
		}
		if unsafeNarrower && !unsafeBroader {
			return true
		}
	}
	return false
}

// assetClassesVary returns true if the disagreement witnesses span more
// than one distinct asset.Type value. Used as the MISSING_ASSET_CLASS_GUARD
// vs LOGIC_BUG discriminator. See feedback memory for why this is a
// presence-of-diversity check rather than a statistical correlation
// test.
func assetClassesVary(witnesses []CoEvaluation) bool {
	if len(witnesses) < 2 {
		return false
	}
	first := witnesses[0].AssetType
	for _, w := range witnesses[1:] {
		if w.AssetType != first {
			return true
		}
	}
	return false
}

// metadataEquivalent reports whether two ControlMetadata views are
// equal on the dimensions REDUNDANCY requires: attack_stage,
// canonical compliance string, canonical remediation string. The
// caller is responsible for producing canonical inputs (sorted,
// deduped) so a string equality check suffices here.
func metadataEquivalent(a, b ControlMetadata) bool {
	return a.AttackStage == b.AttackStage &&
		a.ComplianceCanonical == b.ComplianceCanonical &&
		a.RemediationCanonical == b.RemediationCanonical
}

// ClassificationCounts summarizes a Classify result by category. The
// empty category counts uncategorized pairs (agreed-but-not-redundant
// and zero-coverage).
type ClassificationCounts struct {
	Contradiction        int
	Redundancy           int
	EmpiricalSubsumption int
	Divergence           int
	Uncategorized        int
}

// Count tallies a ClassifiedPair slice into a ClassificationCounts.
func Count(pairs []ClassifiedPair) ClassificationCounts {
	var c ClassificationCounts
	for i := range pairs {
		switch pairs[i].Category {
		case CategoryContradiction:
			c.Contradiction++
		case CategoryRedundancy:
			c.Redundancy++
		case CategoryEmpiricalSubsumption:
			c.EmpiricalSubsumption++
		case CategoryDivergence:
			c.Divergence++
		default:
			c.Uncategorized++
		}
	}
	return c
}

// SortByCategory returns a copy of pairs sorted by (Category, ControlA,
// ControlB) for deterministic report rendering. Uncategorized pairs
// sort last.
func SortByCategory(pairs []ClassifiedPair) []ClassifiedPair {
	out := slices.Clone(pairs)
	slices.SortFunc(out, func(x, y ClassifiedPair) int {
		if c := compareCategoryRank(x.Category, y.Category); c != 0 {
			return c
		}
		if c := compareString(x.ControlA, y.ControlA); c != 0 {
			return c
		}
		return compareString(x.ControlB, y.ControlB)
	})
	return out
}

func compareCategoryRank(a, b ConflictCategory) int {
	return categoryRank(a) - categoryRank(b)
}

// categoryRank gives a stable sort order. Matches the precedence rule
// (CONTRADICTION first) so the report leads with the highest-severity
// category.
func categoryRank(c ConflictCategory) int {
	switch c {
	case CategoryContradiction:
		return 0
	case CategoryRedundancy:
		return 1
	case CategoryEmpiricalSubsumption:
		return 2
	case CategoryDivergence:
		return 3
	default:
		return 4
	}
}
