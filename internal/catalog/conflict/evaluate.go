package conflict

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

// FixtureAsset pairs an asset with the source fixture path so witness
// records can carry that provenance. Witnesses without a fixture path
// are not actionable: a downstream consumer must be able to open the
// fixture and reproduce the verdict.
type FixtureAsset struct {
	FixturePath string
	Asset       asset.Asset
	Identities  []asset.CloudIdentity
}

// CoEvaluation is the per-fixture verdict pair for a CandidatePair. It
// is the lowest-level fact the classification step (Node 3c) reasons
// over: same-pair, same-fixture, both verdicts side by side.
type CoEvaluation struct {
	FixturePath string
	AssetID     string

	// AssetType is the asset's class (e.g., aws_s3_bucket, aws_iam_role).
	// Captured because the classifier (Node 3c) uses asset_class diversity
	// across disagreement witnesses to distinguish CONTRADICTION's
	// MISSING_ASSET_CLASS_GUARD subcategory from LOGIC_BUG.
	AssetType kernel.AssetType

	// UnsafeA / UnsafeB are the unsafe (VIOLATION) flags returned by the
	// predicate evaluator for each control.
	UnsafeA bool
	UnsafeB bool

	// PathValues records the values present on the asset at every
	// dependency path either control reads (DepsA ∪ DepsB), keyed by
	// dotted path. The renderer slices this for witness payloads:
	// CONTRADICTION's observed_values uses the overlap subset;
	// DIVERGENCE's differing_values uses the non-overlap subset. A nil
	// map means no read path resolved on this asset.
	PathValues map[string]any

	// ReadOverlap is true when at least one overlap path (CandidatePair.Overlap)
	// resolved to a non-missing value. Drives the FixturesMatched
	// coverage count — a fixture without overlap-path values does not
	// count as actively exercising the pair.
	ReadOverlap bool
}

// EvalError records a per-fixture, per-control evaluation failure. A
// fixture that fails evaluation for one control is still counted as
// evaluated (for total denominator) but is excluded from CoEvaluations.
// Tracked separately so coverage stats are honest about the run.
type EvalError struct {
	FixturePath string
	AssetID     string
	ControlID   string
	Err         string
}

// EvaluatedPair extends CandidatePair with results from running both
// controls against the fixture corpus. Classification (Node 3c) reads
// from EvaluatedPair, not CandidatePair — the agreement / disagreement
// distribution is what classifies REDUNDANCY vs DIVERGENCE vs
// CONTRADICTION.
type EvaluatedPair struct {
	CandidatePair

	// FixturesEvaluated is the count of fixtures the pair was attempted
	// against (asset shape matched at least one of the two controls).
	FixturesEvaluated int

	// FixturesMatched is the count of fixtures where at least one
	// overlap-path value resolved on the asset. A pair with high
	// FixturesEvaluated but low FixturesMatched signals catalog drift:
	// the pair is supposedly conflict-eligible but the corpus has no
	// asset state to back the claim.
	FixturesMatched int

	// CoEvaluations is the per-fixture verdict pairs, sorted lexicographically
	// by (FixturePath, AssetID) for deterministic downstream classification
	// and witness selection.
	CoEvaluations []CoEvaluation

	// EvaluationErrors records fixtures excluded due to evaluator errors.
	// Sorted by (FixturePath, AssetID, ControlID).
	EvaluationErrors []EvalError
}

// AgreementRate returns the fraction of co-evaluations where both
// controls returned the same verdict. Returns 0 when no co-evaluations
// were recorded; callers should branch on len(CoEvaluations) before
// interpreting the rate (a pair with zero co-evaluations is a coverage
// gap, not perfect disagreement).
func (e EvaluatedPair) AgreementRate() float64 {
	if len(e.CoEvaluations) == 0 {
		return 0
	}
	agree := 0
	for _, ce := range e.CoEvaluations {
		if ce.UnsafeA == ce.UnsafeB {
			agree++
		}
	}
	return float64(agree) / float64(len(e.CoEvaluations))
}

// EvaluatePairs runs each candidate pair against the fixture corpus
// using the supplied predicate evaluator. The catalog map must contain
// every ControlID referenced by pairs; a missing entry is a fail-loud
// programmer error, not a silent skip — the caller built the pairs
// from a catalog and is now passing a different one.
//
// This function does not classify conflicts. It produces the evidence
// the classifier (Node 3c) consumes. It is a pure function of its
// inputs: the same (pairs, catalog, fixtures, eval) always yields the
// same EvaluatedPair slice in the same order.
func EvaluatePairs(
	pairs []CandidatePair,
	catalog map[string]*policy.ControlDefinition,
	fixtures []FixtureAsset,
	eval policy.PredicateEval,
) ([]EvaluatedPair, error) {
	if eval == nil {
		return nil, errors.New("EvaluatePairs: nil predicate evaluator")
	}

	sortedFixtures := slices.Clone(fixtures)
	slices.SortFunc(sortedFixtures, func(a, b FixtureAsset) int {
		if c := compareString(a.FixturePath, b.FixturePath); c != 0 {
			return c
		}
		return compareString(string(a.Asset.ID), string(b.Asset.ID))
	})

	out := make([]EvaluatedPair, 0, len(pairs))

	for i := range pairs {
		pair := &pairs[i]
		ctlA, okA := catalog[pair.ControlA]
		ctlB, okB := catalog[pair.ControlB]
		if !okA || !okB {
			missing := pair.ControlA
			if okA {
				missing = pair.ControlB
			}
			return nil, fmt.Errorf(
				"EvaluatePairs: pair (%s, %s) references control %s not present in catalog",
				pair.ControlA, pair.ControlB, missing)
		}

		ep := EvaluatedPair{CandidatePair: *pair}

		for j := range sortedFixtures {
			fa := &sortedFixtures[j]
			ce, errs := evaluateOnFixture(pair, ctlA, ctlB, fa, eval)
			ep.EvaluationErrors = append(ep.EvaluationErrors, errs...)
			if ce == nil {
				continue
			}
			ep.FixturesEvaluated++
			if ce.ReadOverlap {
				ep.FixturesMatched++
			}
			ep.CoEvaluations = append(ep.CoEvaluations, *ce)
		}

		out = append(out, ep)
	}

	return out, nil
}

// evaluateOnFixture runs both controls against one fixture and returns
// the CoEvaluation, plus any per-control evaluator errors. Returns nil
// CoEvaluation if both controls errored — the fixture contributes
// neither a verdict pair nor a coverage tick.
func evaluateOnFixture(
	pair *CandidatePair,
	ctlA, ctlB *policy.ControlDefinition,
	fa *FixtureAsset,
	eval policy.PredicateEval,
) (*CoEvaluation, []EvalError) {
	var errs []EvalError

	unsafeA, errA := eval(*ctlA, fa.Asset, fa.Identities)
	if errA != nil {
		errs = append(errs, EvalError{
			FixturePath: fa.FixturePath,
			AssetID:     string(fa.Asset.ID),
			ControlID:   pair.ControlA,
			Err:         errA.Error(),
		})
	}
	unsafeB, errB := eval(*ctlB, fa.Asset, fa.Identities)
	if errB != nil {
		errs = append(errs, EvalError{
			FixturePath: fa.FixturePath,
			AssetID:     string(fa.Asset.ID),
			ControlID:   pair.ControlB,
			Err:         errB.Error(),
		})
	}
	if errA != nil || errB != nil {
		return nil, errs
	}

	allPaths := unionSorted(pair.DepsA, pair.DepsB)
	pathVals, _ := readPaths(fa.Asset.Map(), allPaths)
	_, readOverlap := readPaths(fa.Asset.Map(), pair.Overlap)

	return &CoEvaluation{
		FixturePath: fa.FixturePath,
		AssetID:     string(fa.Asset.ID),
		AssetType:   fa.Asset.Type,
		UnsafeA:     unsafeA,
		UnsafeB:     unsafeB,
		PathValues:  pathVals,
		ReadOverlap: readOverlap,
	}, errs
}

// unionSorted returns the sorted union of two lex-sorted dependency
// path lists. Inputs are assumed sorted (the deps extractor guarantees
// this). Order matches the schema's expectation that path lists in the
// report are lex-sorted.
func unionSorted(a, b []string) []string {
	out := make([]string, 0, len(a)+len(b))
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		switch {
		case a[i] == b[j]:
			out = append(out, a[i])
			i++
			j++
		case a[i] < b[j]:
			out = append(out, a[i])
			i++
		default:
			out = append(out, b[j])
			j++
		}
	}
	out = append(out, a[i:]...)
	out = append(out, b[j:]...)
	return out
}

// readPaths walks each dotted path against root and returns the values
// found, keyed by path. Missing paths are absent from the map. The
// second return is true if at least one path resolved.
//
// Path syntax matches the dependency extractor's output: dot-separated
// segments, optional `[*]` for "any element of an array." For arrays,
// the first matching element's value is recorded — the witness only
// needs to demonstrate the disagreement, not enumerate every element.
func readPaths(root map[string]any, paths []string) (map[string]any, bool) {
	if len(paths) == 0 {
		return nil, false
	}
	out := make(map[string]any, len(paths))
	for _, p := range paths {
		v, ok := walkPath(root, p)
		if ok {
			out[p] = v
		}
	}
	if len(out) == 0 {
		return nil, false
	}
	return out, true
}

// walkPath resolves a single dotted path. Returns (value, true) if the
// full path resolved, (nil, false) otherwise. Array index segments
// `[*]` and explicit `[N]` are both supported; `[*]` returns the first
// element. Pure helper — no side effects, no allocations beyond the
// returned value.
func walkPath(root any, path string) (any, bool) {
	cur := root
	for seg := range strings.SplitSeq(path, ".") {
		if cur == nil {
			return nil, false
		}
		// Strip and apply array indexing on segments shaped like "name[*]" or "name[3]".
		field, idx, hasIdx := splitArrayIndex(seg)
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		next, ok := m[field]
		if !ok {
			return nil, false
		}
		if hasIdx {
			arr, ok := next.([]any)
			if !ok || len(arr) == 0 {
				return nil, false
			}
			if idx < 0 || idx >= len(arr) {
				next = arr[0]
			} else {
				next = arr[idx]
			}
		}
		cur = next
	}
	return cur, true
}

// splitArrayIndex parses "field[*]" or "field[3]" into (field, idx, true).
// Returns (seg, 0, false) when the segment has no indexer.
// Index -1 represents `[*]` (any element — caller chooses first).
func splitArrayIndex(seg string) (string, int, bool) {
	open := strings.IndexByte(seg, '[')
	if open < 0 || !strings.HasSuffix(seg, "]") {
		return seg, 0, false
	}
	field := seg[:open]
	body := seg[open+1 : len(seg)-1]
	if body == "*" {
		return field, -1, true
	}
	n, err := strconv.Atoi(body)
	if err != nil {
		return seg, 0, false
	}
	return field, n, true
}
