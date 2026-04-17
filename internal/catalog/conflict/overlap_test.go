package conflict

import (
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/predicate"
)

// buildControl constructs a minimal ControlDefinition whose predicate
// reads each of the supplied property paths via a single any-rule per
// path. The predicate itself is irrelevant for overlap analysis —
// only the extracted dependency set matters.
func buildControl(id string, paths ...string) policy.ControlDefinition {
	rules := make([]policy.PredicateRule, 0, len(paths))
	for _, p := range paths {
		rules = append(rules, policy.PredicateRule{
			Field: predicate.NewFieldPath(p),
			Op:    predicate.OpEq,
		})
	}
	return policy.ControlDefinition{
		ID:              kernel.ControlID(id),
		UnsafePredicate: policy.UnsafePredicate{Any: rules},
	}
}

func TestAnalyzeOverlap_EmptyOverlapSkipped(t *testing.T) {
	catalog := []policy.ControlDefinition{
		buildControl("CTL.A", "properties.x.a"),
		buildControl("CTL.B", "properties.y.b"),
	}
	pairs, stats, err := AnalyzeOverlap(catalog)
	if err != nil {
		t.Fatal(err)
	}
	if len(pairs) != 0 {
		t.Fatalf("expected 0 candidate pairs, got %d: %+v", len(pairs), pairs)
	}
	if stats.TotalPairs != 1 {
		t.Errorf("TotalPairs = %d, want 1", stats.TotalPairs)
	}
	if stats.CandidatePairs != 0 {
		t.Errorf("CandidatePairs = %d, want 0", stats.CandidatePairs)
	}
}

func TestAnalyzeOverlap_Identical(t *testing.T) {
	catalog := []policy.ControlDefinition{
		buildControl("CTL.A", "properties.storage.access.public_read"),
		buildControl("CTL.B", "properties.storage.access.public_read"),
	}
	pairs, stats, err := AnalyzeOverlap(catalog)
	if err != nil {
		t.Fatal(err)
	}
	if len(pairs) != 1 {
		t.Fatalf("expected 1 pair, got %d", len(pairs))
	}
	if pairs[0].Relation != RelationIdentical {
		t.Errorf("Relation = %s, want IDENTICAL", pairs[0].Relation)
	}
	if got := stats.ByRelation[RelationIdentical]; got != 1 {
		t.Errorf("ByRelation[IDENTICAL] = %d, want 1", got)
	}
}

func TestAnalyzeOverlap_Subset(t *testing.T) {
	catalog := []policy.ControlDefinition{
		buildControl("CTL.NARROW",
			"properties.storage.access.public_read",
		),
		buildControl("CTL.BROAD",
			"properties.storage.access.public_read",
			"properties.storage.access.public_list",
		),
	}
	pairs, _, err := AnalyzeOverlap(catalog)
	if err != nil {
		t.Fatal(err)
	}
	if len(pairs) != 1 {
		t.Fatalf("expected 1 pair, got %d", len(pairs))
	}
	p := pairs[0]
	if p.Relation != RelationSubset {
		t.Errorf("Relation = %s, want SUBSET", p.Relation)
	}
	if p.Narrower != "CTL.NARROW" || p.Broader != "CTL.BROAD" {
		t.Errorf("Narrower=%s Broader=%s, want CTL.NARROW / CTL.BROAD", p.Narrower, p.Broader)
	}
}

func TestAnalyzeOverlap_Overlapping(t *testing.T) {
	catalog := []policy.ControlDefinition{
		buildControl("CTL.A",
			"properties.x.shared",
			"properties.x.a_only",
		),
		buildControl("CTL.B",
			"properties.x.shared",
			"properties.x.b_only",
		),
	}
	pairs, _, err := AnalyzeOverlap(catalog)
	if err != nil {
		t.Fatal(err)
	}
	if len(pairs) != 1 {
		t.Fatalf("expected 1 pair, got %d", len(pairs))
	}
	if pairs[0].Relation != RelationOverlapping {
		t.Errorf("Relation = %s, want OVERLAPPING", pairs[0].Relation)
	}
	if len(pairs[0].Overlap) != 1 || pairs[0].Overlap[0] != "properties.x.shared" {
		t.Errorf("Overlap = %v, want [properties.x.shared]", pairs[0].Overlap)
	}
	if pairs[0].Narrower != "" || pairs[0].Broader != "" {
		t.Errorf("Narrower/Broader should be empty for OVERLAPPING, got %q/%q", pairs[0].Narrower, pairs[0].Broader)
	}
}

func TestAnalyzeOverlap_PairsSortedDeterministic(t *testing.T) {
	catalog := []policy.ControlDefinition{
		buildControl("CTL.C", "properties.shared"),
		buildControl("CTL.A", "properties.shared"),
		buildControl("CTL.B", "properties.shared"),
	}
	pairs, _, err := AnalyzeOverlap(catalog)
	if err != nil {
		t.Fatal(err)
	}
	if len(pairs) != 3 {
		t.Fatalf("expected 3 pairs, got %d", len(pairs))
	}
	expected := [][2]string{
		{"CTL.A", "CTL.B"},
		{"CTL.A", "CTL.C"},
		{"CTL.B", "CTL.C"},
	}
	for i, exp := range expected {
		if pairs[i].ControlA != exp[0] || pairs[i].ControlB != exp[1] {
			t.Errorf("pairs[%d] = (%s, %s), want (%s, %s)",
				i, pairs[i].ControlA, pairs[i].ControlB, exp[0], exp[1])
		}
	}
}

func TestAnalyzeOverlap_AliasedControlSkipped(t *testing.T) {
	catalog := []policy.ControlDefinition{
		buildControl("CTL.REGULAR", "properties.shared"),
		{
			ID:                   kernel.ControlID("CTL.ALIASED"),
			UnsafePredicateAlias: "some-alias",
		},
	}
	pairs, stats, err := AnalyzeOverlap(catalog)
	if err != nil {
		t.Fatal(err)
	}
	if len(pairs) != 0 {
		t.Errorf("expected 0 pairs (aliased control skipped), got %d", len(pairs))
	}
	if len(stats.SkippedAliased) != 1 || stats.SkippedAliased[0] != "CTL.ALIASED" {
		t.Errorf("SkippedAliased = %v, want [CTL.ALIASED]", stats.SkippedAliased)
	}
}

func TestAnalyzeOverlap_EmptyDepsControlSkipped(t *testing.T) {
	catalog := []policy.ControlDefinition{
		buildControl("CTL.REGULAR", "properties.shared"),
		{ID: kernel.ControlID("CTL.EMPTY")}, // no predicate rules
	}
	pairs, stats, err := AnalyzeOverlap(catalog)
	if err != nil {
		t.Fatal(err)
	}
	if len(pairs) != 0 {
		t.Errorf("expected 0 pairs (empty-deps control skipped), got %d", len(pairs))
	}
	if len(stats.SkippedEmptyDeps) != 1 || stats.SkippedEmptyDeps[0] != "CTL.EMPTY" {
		t.Errorf("SkippedEmptyDeps = %v, want [CTL.EMPTY]", stats.SkippedEmptyDeps)
	}
}

// TestAnalyzeOverlap_MetadataOnlyOverlapDiscarded pins the routing-vs-evaluation
// rule (PRECEDENCE.md §5): a pair whose only overlap path is the asset-class
// router `type` is structurally not a conflict — each control reads `type`
// to gate which asset class it applies to, not to evaluate the asset's
// security state. Iteration 3.6 added the metadata denylist after Node 3f
// surfaced 233 false-positive CONTRADICTIONs, every one of which had
// `[type]` as its only shared dependency.
func TestAnalyzeOverlap_MetadataOnlyOverlapDiscarded(t *testing.T) {
	catalog := []policy.ControlDefinition{
		buildControl("CTL.APISERVER", "type", "properties.apiserver.anonymous_auth"),
		buildControl("CTL.ETCD", "type", "properties.etcd.client_tls"),
	}
	pairs, stats, err := AnalyzeOverlap(catalog)
	if err != nil {
		t.Fatal(err)
	}
	if len(pairs) != 0 {
		t.Fatalf("expected 0 candidate pairs (metadata-only overlap discarded), got %d: %+v", len(pairs), pairs)
	}
	if stats.SkippedMetadataOnly != 1 {
		t.Errorf("SkippedMetadataOnly = %d, want 1", stats.SkippedMetadataOnly)
	}
}

// TestAnalyzeOverlap_MetadataPlusSubstantiveOverlapKept verifies the filter
// strips metadata paths from Overlap but keeps the pair when at least one
// substantive path remains. Without this, a `[type, X]` overlap would be
// indistinguishable from a `[type]`-only overlap and we'd lose the genuine
// X-overlap signal along with the noise.
func TestAnalyzeOverlap_MetadataPlusSubstantiveOverlapKept(t *testing.T) {
	catalog := []policy.ControlDefinition{
		buildControl("CTL.A", "type", "properties.shared.path"),
		buildControl("CTL.B", "type", "properties.shared.path"),
	}
	pairs, _, err := AnalyzeOverlap(catalog)
	if err != nil {
		t.Fatal(err)
	}
	if len(pairs) != 1 {
		t.Fatalf("expected 1 pair (substantive overlap survives), got %d", len(pairs))
	}
	want := []string{"properties.shared.path"}
	if len(pairs[0].Overlap) != 1 || pairs[0].Overlap[0] != want[0] {
		t.Errorf("Overlap = %v, want %v (metadata path `type` should be filtered)", pairs[0].Overlap, want)
	}
}

func TestAnalyzeOverlap_CandidateRatioDiagnostic(t *testing.T) {
	// 4 controls all sharing a common path — maximum candidate density.
	// Expected: C(4,2) = 6 pairs, all candidates, ratio = 1.0.
	catalog := []policy.ControlDefinition{
		buildControl("CTL.A", "properties.shared"),
		buildControl("CTL.B", "properties.shared"),
		buildControl("CTL.C", "properties.shared"),
		buildControl("CTL.D", "properties.shared"),
	}
	_, stats, err := AnalyzeOverlap(catalog)
	if err != nil {
		t.Fatal(err)
	}
	if stats.TotalPairs != 6 || stats.CandidatePairs != 6 {
		t.Fatalf("TotalPairs=%d CandidatePairs=%d, want 6/6", stats.TotalPairs, stats.CandidatePairs)
	}
	if ratio := stats.CandidateRatio(); ratio != 1.0 {
		t.Errorf("CandidateRatio = %f, want 1.0", ratio)
	}
}
