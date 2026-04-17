package conflict

import (
	"errors"
	"testing"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

// stubEval is a minimal predicate evaluator that returns a verdict
// based on a per-control closure. Unit tests construct it by ID so the
// evaluation logic can be exercised without compiling real CEL.
type stubEval struct {
	verdicts map[string]func(asset.Asset) (bool, error)
}

func (s stubEval) eval() policy.PredicateEval {
	return func(ctl policy.ControlDefinition, a asset.Asset, _ []asset.CloudIdentity) (bool, error) {
		fn, ok := s.verdicts[string(ctl.ID)]
		if !ok {
			return false, nil
		}
		return fn(a)
	}
}

func mkAsset(id string, props map[string]any) asset.Asset {
	return asset.Asset{
		ID:         asset.ID(id),
		Type:       kernel.AssetType("aws_s3_bucket"),
		Vendor:     kernel.Vendor("aws"),
		Properties: props,
	}
}

// mkCatalog builds a tiny catalog map keyed by the IDs the evaluator
// closure expects. The ControlDefinition body is irrelevant — the stub
// evaluator dispatches on ID, not on predicate shape.
func mkCatalog(ids ...string) map[string]*policy.ControlDefinition {
	out := make(map[string]*policy.ControlDefinition, len(ids))
	for _, id := range ids {
		out[id] = &policy.ControlDefinition{ID: kernel.ControlID(id)}
	}
	return out
}

func mkPair(a, b string, overlap ...string) CandidatePair {
	return CandidatePair{
		ControlA: a,
		ControlB: b,
		// In production DepsA and DepsB always contain Overlap. The
		// helper mirrors that so PathValues collection (which walks
		// DepsA ∪ DepsB) covers the overlap paths the test asserts on.
		DepsA:    overlap,
		DepsB:    overlap,
		Overlap:  overlap,
		Relation: RelationOverlapping,
	}
}

func TestEvaluatePairs_NilEvaluatorRejected(t *testing.T) {
	_, err := EvaluatePairs(nil, nil, nil, nil)
	if err == nil {
		t.Fatal("expected error for nil evaluator, got nil")
	}
}

func TestEvaluatePairs_MissingCatalogEntryFailsLoud(t *testing.T) {
	pairs := []CandidatePair{mkPair("CTL.A", "CTL.B")}
	catalog := mkCatalog("CTL.A") // CTL.B intentionally missing
	stub := stubEval{verdicts: map[string]func(asset.Asset) (bool, error){
		"CTL.A": func(asset.Asset) (bool, error) { return false, nil },
	}}
	_, err := EvaluatePairs(pairs, catalog, nil, stub.eval())
	if err == nil {
		t.Fatal("expected error for missing catalog entry, got nil")
	}
}

func TestEvaluatePairs_AgreementAndDisagreementCounted(t *testing.T) {
	// Two assets, two controls. fixture-1: both UNSAFE (agree).
	// fixture-2: A unsafe, B safe (disagree).
	pairs := []CandidatePair{mkPair("CTL.A", "CTL.B", "properties.shared")}
	catalog := mkCatalog("CTL.A", "CTL.B")
	stub := stubEval{verdicts: map[string]func(asset.Asset) (bool, error){
		"CTL.A": func(a asset.Asset) (bool, error) { return true, nil },
		"CTL.B": func(a asset.Asset) (bool, error) {
			return a.ID == "asset-1", nil
		},
	}}
	fixtures := []FixtureAsset{
		{FixturePath: "fix-1.json", Asset: mkAsset("asset-1", map[string]any{"properties": map[string]any{"shared": true}})},
		{FixturePath: "fix-2.json", Asset: mkAsset("asset-2", map[string]any{"properties": map[string]any{"shared": false}})},
	}

	results, err := EvaluatePairs(pairs, catalog, fixtures, stub.eval())
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	r := results[0]
	if r.FixturesEvaluated != 2 {
		t.Errorf("FixturesEvaluated = %d, want 2", r.FixturesEvaluated)
	}
	if r.FixturesMatched != 2 {
		t.Errorf("FixturesMatched = %d, want 2", r.FixturesMatched)
	}
	if got := r.AgreementRate(); got != 0.5 {
		t.Errorf("AgreementRate = %f, want 0.5", got)
	}
}

func TestEvaluatePairs_MissingOverlapPathDoesNotCountAsMatched(t *testing.T) {
	// Asset properties have no value at the overlap path. The evaluation
	// still happens (controls return verdicts based on whatever they
	// see), but FixturesMatched should not increment.
	pairs := []CandidatePair{mkPair("CTL.A", "CTL.B", "properties.storage.access.public_read")}
	catalog := mkCatalog("CTL.A", "CTL.B")
	stub := stubEval{verdicts: map[string]func(asset.Asset) (bool, error){
		"CTL.A": func(asset.Asset) (bool, error) { return false, nil },
		"CTL.B": func(asset.Asset) (bool, error) { return false, nil },
	}}
	fixtures := []FixtureAsset{
		{FixturePath: "fix.json", Asset: mkAsset("a1", map[string]any{"properties": map[string]any{"unrelated": 1}})},
	}

	results, err := EvaluatePairs(pairs, catalog, fixtures, stub.eval())
	if err != nil {
		t.Fatal(err)
	}
	r := results[0]
	if r.FixturesEvaluated != 1 {
		t.Errorf("FixturesEvaluated = %d, want 1", r.FixturesEvaluated)
	}
	if r.FixturesMatched != 0 {
		t.Errorf("FixturesMatched = %d, want 0 (no overlap value resolved)", r.FixturesMatched)
	}
}

func TestEvaluatePairs_PathValuesCapturedForWitness(t *testing.T) {
	pairs := []CandidatePair{mkPair("CTL.A", "CTL.B", "properties.storage.access.public_read")}
	catalog := mkCatalog("CTL.A", "CTL.B")
	stub := stubEval{verdicts: map[string]func(asset.Asset) (bool, error){
		"CTL.A": func(asset.Asset) (bool, error) { return true, nil },
		"CTL.B": func(asset.Asset) (bool, error) { return false, nil },
	}}
	fixtures := []FixtureAsset{
		{FixturePath: "fix.json", Asset: mkAsset("a1", map[string]any{
			"properties": map[string]any{
				"storage": map[string]any{"access": map[string]any{"public_read": true}},
			},
		})},
	}

	results, _ := EvaluatePairs(pairs, catalog, fixtures, stub.eval())
	co := results[0].CoEvaluations[0]
	if !co.UnsafeA || co.UnsafeB {
		t.Errorf("verdicts: UnsafeA=%v UnsafeB=%v, want true/false", co.UnsafeA, co.UnsafeB)
	}
	v, ok := co.PathValues["properties.storage.access.public_read"]
	if !ok {
		t.Fatalf("PathValues missing public_read; got %v", co.PathValues)
	}
	if b, _ := v.(bool); !b {
		t.Errorf("PathValues[public_read] = %v, want true", v)
	}
}

func TestEvaluatePairs_DeterministicOrdering(t *testing.T) {
	// Fixtures supplied out of lexicographic order; CoEvaluations must
	// come back sorted by (FixturePath, AssetID).
	pairs := []CandidatePair{mkPair("CTL.A", "CTL.B", "properties.shared")}
	catalog := mkCatalog("CTL.A", "CTL.B")
	stub := stubEval{verdicts: map[string]func(asset.Asset) (bool, error){
		"CTL.A": func(asset.Asset) (bool, error) { return false, nil },
		"CTL.B": func(asset.Asset) (bool, error) { return false, nil },
	}}
	fixtures := []FixtureAsset{
		{FixturePath: "z.json", Asset: mkAsset("a", map[string]any{"properties": map[string]any{"shared": 1}})},
		{FixturePath: "a.json", Asset: mkAsset("z", map[string]any{"properties": map[string]any{"shared": 1}})},
		{FixturePath: "a.json", Asset: mkAsset("a", map[string]any{"properties": map[string]any{"shared": 1}})},
	}

	results, _ := EvaluatePairs(pairs, catalog, fixtures, stub.eval())
	got := results[0].CoEvaluations
	want := []struct{ path, id string }{
		{"a.json", "a"},
		{"a.json", "z"},
		{"z.json", "a"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d co-evals, want %d", len(got), len(want))
	}
	for i, w := range want {
		if got[i].FixturePath != w.path || got[i].AssetID != w.id {
			t.Errorf("co[%d] = (%s,%s), want (%s,%s)", i, got[i].FixturePath, got[i].AssetID, w.path, w.id)
		}
	}
}

func TestEvaluatePairs_EvaluatorErrorRecordedAndFixtureSkipped(t *testing.T) {
	pairs := []CandidatePair{mkPair("CTL.A", "CTL.B", "properties.shared")}
	catalog := mkCatalog("CTL.A", "CTL.B")
	stub := stubEval{verdicts: map[string]func(asset.Asset) (bool, error){
		"CTL.A": func(asset.Asset) (bool, error) { return false, errors.New("boom") },
		"CTL.B": func(asset.Asset) (bool, error) { return false, nil },
	}}
	fixtures := []FixtureAsset{
		{FixturePath: "fix.json", Asset: mkAsset("a1", map[string]any{"properties": map[string]any{"shared": 1}})},
	}

	results, err := EvaluatePairs(pairs, catalog, fixtures, stub.eval())
	if err != nil {
		t.Fatalf("EvaluatePairs returned err: %v", err)
	}
	r := results[0]
	if r.FixturesEvaluated != 0 {
		t.Errorf("FixturesEvaluated = %d, want 0 (evaluator error excludes fixture)", r.FixturesEvaluated)
	}
	if len(r.EvaluationErrors) != 1 {
		t.Fatalf("EvaluationErrors len = %d, want 1", len(r.EvaluationErrors))
	}
	if r.EvaluationErrors[0].ControlID != "CTL.A" {
		t.Errorf("EvaluationErrors[0].ControlID = %s, want CTL.A", r.EvaluationErrors[0].ControlID)
	}
}

func TestAgreementRate_NoCoEvaluationsReturnsZero(t *testing.T) {
	ep := EvaluatedPair{}
	if r := ep.AgreementRate(); r != 0 {
		t.Errorf("AgreementRate on empty = %f, want 0", r)
	}
}

func TestEvaluatePairs_ArrayWildcardPath(t *testing.T) {
	// Overlap path is "properties.identity.policies.attached[*].arn".
	// Fixture asset has the array populated; readPaths should resolve
	// the first element's arn.
	pairs := []CandidatePair{mkPair("CTL.A", "CTL.B", "properties.identity.policies.attached[*].arn")}
	catalog := mkCatalog("CTL.A", "CTL.B")
	stub := stubEval{verdicts: map[string]func(asset.Asset) (bool, error){
		"CTL.A": func(asset.Asset) (bool, error) { return true, nil },
		"CTL.B": func(asset.Asset) (bool, error) { return true, nil },
	}}
	fixtures := []FixtureAsset{
		{FixturePath: "fix.json", Asset: mkAsset("role-1", map[string]any{
			"properties": map[string]any{
				"identity": map[string]any{
					"policies": map[string]any{
						"attached": []any{
							map[string]any{"arn": "arn:aws:iam::aws:policy/AdministratorAccess"},
						},
					},
				},
			},
		})},
	}

	results, _ := EvaluatePairs(pairs, catalog, fixtures, stub.eval())
	r := results[0]
	if r.FixturesMatched != 1 {
		t.Fatalf("FixturesMatched = %d, want 1 (wildcard array path should resolve)", r.FixturesMatched)
	}
	v := r.CoEvaluations[0].PathValues["properties.identity.policies.attached[*].arn"]
	if v != "arn:aws:iam::aws:policy/AdministratorAccess" {
		t.Errorf("PathValues at wildcard path = %v, want admin arn", v)
	}
}
