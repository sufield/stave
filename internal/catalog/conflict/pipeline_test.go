package conflict

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

// Pipeline tests for Node 3e. Each test instantiates a synthetic
// mini-catalog and walks it end-to-end through the analyzer:
//
//	EvaluatePairs (3b) → Classify (3c) → BuildReport (3d)
//
// The point is to force concrete examples of every taxonomy category
// out the other end. If a category is hard to instantiate cleanly, the
// taxonomy itself — not just the code — needs sharpening.
//
// AnalyzeOverlap (Node 3a) is intentionally bypassed: it requires real
// CEL predicates so the deps extractor can run. Pair construction here
// is synthetic so each test can isolate one Relation/coverage shape.

// pipelineCase wires a small fixture corpus and a stubbed evaluator
// through the pipeline and returns the rendered report. Tests assert
// on the report shape — that is the contract downstream apps consume.
type pipelineCase struct {
	pair      CandidatePair
	metadata  map[string]ControlMetadata
	stub      stubEval
	fixtures  []FixtureAsset
	assertion func(t *testing.T, r Report, classified []ClassifiedPair)
}

func runPipeline(t *testing.T, tc pipelineCase) {
	t.Helper()

	cat := mkCatalog(tc.pair.ControlA, tc.pair.ControlB)
	evaluated, err := EvaluatePairs([]CandidatePair{tc.pair}, cat, tc.fixtures, tc.stub.eval())
	if err != nil {
		t.Fatalf("EvaluatePairs: %v", err)
	}
	classified, err := Classify(evaluated, tc.metadata)
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	r := BuildReport(ReportInputs{
		Classified:           classified,
		CatalogVersion:       "synth-cat",
		FixtureCorpusVersion: "synth-corp",
		StaveVersion:         "0.1.0-test",
		GeneratedAt:          time.Date(2026, 4, 17, 12, 0, 0, 0, time.UTC),
	})
	roundtripValidate(t, r)
	tc.assertion(t, r, classified)
}

// mkAssetTyped builds an asset with an explicit asset class — needed
// for MISSING_ASSET_CLASS_GUARD scenarios that require diversity in
// disagreement witnesses. Properties are nested under "properties" so
// dotted paths like "properties.public" resolve via the deps walker.
func mkAssetTyped(id, kind string, props map[string]any) asset.Asset {
	return asset.Asset{
		ID:         asset.ID(id),
		Type:       kernel.AssetType(kind),
		Vendor:     kernel.Vendor("aws"),
		Properties: map[string]any{"properties": props},
	}
}

// propsAt extracts the nested properties map from an asset constructed
// by mkAssetTyped or mkAssetNested. Stub evaluators use this so they
// can read the same flat shape the test author wrote.
func propsAt(a asset.Asset) map[string]any {
	p, _ := a.Properties["properties"].(map[string]any)
	return p
}

// mkAssetNested wraps mkAsset so paths like "properties.public" resolve.
func mkAssetNested(id string, props map[string]any) asset.Asset {
	return asset.Asset{
		ID:         asset.ID(id),
		Type:       kernel.AssetType("aws_s3_bucket"),
		Vendor:     kernel.Vendor("aws"),
		Properties: map[string]any{"properties": props},
	}
}

// TestPipeline_Redundancy: two controls with identical deps and identical
// metadata, agreeing on every fixture. Out the other end: one
// REDUNDANCY pair with shared_compliance_hash and shared_remediation_hash
// populated. This is the hygiene case — catalog authors review and
// merge.
func TestPipeline_Redundancy(t *testing.T) {
	pair := CandidatePair{
		ControlA: "CTL.RED.A", ControlB: "CTL.RED.B",
		DepsA: []string{"properties.public"}, DepsB: []string{"properties.public"},
		Overlap:  []string{"properties.public"},
		Relation: RelationIdentical,
	}
	mdA, mdB := pcMeta(pair.ControlA, pair.ControlB)
	tc := pipelineCase{
		pair: pair,
		metadata: map[string]ControlMetadata{
			pair.ControlA: mdA,
			pair.ControlB: mdB,
		},
		stub: stubEval{verdicts: map[string]func(asset.Asset) (bool, error){
			pair.ControlA: func(a asset.Asset) (bool, error) {
				return propsAt(a)["public"] == true, nil
			},
			pair.ControlB: func(a asset.Asset) (bool, error) {
				return propsAt(a)["public"] == true, nil
			},
		}},
		fixtures: []FixtureAsset{
			{FixturePath: "f1.json", Asset: mkAssetNested("a1", map[string]any{"public": true})},
			{FixturePath: "f2.json", Asset: mkAssetNested("a2", map[string]any{"public": false})},
		},
		assertion: func(t *testing.T, r Report, _ []ClassifiedPair) {
			if len(r.Pairs) != 1 || r.Pairs[0].Category != CategoryRedundancy {
				t.Fatalf("want 1 REDUNDANCY pair, got %+v", r.Pairs)
			}
			pl := r.Pairs[0].Payload.(RedundancyPayload)
			if pl.SharedComplianceHash == "" || pl.SharedRemediationHash == "" {
				t.Errorf("hashes empty: %+v", pl)
			}
			if pl.SharedAttackStage != "exfiltration" {
				t.Errorf("attack_stage = %q, want exfiltration", pl.SharedAttackStage)
			}
		},
	}
	runPipeline(t, tc)
}

// TestPipeline_ContradictionLogicBug: two controls with IDENTICAL deps
// disagreeing on a single asset class. The classifier returns
// LOGIC_BUG (not MISSING_GUARD) because the disagreements do not span
// asset classes — both authors encoded the same shared input but with
// genuinely contradictory rules.
func TestPipeline_ContradictionLogicBug(t *testing.T) {
	pair := CandidatePair{
		ControlA: "CTL.LB.A", ControlB: "CTL.LB.B",
		DepsA: []string{"properties.public"}, DepsB: []string{"properties.public"},
		Overlap:  []string{"properties.public"},
		Relation: RelationIdentical,
	}
	mdA, mdB := pcMeta(pair.ControlA, pair.ControlB)
	tc := pipelineCase{
		pair:     pair,
		metadata: map[string]ControlMetadata{pair.ControlA: mdA, pair.ControlB: mdB},
		stub: stubEval{verdicts: map[string]func(asset.Asset) (bool, error){
			pair.ControlA: func(a asset.Asset) (bool, error) { return propsAt(a)["public"] == true, nil },
			pair.ControlB: func(a asset.Asset) (bool, error) { return propsAt(a)["public"] == false, nil },
		}},
		fixtures: []FixtureAsset{
			{FixturePath: "buckets/f1.json", Asset: mkAssetTyped("b1", "aws_s3_bucket", map[string]any{"public": true})},
			{FixturePath: "buckets/f2.json", Asset: mkAssetTyped("b2", "aws_s3_bucket", map[string]any{"public": false})},
		},
		assertion: func(t *testing.T, r Report, _ []ClassifiedPair) {
			if len(r.Pairs) != 1 {
				t.Fatalf("want 1 pair, got %d", len(r.Pairs))
			}
			if r.Pairs[0].Category != CategoryContradiction {
				t.Fatalf("category = %s, want CONTRADICTION", r.Pairs[0].Category)
			}
			pl := r.Pairs[0].Payload.(ContradictionPayload)
			if pl.Subcategory != SubcategoryLogicBug {
				t.Errorf("subcategory = %s, want LOGIC_BUG", pl.Subcategory)
			}
			if len(pl.DisagreementWitnesses) != 2 {
				t.Errorf("witnesses = %d, want 2", len(pl.DisagreementWitnesses))
			}
			// observed_values must carry the overlap-path value.
			for _, w := range pl.DisagreementWitnesses {
				if _, ok := w.ObservedValues["properties.public"]; !ok {
					t.Errorf("witness %s missing observed_values[properties.public]", w.AssetID)
				}
			}
		},
	}
	runPipeline(t, tc)
}

// TestPipeline_ContradictionMissingGuard: two controls disagree on
// fixtures that span more than one asset class. The classifier returns
// MISSING_ASSET_CLASS_GUARD.
//
// Concrete narrative: control A flags any asset with encryption=false;
// control B flags only buckets with encryption=false. Disagreements
// surface on EBS volumes and snapshots — every non-bucket case.
//
// The taxonomy challenge the user asked about: the classifier infers
// "missing guard" from witness-class diversity, NOT from inspecting
// the predicates for guard logic. So this rule fires even when only
// ONE control is "actually" missing a guard — as is the case here. In
// this scenario the colloquial reading still holds (control A IS too
// broad, and adding a type guard IS the fix), so the rule is sound but
// the schema's description ("neither guards") is overly specific.
func TestPipeline_ContradictionMissingGuard(t *testing.T) {
	pair := CandidatePair{
		ControlA: "CTL.MG.A", ControlB: "CTL.MG.B",
		DepsA:    []string{"properties.encryption_at_rest"},
		DepsB:    []string{"properties.encryption_at_rest"},
		Overlap:  []string{"properties.encryption_at_rest"},
		Relation: RelationIdentical,
	}
	mdA, mdB := pcMeta(pair.ControlA, pair.ControlB)
	tc := pipelineCase{
		pair:     pair,
		metadata: map[string]ControlMetadata{pair.ControlA: mdA, pair.ControlB: mdB},
		stub: stubEval{verdicts: map[string]func(asset.Asset) (bool, error){
			// A: universal "encryption disabled is unsafe"
			pair.ControlA: func(a asset.Asset) (bool, error) {
				return propsAt(a)["encryption_at_rest"] == false, nil
			},
			// B: scoped to S3 buckets only — properly guarded
			pair.ControlB: func(a asset.Asset) (bool, error) {
				if a.Type != kernel.AssetType("aws_s3_bucket") {
					return false, nil
				}
				return propsAt(a)["encryption_at_rest"] == false, nil
			},
		}},
		fixtures: []FixtureAsset{
			{FixturePath: "buckets/b.json", Asset: mkAssetTyped("b1", "aws_s3_bucket", map[string]any{"encryption_at_rest": false})},  // both fire
			{FixturePath: "volumes/v.json", Asset: mkAssetTyped("v1", "aws_ebs_volume", map[string]any{"encryption_at_rest": false})}, // A fires, B passes
			{FixturePath: "snapshots/s.json", Asset: mkAssetTyped("s1", "aws_ebs_snapshot", map[string]any{"encryption_at_rest": false})},
		},
		assertion: func(t *testing.T, r Report, _ []ClassifiedPair) {
			if len(r.Pairs) != 1 {
				t.Fatalf("want 1 pair, got %d", len(r.Pairs))
			}
			pl, ok := r.Pairs[0].Payload.(ContradictionPayload)
			if !ok {
				t.Fatalf("payload type = %T", r.Pairs[0].Payload)
			}
			if pl.Subcategory != SubcategoryMissingAssetClassGuard {
				t.Errorf("subcategory = %s, want MISSING_ASSET_CLASS_GUARD", pl.Subcategory)
			}
			// Witnesses should be on volume + snapshot (the disagreement
			// fixtures), not on bucket (where they agree).
			seen := map[string]bool{}
			for _, w := range pl.DisagreementWitnesses {
				seen[w.AssetID] = true
			}
			if !seen["v1"] || !seen["s1"] {
				t.Errorf("expected witnesses on v1 and s1; got %v", seen)
			}
			if seen["b1"] {
				t.Errorf("bucket b1 (agreement fixture) appeared as witness")
			}
		},
	}
	runPipeline(t, tc)
}

// TestPipeline_EmpiricalSubsumption: SUBSET deps, narrower's VIOLATIONs
// imply broader's VIOLATIONs across the corpus. Classifier returns
// EMPIRICAL_SUBSUMPTION; renderer emits dependency_delta with the
// broader-only paths.
func TestPipeline_EmpiricalSubsumption(t *testing.T) {
	pair := CandidatePair{
		ControlA: "CTL.NARROW", ControlB: "CTL.WIDE",
		DepsA:    []string{"properties.public"},
		DepsB:    []string{"properties.public", "properties.policy"},
		Overlap:  []string{"properties.public"},
		Relation: RelationSubset,
		Narrower: "CTL.NARROW", Broader: "CTL.WIDE",
	}
	mdA, mdB := pcMeta(pair.ControlA, pair.ControlB)
	tc := pipelineCase{
		pair:     pair,
		metadata: map[string]ControlMetadata{pair.ControlA: mdA, pair.ControlB: mdB},
		stub: stubEval{verdicts: map[string]func(asset.Asset) (bool, error){
			// Narrower: VIOLATION when public=true.
			pair.ControlA: func(a asset.Asset) (bool, error) { return propsAt(a)["public"] == true, nil },
			// Broader: VIOLATION when public=true OR policy="permissive".
			pair.ControlB: func(a asset.Asset) (bool, error) {
				return propsAt(a)["public"] == true || propsAt(a)["policy"] == "permissive", nil
			},
		}},
		fixtures: []FixtureAsset{
			// public=true → both fire (consistent with subsumption)
			{FixturePath: "f1.json", Asset: mkAssetNested("a1", map[string]any{"public": true, "policy": "strict"})},
			// public=false, policy=permissive → A passes, B fires (consistent)
			{FixturePath: "f2.json", Asset: mkAssetNested("a2", map[string]any{"public": false, "policy": "permissive"})},
			// public=false, policy=strict → both pass
			{FixturePath: "f3.json", Asset: mkAssetNested("a3", map[string]any{"public": false, "policy": "strict"})},
		},
		assertion: func(t *testing.T, r Report, _ []ClassifiedPair) {
			if len(r.Pairs) != 1 {
				t.Fatalf("want 1 pair, got %d", len(r.Pairs))
			}
			if r.Pairs[0].Category != CategoryEmpiricalSubsumption {
				t.Fatalf("category = %s, want EMPIRICAL_SUBSUMPTION", r.Pairs[0].Category)
			}
			pl := r.Pairs[0].Payload.(EmpiricalSubsumptionPayload)
			if pl.Narrower != "CTL.NARROW" || pl.Broader != "CTL.WIDE" {
				t.Errorf("narrower/broader = %s/%s", pl.Narrower, pl.Broader)
			}
			if len(pl.DependencyDelta) != 1 || pl.DependencyDelta[0] != "properties.policy" {
				t.Errorf("dependency_delta = %v, want [properties.policy]", pl.DependencyDelta)
			}
		},
	}
	runPipeline(t, tc)
}

// TestPipeline_EmpiricalSubsumptionDisqualified: a single witness where
// narrower=VIOLATION and broader=PASS disqualifies subsumption — the
// pair drops to CONTRADICTION (LOGIC_BUG, single asset class). This is
// the critical pinning case for the "disqualifying" semantics; the
// pipeline must NOT silently file this as EMPIRICAL_SUBSUMPTION.
func TestPipeline_EmpiricalSubsumptionDisqualified(t *testing.T) {
	pair := CandidatePair{
		ControlA: "CTL.NARROW", ControlB: "CTL.WIDE",
		DepsA:    []string{"properties.public"},
		DepsB:    []string{"properties.public", "properties.policy"},
		Overlap:  []string{"properties.public"},
		Relation: RelationSubset,
		Narrower: "CTL.NARROW", Broader: "CTL.WIDE",
	}
	mdA, mdB := pcMeta(pair.ControlA, pair.ControlB)
	tc := pipelineCase{
		pair:     pair,
		metadata: map[string]ControlMetadata{pair.ControlA: mdA, pair.ControlB: mdB},
		stub: stubEval{verdicts: map[string]func(asset.Asset) (bool, error){
			// Narrower fires on a fixture where the broader does not — the disqualifier.
			pair.ControlA: func(a asset.Asset) (bool, error) { return propsAt(a)["public"] == true, nil },
			pair.ControlB: func(a asset.Asset) (bool, error) {
				// Broader has a stricter rule that paradoxically excludes the
				// narrower's case: policy=strict means the public flag is overridden.
				return propsAt(a)["public"] == true && propsAt(a)["policy"] == "permissive", nil
			},
		}},
		fixtures: []FixtureAsset{
			// public=true, policy=strict → narrower fires, broader does not. DISQUALIFIES.
			{FixturePath: "f1.json", Asset: mkAssetNested("a1", map[string]any{"public": true, "policy": "strict"})},
		},
		assertion: func(t *testing.T, r Report, _ []ClassifiedPair) {
			if len(r.Pairs) != 1 {
				t.Fatalf("want 1 pair, got %d", len(r.Pairs))
			}
			if r.Pairs[0].Category == CategoryEmpiricalSubsumption {
				t.Fatal("subsumption was NOT disqualified despite narrower=VIOLATION + broader=PASS witness")
			}
			if r.Pairs[0].Category != CategoryContradiction {
				t.Fatalf("category = %s, want CONTRADICTION", r.Pairs[0].Category)
			}
		},
	}
	runPipeline(t, tc)
}

// TestPipeline_Divergence: OVERLAPPING deps, single-asset-class
// disagreement → DIVERGENCE (informational), not CONTRADICTION. The
// minimal_disagreement_fixtures payload carries differing_values from
// the non-overlap subset of each control's reads.
func TestPipeline_Divergence(t *testing.T) {
	pair := CandidatePair{
		ControlA: "CTL.DIV.A", ControlB: "CTL.DIV.B",
		DepsA:    []string{"properties.public", "properties.tag"},
		DepsB:    []string{"properties.public", "properties.policy"},
		Overlap:  []string{"properties.public"},
		Relation: RelationOverlapping,
	}
	mdA, mdB := pcMeta(pair.ControlA, pair.ControlB)
	tc := pipelineCase{
		pair:     pair,
		metadata: map[string]ControlMetadata{pair.ControlA: mdA, pair.ControlB: mdB},
		stub: stubEval{verdicts: map[string]func(asset.Asset) (bool, error){
			// A: VIOLATION when public AND untagged
			pair.ControlA: func(a asset.Asset) (bool, error) {
				return propsAt(a)["public"] == true && propsAt(a)["tag"] == nil, nil
			},
			// B: VIOLATION when public AND policy=permissive
			pair.ControlB: func(a asset.Asset) (bool, error) {
				return propsAt(a)["public"] == true && propsAt(a)["policy"] == "permissive", nil
			},
		}},
		fixtures: []FixtureAsset{
			// public+untagged+strict → A fires, B passes
			{FixturePath: "buckets/f1.json", Asset: mkAssetTyped("b1", "aws_s3_bucket",
				map[string]any{"public": true, "tag": nil, "policy": "strict"})},
			// public+tagged+permissive → A passes, B fires
			{FixturePath: "buckets/f2.json", Asset: mkAssetTyped("b2", "aws_s3_bucket",
				map[string]any{"public": true, "tag": "owned", "policy": "permissive"})},
			// not public → both pass (agreement)
			{FixturePath: "buckets/f3.json", Asset: mkAssetTyped("b3", "aws_s3_bucket",
				map[string]any{"public": false, "tag": nil, "policy": "strict"})},
		},
		assertion: func(t *testing.T, r Report, _ []ClassifiedPair) {
			if len(r.Pairs) != 1 {
				t.Fatalf("want 1 pair, got %d", len(r.Pairs))
			}
			if r.Pairs[0].Category != CategoryDivergence {
				t.Fatalf("category = %s, want DIVERGENCE", r.Pairs[0].Category)
			}
			pl := r.Pairs[0].Payload.(DivergencePayload)
			if pl.AgreementRate >= 1.0 || pl.AgreementRate <= 0.0 {
				t.Errorf("agreement_rate = %v; want strictly between 0 and 1", pl.AgreementRate)
			}
			if len(pl.MinimalDisagreementFixtures) != 2 {
				t.Errorf("disagreement witnesses = %d, want 2", len(pl.MinimalDisagreementFixtures))
			}
			// differing_values must contain the non-overlap paths,
			// not properties.public (overlap).
			for _, w := range pl.MinimalDisagreementFixtures {
				if _, ok := w.DifferingValues["properties.public"]; ok {
					t.Errorf("differing_values leaked overlap path on %s", w.AssetID)
				}
			}
		},
	}
	runPipeline(t, tc)
}

// TestPipeline_AgreementWithDifferingMetadataIsUncategorized: IDENTICAL
// deps, 100% agreement, but compliance/remediation differ → not
// REDUNDANCY, not CONTRADICTION. Surfaces as no pair in the report
// (uncategorized). This is the cross-framework duplicate scenario the
// taxonomy intentionally does NOT over-claim — see Iteration 3 user
// guidance about future CROSS_FRAMEWORK_DUPLICATE category.
func TestPipeline_AgreementWithDifferingMetadataIsUncategorized(t *testing.T) {
	pair := CandidatePair{
		ControlA: "CTL.X", ControlB: "CTL.Y",
		DepsA: []string{"properties.public"}, DepsB: []string{"properties.public"},
		Overlap:  []string{"properties.public"},
		Relation: RelationIdentical,
	}
	mdA, mdB := pcMeta(pair.ControlA, pair.ControlB)
	mdB.ComplianceCanonical = "HIPAA:164.312|NIST:AC-3" // different framework
	tc := pipelineCase{
		pair:     pair,
		metadata: map[string]ControlMetadata{pair.ControlA: mdA, pair.ControlB: mdB},
		stub: stubEval{verdicts: map[string]func(asset.Asset) (bool, error){
			pair.ControlA: func(a asset.Asset) (bool, error) { return propsAt(a)["public"] == true, nil },
			pair.ControlB: func(a asset.Asset) (bool, error) { return propsAt(a)["public"] == true, nil },
		}},
		fixtures: []FixtureAsset{
			{FixturePath: "f1.json", Asset: mkAssetNested("a1", map[string]any{"public": true})},
			{FixturePath: "f2.json", Asset: mkAssetNested("a2", map[string]any{"public": false})},
		},
		assertion: func(t *testing.T, r Report, classified []ClassifiedPair) {
			if len(r.Pairs) != 0 {
				t.Errorf("want 0 pairs in report (agreement+different-metadata is not REDUNDANCY); got %d: %+v",
					len(r.Pairs), r.Pairs)
			}
			// But the classifier did process it — confirm it's marked uncategorized.
			if classified[0].Category != "" {
				t.Errorf("classified Category = %q, want empty", classified[0].Category)
			}
		},
	}
	runPipeline(t, tc)
}

// TestPipeline_NoFixtureCoverageSurfacedAsGap: a pair that overlap analysis
// produced but evaluation found no co-evaluations for must surface as a
// NO_FIXTURE_COVERAGE gap, not as a finding. The end-to-end assertion
// guards against silent loss when EvaluatePairs returns zero CoEvaluations.
func TestPipeline_NoFixtureCoverageSurfacedAsGap(t *testing.T) {
	pair := CandidatePair{
		ControlA: "CTL.NOCOV.A", ControlB: "CTL.NOCOV.B",
		DepsA: []string{"properties.thing"}, DepsB: []string{"properties.thing"},
		Overlap:  []string{"properties.thing"},
		Relation: RelationIdentical,
	}
	mdA, mdB := pcMeta(pair.ControlA, pair.ControlB)
	tc := pipelineCase{
		pair:     pair,
		metadata: map[string]ControlMetadata{pair.ControlA: mdA, pair.ControlB: mdB},
		stub: stubEval{verdicts: map[string]func(asset.Asset) (bool, error){
			pair.ControlA: func(asset.Asset) (bool, error) { return false, nil },
			pair.ControlB: func(asset.Asset) (bool, error) { return false, nil },
		}},
		fixtures: nil, // empty corpus
		assertion: func(t *testing.T, r Report, _ []ClassifiedPair) {
			if len(r.Pairs) != 0 {
				t.Errorf("want 0 pairs (no coverage), got %d", len(r.Pairs))
			}
			var gap *AnalysisGap
			for i := range r.AnalysisGaps {
				if r.AnalysisGaps[i].Reason == GapNoFixtureCoverage {
					gap = &r.AnalysisGaps[i]
					break
				}
			}
			if gap == nil {
				t.Fatalf("expected NO_FIXTURE_COVERAGE gap; got %+v", r.AnalysisGaps)
			}
			if len(gap.Controls) != 2 {
				t.Errorf("gap.Controls = %v, want 2 entries", gap.Controls)
			}
		},
	}
	runPipeline(t, tc)
}

// silence unused warning if a helper above is unreferenced in some build
var _ = policy.ControlDefinition{}
