package conflict

import (
	"testing"

	"github.com/sufield/stave/internal/core/kernel"
)

// mkMetadata builds two ControlMetadata entries with identical content.
// Override after construction to introduce specific differences.
func mkMetadata(idA, idB string) map[string]ControlMetadata {
	return map[string]ControlMetadata{
		idA: {
			ControlID:            idA,
			AttackStage:          "exfiltration",
			ComplianceCanonical:  "PCI-DSS:1.2|SOC2:CC6.1",
			RemediationCanonical: "block_public_access",
		},
		idB: {
			ControlID:            idB,
			AttackStage:          "exfiltration",
			ComplianceCanonical:  "PCI-DSS:1.2|SOC2:CC6.1",
			RemediationCanonical: "block_public_access",
		},
	}
}

// mkCoEval is a quick CoEvaluation builder. assetType defaults to
// "aws_s3_bucket" if empty.
func mkCoEval(path, id string, unsafeA, unsafeB bool, assetType string) CoEvaluation {
	if assetType == "" {
		assetType = "aws_s3_bucket"
	}
	return CoEvaluation{
		FixturePath: path,
		AssetID:     id,
		AssetType:   kernel.AssetType(assetType),
		UnsafeA:     unsafeA,
		UnsafeB:     unsafeB,
		ReadOverlap: true,
	}
}

func TestClassify_NoCoEvaluationsReturnsEmptyCategory(t *testing.T) {
	ep := EvaluatedPair{CandidatePair: CandidatePair{
		ControlA: "CTL.A", ControlB: "CTL.B", Relation: RelationIdentical,
	}}
	out, err := Classify([]EvaluatedPair{ep}, mkMetadata("CTL.A", "CTL.B"))
	if err != nil {
		t.Fatal(err)
	}
	if out[0].Category != "" {
		t.Errorf("Category = %q, want empty (no coverage)", out[0].Category)
	}
}

func TestClassify_MissingMetadataFailsLoud(t *testing.T) {
	ep := EvaluatedPair{
		CandidatePair: CandidatePair{ControlA: "CTL.A", ControlB: "CTL.B", Relation: RelationIdentical},
		CoEvaluations: []CoEvaluation{mkCoEval("f.json", "a", false, false, "")},
	}
	md := map[string]ControlMetadata{"CTL.A": {ControlID: "CTL.A"}} // CTL.B missing
	_, err := Classify([]EvaluatedPair{ep}, md)
	if err == nil {
		t.Fatal("expected error for missing metadata, got nil")
	}
}

// TestClassify_RedundancyHappyPath: IDENTICAL deps, 100% agreement,
// matching metadata → REDUNDANCY.
func TestClassify_RedundancyHappyPath(t *testing.T) {
	ep := EvaluatedPair{
		CandidatePair: CandidatePair{ControlA: "CTL.A", ControlB: "CTL.B", Relation: RelationIdentical},
		CoEvaluations: []CoEvaluation{
			mkCoEval("f1.json", "a1", true, true, ""),
			mkCoEval("f2.json", "a2", false, false, ""),
		},
	}
	out, _ := Classify([]EvaluatedPair{ep}, mkMetadata("CTL.A", "CTL.B"))
	if out[0].Category != CategoryRedundancy {
		t.Errorf("Category = %s, want REDUNDANCY", out[0].Category)
	}
}

// TestClassify_RedundancyDisqualifiedByMetadataMismatch: IDENTICAL deps,
// 100% agreement, but compliance differs → uncategorized (no semantic
// equivalence to claim).
func TestClassify_RedundancyDisqualifiedByMetadataMismatch(t *testing.T) {
	md := mkMetadata("CTL.A", "CTL.B")
	mdB := md["CTL.B"]
	mdB.ComplianceCanonical = "PCI-DSS:99.9"
	md["CTL.B"] = mdB

	ep := EvaluatedPair{
		CandidatePair: CandidatePair{ControlA: "CTL.A", ControlB: "CTL.B", Relation: RelationIdentical},
		CoEvaluations: []CoEvaluation{mkCoEval("f.json", "a", true, true, "")},
	}
	out, _ := Classify([]EvaluatedPair{ep}, md)
	if out[0].Category != "" {
		t.Errorf("Category = %s, want empty (metadata mismatch disqualifies REDUNDANCY)", out[0].Category)
	}
}

// TestClassify_DisqualifyingPrecedence_RedundancyToContradiction is
// the load-bearing precedence test the user called out.
//
// Setup: IDENTICAL deps, matching metadata, agreement on 9 fixtures,
// disagreement on 1 fixture, all assets same class. By a naive
// "agreement_rate >= threshold" REDUNDANCY rule, this would classify
// REDUNDANCY. Per the disqualifying precedence rule, it must classify
// CONTRADICTION/LOGIC_BUG.
//
// If a future maintainer reintroduces a tolerance threshold, this test
// fails — that is the intent.
func TestClassify_DisqualifyingPrecedence_RedundancyToContradiction(t *testing.T) {
	coevals := make([]CoEvaluation, 0, 10)
	for i := range 9 {
		coevals = append(coevals, mkCoEval(
			"agree-"+string(rune('a'+i))+".json",
			"asset", true, true, "",
		))
	}
	coevals = append(coevals, mkCoEval("disagree.json", "asset-x", true, false, ""))

	ep := EvaluatedPair{
		CandidatePair: CandidatePair{ControlA: "CTL.A", ControlB: "CTL.B", Relation: RelationIdentical},
		CoEvaluations: coevals,
	}
	out, _ := Classify([]EvaluatedPair{ep}, mkMetadata("CTL.A", "CTL.B"))

	if out[0].Category != CategoryContradiction {
		t.Fatalf("Category = %s, want CONTRADICTION (disqualifying precedence — any disagreement disqualifies REDUNDANCY)",
			out[0].Category)
	}
	if out[0].ContradictionSubcategory != SubcategoryLogicBug {
		t.Errorf("Subcategory = %s, want LOGIC_BUG (single asset_class)",
			out[0].ContradictionSubcategory)
	}
}

// TestClassify_ContradictionMissingAssetClassGuard: IDENTICAL deps,
// disagreement spans 2+ asset_class values → MISSING_ASSET_CLASS_GUARD.
func TestClassify_ContradictionMissingAssetClassGuard(t *testing.T) {
	ep := EvaluatedPair{
		CandidatePair: CandidatePair{ControlA: "CTL.A", ControlB: "CTL.B", Relation: RelationIdentical},
		CoEvaluations: []CoEvaluation{
			mkCoEval("f1.json", "bucket-1", true, false, "aws_s3_bucket"),
			mkCoEval("f2.json", "role-1", true, false, "aws_iam_role"),
		},
	}
	out, _ := Classify([]EvaluatedPair{ep}, mkMetadata("CTL.A", "CTL.B"))
	if out[0].Category != CategoryContradiction {
		t.Fatalf("Category = %s, want CONTRADICTION", out[0].Category)
	}
	if out[0].ContradictionSubcategory != SubcategoryMissingAssetClassGuard {
		t.Errorf("Subcategory = %s, want MISSING_ASSET_CLASS_GUARD",
			out[0].ContradictionSubcategory)
	}
}

// TestClassify_ContradictionPartialAssetClassCorrelation is the user's
// second adversarial test: disagreement witnesses span three
// asset_class values, only some of which correlate with the verdict
// split. The classifier rule is presence-of-diversity, not statistical
// correlation — three classes in disagreement witnesses → MISSING_GUARD,
// regardless of how clean the correlation is.
func TestClassify_ContradictionPartialAssetClassCorrelation(t *testing.T) {
	ep := EvaluatedPair{
		CandidatePair: CandidatePair{ControlA: "CTL.A", ControlB: "CTL.B", Relation: RelationIdentical},
		CoEvaluations: []CoEvaluation{
			// Class 1 disagrees one way:
			mkCoEval("f1.json", "bucket-1", true, false, "aws_s3_bucket"),
			// Class 2 disagrees the other way:
			mkCoEval("f2.json", "role-1", false, true, "aws_iam_role"),
			// Class 3 disagrees the same way as class 1 — partial correlation:
			mkCoEval("f3.json", "func-1", true, false, "aws_lambda_function"),
		},
	}
	out, _ := Classify([]EvaluatedPair{ep}, mkMetadata("CTL.A", "CTL.B"))
	if out[0].Category != CategoryContradiction {
		t.Fatalf("Category = %s, want CONTRADICTION", out[0].Category)
	}
	if out[0].ContradictionSubcategory != SubcategoryMissingAssetClassGuard {
		t.Errorf("Subcategory = %s, want MISSING_ASSET_CLASS_GUARD (presence-of-diversity rule)",
			out[0].ContradictionSubcategory)
	}
}

// TestClassify_EmpiricalSubsumptionHappyPath: SUBSET deps, narrower's
// violations are a subset of broader's → EMPIRICAL_SUBSUMPTION.
// Includes one (PASS, VIOLATION) witness which is *consistent* with
// subsumption (broader is stricter) and must not disqualify.
func TestClassify_EmpiricalSubsumptionHappyPath(t *testing.T) {
	ep := EvaluatedPair{
		CandidatePair: CandidatePair{
			ControlA: "CTL.NARROW", ControlB: "CTL.BROAD",
			Relation: RelationSubset,
			Narrower: "CTL.NARROW", Broader: "CTL.BROAD",
		},
		CoEvaluations: []CoEvaluation{
			mkCoEval("f1.json", "a1", true, true, ""),   // both flag → consistent
			mkCoEval("f2.json", "a2", false, false, ""), // both pass → consistent
			mkCoEval("f3.json", "a3", false, true, ""),  // broader is stricter → consistent
		},
	}
	out, _ := Classify([]EvaluatedPair{ep}, mkMetadata("CTL.NARROW", "CTL.BROAD"))
	if out[0].Category != CategoryEmpiricalSubsumption {
		t.Errorf("Category = %s, want EMPIRICAL_SUBSUMPTION", out[0].Category)
	}
}

// TestClassify_EmpiricalSubsumptionAsymmetryDisqualifies is the
// asymmetric-rule test: a single fixture where narrower=VIOLATION and
// broader=PASS disqualifies subsumption (broader cannot subsume
// narrower if narrower catches something broader misses), and the
// pair classifies CONTRADICTION instead.
func TestClassify_EmpiricalSubsumptionAsymmetryDisqualifies(t *testing.T) {
	ep := EvaluatedPair{
		CandidatePair: CandidatePair{
			ControlA: "CTL.NARROW", ControlB: "CTL.BROAD",
			Relation: RelationSubset,
			Narrower: "CTL.NARROW", Broader: "CTL.BROAD",
		},
		CoEvaluations: []CoEvaluation{
			mkCoEval("f1.json", "a1", true, true, ""),
			// Disqualifying witness: narrower flags, broader doesn't:
			mkCoEval("f2.json", "a2", true, false, ""),
		},
	}
	out, _ := Classify([]EvaluatedPair{ep}, mkMetadata("CTL.NARROW", "CTL.BROAD"))
	if out[0].Category != CategoryContradiction {
		t.Fatalf("Category = %s, want CONTRADICTION (subsumption asymmetry violated)", out[0].Category)
	}
}

// TestClassify_EmpiricalSubsumptionDirectionRespected covers the
// inverse direction: when ControlB is narrower (Narrower field points
// to ControlB), the asymmetry check must flip accordingly.
func TestClassify_EmpiricalSubsumptionDirectionRespected(t *testing.T) {
	ep := EvaluatedPair{
		CandidatePair: CandidatePair{
			ControlA: "CTL.BROAD", ControlB: "CTL.NARROW",
			Relation: RelationSubset,
			Narrower: "CTL.NARROW", Broader: "CTL.BROAD",
		},
		// Disqualifying witness: narrower (ControlB) flags, broader
		// (ControlA) doesn't:
		CoEvaluations: []CoEvaluation{
			mkCoEval("f.json", "a", false, true, ""),
		},
	}
	out, _ := Classify([]EvaluatedPair{ep}, mkMetadata("CTL.BROAD", "CTL.NARROW"))
	if out[0].Category != CategoryContradiction {
		t.Errorf("Category = %s, want CONTRADICTION (direction-aware asymmetry check)", out[0].Category)
	}
}

// TestClassify_DivergenceForOverlappingDepsWithSingleAssetClass:
// OVERLAPPING (not subset) deps, disagreement, single asset_class →
// DIVERGENCE (the differing dep paths are the likely explanation).
func TestClassify_DivergenceForOverlappingDepsWithSingleAssetClass(t *testing.T) {
	ep := EvaluatedPair{
		CandidatePair: CandidatePair{
			ControlA: "CTL.A", ControlB: "CTL.B", Relation: RelationOverlapping,
		},
		CoEvaluations: []CoEvaluation{
			mkCoEval("f1.json", "a1", true, true, ""),
			mkCoEval("f2.json", "a2", false, false, ""),
			mkCoEval("f3.json", "a3", true, false, ""),
		},
	}
	out, _ := Classify([]EvaluatedPair{ep}, mkMetadata("CTL.A", "CTL.B"))
	if out[0].Category != CategoryDivergence {
		t.Errorf("Category = %s, want DIVERGENCE", out[0].Category)
	}
}

// TestClassify_OverlappingDepsWithAssetClassDiversityIsContradiction:
// even for OVERLAPPING deps, asset_class diversity in disagreement
// witnesses promotes to CONTRADICTION/MISSING_GUARD.
func TestClassify_OverlappingDepsWithAssetClassDiversityIsContradiction(t *testing.T) {
	ep := EvaluatedPair{
		CandidatePair: CandidatePair{
			ControlA: "CTL.A", ControlB: "CTL.B", Relation: RelationOverlapping,
		},
		CoEvaluations: []CoEvaluation{
			mkCoEval("f1.json", "bucket-1", true, false, "aws_s3_bucket"),
			mkCoEval("f2.json", "role-1", true, false, "aws_iam_role"),
		},
	}
	out, _ := Classify([]EvaluatedPair{ep}, mkMetadata("CTL.A", "CTL.B"))
	if out[0].Category != CategoryContradiction {
		t.Fatalf("Category = %s, want CONTRADICTION", out[0].Category)
	}
	if out[0].ContradictionSubcategory != SubcategoryMissingAssetClassGuard {
		t.Errorf("Subcategory = %s, want MISSING_ASSET_CLASS_GUARD",
			out[0].ContradictionSubcategory)
	}
}

func TestCount_TalliesByCategory(t *testing.T) {
	pairs := []ClassifiedPair{
		{Category: CategoryContradiction},
		{Category: CategoryContradiction},
		{Category: CategoryRedundancy},
		{Category: CategoryDivergence},
		{Category: ""},
	}
	c := Count(pairs)
	if c.Contradiction != 2 || c.Redundancy != 1 || c.Divergence != 1 || c.Uncategorized != 1 {
		t.Errorf("Count = %+v, want 2/1/0/1/1", c)
	}
}

func TestSortByCategory_ContradictionFirst(t *testing.T) {
	pairs := []ClassifiedPair{
		{Category: CategoryDivergence, EvaluatedPair: EvaluatedPair{CandidatePair: CandidatePair{ControlA: "CTL.A", ControlB: "CTL.B"}}},
		{Category: CategoryContradiction, EvaluatedPair: EvaluatedPair{CandidatePair: CandidatePair{ControlA: "CTL.X", ControlB: "CTL.Y"}}},
		{Category: CategoryRedundancy, EvaluatedPair: EvaluatedPair{CandidatePair: CandidatePair{ControlA: "CTL.M", ControlB: "CTL.N"}}},
	}
	sorted := SortByCategory(pairs)
	if sorted[0].Category != CategoryContradiction {
		t.Errorf("first sorted category = %s, want CONTRADICTION", sorted[0].Category)
	}
	if sorted[1].Category != CategoryRedundancy {
		t.Errorf("second sorted category = %s, want REDUNDANCY", sorted[1].Category)
	}
	if sorted[2].Category != CategoryDivergence {
		t.Errorf("third sorted category = %s, want DIVERGENCE", sorted[2].Category)
	}
}
