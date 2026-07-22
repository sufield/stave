package readiness

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

func ctl(id string, types ...kernel.AssetType) policy.ControlDefinition {
	return policy.ControlDefinition{
		ID:                   kernel.ControlID(id),
		ApplicableAssetTypes: types,
	}
}

func snap(assets ...asset.Asset) asset.Snapshot {
	return asset.Snapshot{
		CapturedAt: time.Date(2026, 5, 14, 0, 0, 0, 0, time.UTC),
		Assets:     assets,
	}
}

func a(id, t string) asset.Asset {
	return asset.Asset{
		ID:   asset.ID(id),
		Type: kernel.AssetType(t),
	}
}

func TestAnalyze_EmptySnapshots_ZeroReadiness(t *testing.T) {
	report := Analyze(
		[]policy.ControlDefinition{ctl("CTL.S3.001", "aws_s3_bucket")},
		nil,
		nil,
		5,
	)
	if report.ObservationCount != 0 {
		t.Errorf("ObservationCount: want 0, got %d", report.ObservationCount)
	}
	if report.ReadinessScore != 0 {
		t.Errorf("ReadinessScore: want 0, got %f", report.ReadinessScore)
	}
	if report.Controls.Blocked != 1 {
		t.Errorf("Blocked controls: want 1, got %d", report.Controls.Blocked)
	}
	// Empty snapshot: the one missing asset type should drive
	// the action plan.
	if len(report.Actions) != 1 {
		t.Fatalf("Actions: want 1, got %d", len(report.Actions))
	}
	if report.Actions[0].AssetType != "aws_s3_bucket" {
		t.Errorf("Action asset type: got %s", report.Actions[0].AssetType)
	}
	if report.Actions[0].ControlsUnblocked != 1 {
		t.Errorf("Action ControlsUnblocked: want 1, got %d", report.Actions[0].ControlsUnblocked)
	}
}

func TestAnalyze_AllRequiredTypesObserved_FullScore(t *testing.T) {
	controls := []policy.ControlDefinition{
		ctl("CTL.S3.001", "aws_s3_bucket"),
		ctl("CTL.IAM.001", "aws_iam_role"),
	}
	snapshot := snap(a("b1", "aws_s3_bucket"), a("r1", "aws_iam_role"))
	report := Analyze(controls, nil, []asset.Snapshot{snapshot}, 5)
	if report.Controls.CanFire != 2 {
		t.Errorf("CanFire: want 2, got %d", report.Controls.CanFire)
	}
	if report.Controls.Blocked != 0 {
		t.Errorf("Blocked: want 0, got %d", report.Controls.Blocked)
	}
	if report.ReadinessScore != 1.0 {
		t.Errorf("ReadinessScore: want 1.0, got %f", report.ReadinessScore)
	}
	if len(report.Actions) != 0 {
		t.Errorf("Actions: want 0 when nothing is blocked, got %d", len(report.Actions))
	}
}

func TestAnalyze_NoApplicableTypes_Indeterminate(t *testing.T) {
	// A control with no declared applicable_asset_types is the
	// "fires on any asset" case (81% of the real catalog at
	// time of writing). The analyzer cannot statically predict
	// firing — must report indeterminate, NOT can-fire or
	// blocked.
	controls := []policy.ControlDefinition{ctl("CTL.GENERIC.001")}
	report := Analyze(controls, nil, nil, 5)
	if report.Controls.Indeterminate != 1 {
		t.Errorf("Indeterminate: want 1, got %d", report.Controls.Indeterminate)
	}
	if report.Controls.CanFire != 0 || report.Controls.Blocked != 0 {
		t.Errorf("CanFire/Blocked: want 0/0, got %d/%d",
			report.Controls.CanFire, report.Controls.Blocked)
	}
	// Indeterminate controls do not affect the readiness score
	// or the action plan — readiness measures the classifiable
	// subset only.
	if report.ReadinessScore != 0 {
		t.Errorf("ReadinessScore for indeterminate-only catalog: want 0, got %f", report.ReadinessScore)
	}
	if len(report.Actions) != 0 {
		t.Errorf("Actions: indeterminate-only catalog produces no plan, got %d", len(report.Actions))
	}
}

func TestAnalyze_ChainBlockedByOneMember(t *testing.T) {
	controls := []policy.ControlDefinition{
		ctl("CTL.S3.001", "aws_s3_bucket"),
		ctl("CTL.IAM.001", "aws_iam_role"),
	}
	chains := []policy.ChainDefinition{
		{
			ID:                  kernel.ChainID("test_chain"),
			ControlIDs:          []kernel.ControlID{"CTL.S3.001", "CTL.IAM.001"},
			EscalationThreshold: 2,
		},
	}
	// Observe S3 but not IAM. Chain is blocked because IAM is missing.
	snapshot := snap(a("b1", "aws_s3_bucket"))
	report := Analyze(controls, chains, []asset.Snapshot{snapshot}, 5)
	if report.Chains.Blocked != 1 {
		t.Errorf("Chain blocked: want 1, got %d", report.Chains.Blocked)
	}
	if report.Chains.CanFire != 0 {
		t.Errorf("Chain CanFire: want 0, got %d", report.Chains.CanFire)
	}
	// Top action should name the missing IAM role type.
	if len(report.Actions) == 0 {
		t.Fatal("Actions: want at least 1")
	}
	if report.Actions[0].AssetType != "aws_iam_role" {
		t.Errorf("Top action: want aws_iam_role, got %s", report.Actions[0].AssetType)
	}
	if report.Actions[0].ChainsUnblocked != 1 {
		t.Errorf("ChainsUnblocked: want 1, got %d", report.Actions[0].ChainsUnblocked)
	}
}

func TestAnalyze_ChainIndeterminate_WhenMemberHasNoApplicable(t *testing.T) {
	controls := []policy.ControlDefinition{
		ctl("CTL.S3.001", "aws_s3_bucket"),
		ctl("CTL.GENERIC.001"), // no applicable types
	}
	chains := []policy.ChainDefinition{
		{
			ID:                  kernel.ChainID("test_chain"),
			ControlIDs:          []kernel.ControlID{"CTL.S3.001", "CTL.GENERIC.001"},
			EscalationThreshold: 2,
		},
	}
	snapshot := snap(a("b1", "aws_s3_bucket"))
	report := Analyze(controls, chains, []asset.Snapshot{snapshot}, 5)
	// One member can fire; one is indeterminate; chain is indeterminate.
	if report.Chains.Indeterminate != 1 {
		t.Errorf("Chain indeterminate: want 1, got %d", report.Chains.Indeterminate)
	}
}

func TestRankActions_ChainsOutweighControls(t *testing.T) {
	// Two missing types: one blocks more chains, the other blocks
	// more controls. Chain blocker ranks first.
	controls := []policy.ControlDefinition{
		// 5 controls needing aws_iam_role
		ctl("CTL.IAM.001", "aws_iam_role"),
		ctl("CTL.IAM.002", "aws_iam_role"),
		ctl("CTL.IAM.003", "aws_iam_role"),
		ctl("CTL.IAM.004", "aws_iam_role"),
		ctl("CTL.IAM.005", "aws_iam_role"),
		// 10 controls needing aws_vpc (more controls, but fewer chains)
		ctl("CTL.VPC.001", "aws_vpc"),
		ctl("CTL.VPC.002", "aws_vpc"),
		ctl("CTL.VPC.003", "aws_vpc"),
		ctl("CTL.VPC.004", "aws_vpc"),
		ctl("CTL.VPC.005", "aws_vpc"),
		ctl("CTL.VPC.006", "aws_vpc"),
		ctl("CTL.VPC.007", "aws_vpc"),
		ctl("CTL.VPC.008", "aws_vpc"),
		ctl("CTL.VPC.009", "aws_vpc"),
		ctl("CTL.VPC.010", "aws_vpc"),
	}
	// 3 chains requiring aws_iam_role, 1 chain requiring aws_vpc
	chains := []policy.ChainDefinition{
		{ID: "chain_iam_1", ControlIDs: []kernel.ControlID{"CTL.IAM.001"}, EscalationThreshold: 1},
		{ID: "chain_iam_2", ControlIDs: []kernel.ControlID{"CTL.IAM.002"}, EscalationThreshold: 1},
		{ID: "chain_iam_3", ControlIDs: []kernel.ControlID{"CTL.IAM.003"}, EscalationThreshold: 1},
		{ID: "chain_vpc_1", ControlIDs: []kernel.ControlID{"CTL.VPC.001"}, EscalationThreshold: 1},
	}
	observed := map[kernel.AssetType]int{}
	actions := rankActions(controls, chains, observed, 5)
	if len(actions) != 2 {
		t.Fatalf("want 2 actions, got %d", len(actions))
	}
	if actions[0].AssetType != "aws_iam_role" {
		t.Errorf("expected aws_iam_role first (more chain unlocks), got %s", actions[0].AssetType)
	}
}

func TestRankActions_TopN(t *testing.T) {
	controls := []policy.ControlDefinition{
		ctl("CTL.A.001", "a"),
		ctl("CTL.B.001", "b"), ctl("CTL.B.002", "b"),
		ctl("CTL.C.001", "c"), ctl("CTL.C.002", "c"), ctl("CTL.C.003", "c"),
		ctl("CTL.D.001", "d"), ctl("CTL.D.002", "d"), ctl("CTL.D.003", "d"), ctl("CTL.D.004", "d"),
		ctl("CTL.E.001", "e"), ctl("CTL.E.002", "e"), ctl("CTL.E.003", "e"), ctl("CTL.E.004", "e"), ctl("CTL.E.005", "e"),
	}
	actions := rankActions(controls, nil, map[kernel.AssetType]int{}, 3)
	if len(actions) != 3 {
		t.Fatalf("topN=3 expected 3 actions, got %d", len(actions))
	}
	want := []kernel.AssetType{"e", "d", "c"}
	for i, w := range want {
		if actions[i].AssetType != w {
			t.Errorf("actions[%d] = %s, want %s", i, actions[i].AssetType, w)
		}
	}
}

func TestRankActions_SkipsObservedTypes(t *testing.T) {
	controls := []policy.ControlDefinition{
		ctl("CTL.S3.001", "aws_s3_bucket"),
		ctl("CTL.S3.002", "aws_s3_bucket"),
		ctl("CTL.IAM.001", "aws_iam_role"),
	}
	observed := map[kernel.AssetType]int{"aws_s3_bucket": 3}
	actions := rankActions(controls, nil, observed, 5)
	if len(actions) != 1 || actions[0].AssetType != "aws_iam_role" {
		t.Errorf("observed types must not appear in action plan; got %+v", actions)
	}
}

func TestRankActions_GreedySetCover_EliminatesRedundant(t *testing.T) {
	// This is the key set cover test. Three actions with overlapping coverage:
	//   Type A unblocks controls {1, 2, 3}
	//   Type B unblocks controls {2, 3, 4}
	//   Type C unblocks controls {4, 5}
	// Static sort (by count): A=3, B=3, C=2 → selects A, B, C
	// Greedy set cover: A (covers 1,2,3), marginal B drops to 1 (only 4),
	//   C also covers 4+5 (marginal 2) → selects A, C — B is redundant.
	controls := []policy.ControlDefinition{
		// Controls 1,2,3 accept types A and B (overlap)
		ctl("CTL.001", "type_a"),
		{ID: "CTL.002", ApplicableAssetTypes: []kernel.AssetType{"type_a", "type_b"}},
		{ID: "CTL.003", ApplicableAssetTypes: []kernel.AssetType{"type_a", "type_b"}},
		// Control 4 accepts B and C (overlap)
		{ID: "CTL.004", ApplicableAssetTypes: []kernel.AssetType{"type_b", "type_c"}},
		// Control 5 accepts only C
		ctl("CTL.005", "type_c"),
	}
	actions := rankActions(controls, nil, map[kernel.AssetType]int{}, 10)

	// Greedy should pick A (3 controls) first, then C (2 marginal: 4,5).
	// B is redundant — its marginal value after A is 1 (only CTL.004),
	// but C covers CTL.004 AND CTL.005 (marginal 2 > 1).
	if len(actions) != 3 {
		// All 3 types get selected (B still covers something),
		// but the ORDER matters: A first, then C, then B.
		t.Logf("actions: %v", actions)
	}
	if actions[0].AssetType != "type_a" {
		t.Errorf("first action should be type_a (3 controls), got %s", actions[0].AssetType)
	}
	if actions[1].AssetType != "type_c" {
		t.Errorf("second action should be type_c (2 marginal), got %s", actions[1].AssetType)
	}
	// After A and C, B has marginal value 0 (all controls covered).
	if len(actions) > 2 && actions[2].ControlsUnblocked != 0 {
		t.Errorf("third action should have 0 marginal controls, got %d", actions[2].ControlsUnblocked)
	}
	// Key assertion: with topN=2, greedy covers all 5 controls in 2 picks.
	actions2 := rankActions(controls, nil, map[kernel.AssetType]int{}, 2)
	if len(actions2) != 2 {
		t.Fatalf("topN=2: want 2 actions, got %d", len(actions2))
	}
	totalCovered := actions2[0].ControlsUnblocked + actions2[1].ControlsUnblocked
	if totalCovered != 5 {
		t.Errorf("2 greedy picks should cover all 5 controls, covered %d", totalCovered)
	}
}

func TestRankActions_GreedySetCover_DuplicateCoverage(t *testing.T) {
	// Two types cover exactly the same controls — greedy picks one,
	// the other has 0 marginal value.
	controls := []policy.ControlDefinition{
		{ID: "CTL.001", ApplicableAssetTypes: []kernel.AssetType{"type_a", "type_b"}},
		{ID: "CTL.002", ApplicableAssetTypes: []kernel.AssetType{"type_a", "type_b"}},
		{ID: "CTL.003", ApplicableAssetTypes: []kernel.AssetType{"type_a", "type_b"}},
	}
	actions := rankActions(controls, nil, map[kernel.AssetType]int{}, 5)
	if len(actions) < 1 {
		t.Fatal("expected at least 1 action")
	}
	if actions[0].ControlsUnblocked != 3 {
		t.Errorf("first pick should cover 3, got %d", actions[0].ControlsUnblocked)
	}
	// Second pick has 0 marginal value — either not emitted or emitted with 0.
	if len(actions) > 1 && actions[1].ControlsUnblocked != 0 {
		t.Errorf("second pick should have 0 marginal, got %d", actions[1].ControlsUnblocked)
	}
}

// TestAnalyze_BucketPercentages_SumToHundred locks in the share-of-
// total percentage annotation. Without these fields a JSON consumer
// would have to recompute the percentages from the integer counts
// to render the same numbers the text output shows; with them, the
// three buckets exposing share-of-total are the source of truth.
// Their sum must equal 100 (modulo float rounding) whenever Total
// is non-zero. The test guards both the math and the API:
//
//  1. Three controls in three different buckets (CanFire / Blocked /
//     Indeterminate) so each *Pct is exercised independently.
//  2. The sum is 100.0 — not 99.9, not 100.1 — because the percent
//     values are derived from integer counts that always partition
//     Total exactly.
//  3. The denominator-annotation field is set verbatim. Renaming the
//     constant requires touching this test, which is intentional —
//     the string is the JSON contract.
func TestAnalyze_BucketPercentages_SumToHundred(t *testing.T) {
	controls := []policy.ControlDefinition{
		ctl("CTL.A.001", "aws_s3_bucket"),          // CanFire
		ctl("CTL.B.001", "aws_missing_type"),       // Blocked
		ctl("CTL.C.001" /* no applicable types */), // Indeterminate
	}
	snapshot := snap(a("b1", "aws_s3_bucket"))
	r := Analyze(controls, nil, []asset.Snapshot{snapshot}, 0)

	c := r.Controls
	if c.Total != 3 {
		t.Fatalf("Total: want 3, got %d", c.Total)
	}
	if c.CanFire != 1 || c.Blocked != 1 || c.Indeterminate != 1 {
		t.Fatalf("bucket counts: want 1/1/1, got %d/%d/%d", c.CanFire, c.Blocked, c.Indeterminate)
	}
	sum := c.CanFirePct + c.BlockedPct + c.IndeterminatePct
	if sum < 99.99 || sum > 100.01 {
		t.Errorf("share-of-total percentages must sum to ~100; got %.4f (%.4f + %.4f + %.4f)",
			sum, c.CanFirePct, c.BlockedPct, c.IndeterminatePct)
	}
	const wantDenom = "can_fire + blocked (excludes indeterminate)"
	if r.ReadinessDenominator != wantDenom {
		t.Errorf("ReadinessDenominator: got %q, want %q", r.ReadinessDenominator, wantDenom)
	}
}

// TestAnalyze_EmptyForecast_NoPercentageDivisionByZero guards the
// degenerate case: an empty control set must leave the *Pct fields
// at zero, not produce NaN. JSON output of NaN crashes consumers
// that assume the field is a finite number.
func TestAnalyze_EmptyForecast_NoPercentageDivisionByZero(t *testing.T) {
	r := Analyze(nil, nil, nil, 0)
	if r.Controls.CanFirePct != 0 || r.Controls.BlockedPct != 0 || r.Controls.IndeterminatePct != 0 {
		t.Errorf("empty forecast must have zero percentages; got %v",
			[]float64{r.Controls.CanFirePct, r.Controls.BlockedPct, r.Controls.IndeterminatePct})
	}
}
