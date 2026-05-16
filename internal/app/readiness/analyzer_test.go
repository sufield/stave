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
	controlBlockers := map[kernel.AssetType]int{
		"aws_vpc":      50, // many controls, few chains
		"aws_iam_role": 5,  // few controls, many chains
	}
	chainBlockers := map[kernel.AssetType]int{
		"aws_iam_role": 30,
		"aws_vpc":      2,
	}
	observed := map[kernel.AssetType]int{}
	actions := rankActions(controlBlockers, chainBlockers, observed, 5)
	if len(actions) != 2 {
		t.Fatalf("want 2 actions, got %d", len(actions))
	}
	if actions[0].AssetType != "aws_iam_role" {
		t.Errorf("expected aws_iam_role first (more chain unlocks), got %s", actions[0].AssetType)
	}
}

func TestRankActions_TopN(t *testing.T) {
	controlBlockers := map[kernel.AssetType]int{
		"a": 1, "b": 2, "c": 3, "d": 4, "e": 5,
	}
	actions := rankActions(controlBlockers, nil, map[kernel.AssetType]int{}, 3)
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
	// A type that is already observed must not appear in the
	// action plan even if it was listed as a blocker — the
	// blocker map records all member types of blocked controls,
	// not just the missing ones.
	controlBlockers := map[kernel.AssetType]int{
		"aws_s3_bucket": 10,
		"aws_iam_role":  5,
	}
	observed := map[kernel.AssetType]int{"aws_s3_bucket": 3}
	actions := rankActions(controlBlockers, nil, observed, 5)
	if len(actions) != 1 || actions[0].AssetType != "aws_iam_role" {
		t.Errorf("observed types must not appear in action plan; got %+v", actions)
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
