package risk

import (
	"math"
	"testing"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

func assertScoreClose(t *testing.T, got, want float64) {
	t.Helper()
	if math.Abs(got-want) > 1e-6 {
		t.Errorf("score = %v, want %v (diff %v)", got, want, got-want)
	}
}

func TestDurationFactor(t *testing.T) {
	tests := []struct {
		name  string
		hours float64
		want  float64
	}{
		{"zero hours", 0, 1.0},
		{"29 days", 29 * 24, 1.0},
		{"30 days", 30 * 24, 1.5},
		{"89 days", 89 * 24, 1.5},
		{"90 days", 90 * 24, 2.0},
		{"364 days", 364 * 24, 2.0},
		{"365 days", 365 * 24, 3.0},
		{"1642 days", 1642 * 24, 3.0},
		{"1643 days (4.5 years)", 1643 * 24, 5.0},
		{"2000 days", 2000 * 24, 5.0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DurationFactor(tt.hours)
			if got != tt.want {
				t.Errorf("DurationFactor(%v) = %v, want %v", tt.hours, got, tt.want)
			}
		})
	}
}

func TestRankExposures_SortOrder(t *testing.T) {
	inputs := []RankInput{
		{ControlID: "CTL.LOW.001", AssetID: "asset-1", ControlSeverity: policy.SeverityLow, UnsafeDurationHours: 10 * 24},
		{ControlID: "CTL.CRIT.001", AssetID: "asset-2", ControlSeverity: policy.SeverityCritical, UnsafeDurationHours: 400 * 24},
		{ControlID: "CTL.MED.001", AssetID: "asset-3", ControlSeverity: policy.SeverityMedium, UnsafeDurationHours: 100 * 24},
	}

	ranks := RankExposures(inputs, nil, 0)

	if len(ranks) != 3 {
		t.Fatalf("got %d ranks, want 3", len(ranks))
	}

	// Critical + 400 days raw computes to 100 * 3.0 (DurationFactor)
	// * BlindMultiplier(400) ≈ 628 but the score is capped at
	// ScoreCatastrophic (=100). The cap keeps the score frame stable
	// for catastrophic findings: an uncapped 628 alongside a 127
	// makes every other finding render as a sub-1% bar in the
	// renderer, which obscures rather than highlights risk.
	if ranks[0].ControlID != "CTL.CRIT.001" {
		t.Errorf("rank 0 = %s, want CTL.CRIT.001", ranks[0].ControlID)
	}
	assertScoreClose(t, ranks[0].ExposureScore.Value(), float64(ScoreCatastrophic))
	if !ranks[0].SilentKiller {
		t.Error("rank 0 should be silent killer (400 days > 300)")
	}

	// Medium + 100 days raw = 50 * 2.0 * BlindMultiplier(100) ≈
	// 127.397 — but capped at ScoreCatastrophic (=100). Below the
	// ceiling the raw score passes through unchanged.
	if ranks[1].ControlID != "CTL.MED.001" {
		t.Errorf("rank 1 = %s, want CTL.MED.001", ranks[1].ControlID)
	}
	assertScoreClose(t, ranks[1].ExposureScore.Value(), float64(ScoreCatastrophic))

	// Low + 10 days = 25 * 1.0 * (1 + 10/365) = 25.685...
	if ranks[2].ControlID != "CTL.LOW.001" {
		t.Errorf("rank 2 = %s, want CTL.LOW.001", ranks[2].ControlID)
	}
	assertScoreClose(t, ranks[2].ExposureScore.Value(), 25.0*1.0*BlindMultiplier(10))
	if ranks[2].SilentKiller {
		t.Error("rank 2 should not be silent killer (10 days < 300)")
	}
}

func TestRankExposures_TopN(t *testing.T) {
	inputs := []RankInput{
		{ControlID: "CTL.A", AssetID: "a", ControlSeverity: policy.SeverityCritical, UnsafeDurationHours: 24},
		{ControlID: "CTL.B", AssetID: "b", ControlSeverity: policy.SeverityHigh, UnsafeDurationHours: 24},
		{ControlID: "CTL.C", AssetID: "c", ControlSeverity: policy.SeverityMedium, UnsafeDurationHours: 24},
	}
	ranks := RankExposures(inputs, nil, 2)
	if len(ranks) != 2 {
		t.Fatalf("got %d, want 2", len(ranks))
	}
	if ranks[0].ControlID != "CTL.A" {
		t.Errorf("top 1 = %s, want CTL.A", ranks[0].ControlID)
	}
}

func TestRankExposures_BaseImpactOverride(t *testing.T) {
	inputs := []RankInput{
		{ControlID: "CTL.WITH.IMPACT", AssetID: "asset-1", ControlSeverity: policy.SeverityMedium, UnsafeDurationHours: 24},
	}

	ctl := &policy.ControlDefinition{}
	ctl.Params = policy.NewParams(map[string]any{"base_impact": float64(80)})
	lookup := map[kernel.ControlID]*policy.ControlDefinition{
		"CTL.WITH.IMPACT": ctl,
	}

	ranks := RankExposures(inputs, lookup, 0)
	if ranks[0].Breakdown.BaseScore != 80 {
		t.Errorf("base = %d, want 80", ranks[0].Breakdown.BaseScore)
	}
}

func TestRankExposures_BlastMultiplier(t *testing.T) {
	inputs := []RankInput{
		{ControlID: "CTL.BLAST", AssetID: "asset-1", ControlSeverity: policy.SeverityCritical, UnsafeDurationHours: 24},
	}

	ctl := &policy.ControlDefinition{}
	ctl.Params = policy.NewParams(map[string]any{
		"blast_radius": map[string]any{
			"multiplier": 2.5,
		},
	})
	lookup := map[kernel.ControlID]*policy.ControlDefinition{
		"CTL.BLAST": ctl,
	}

	ranks := RankExposures(inputs, lookup, 0)
	// Raw 100 * 2.5 * BlindMultiplier(1) ≈ 250 — capped at
	// ScoreCatastrophic. Pre-cap behavior leaked a 250 score that
	// dwarfed every other finding in the same report.
	assertScoreClose(t, ranks[0].ExposureScore.Value(), float64(ScoreCatastrophic))
}

func TestRankExposures_PublicExposure(t *testing.T) {
	exp := &policy.Exposure{PrincipalScope: kernel.ScopePublic}
	inputs := []RankInput{
		{ControlID: "CTL.PUBLIC", AssetID: "asset-1", ControlSeverity: policy.SeverityHigh, UnsafeDurationHours: 24, Exposure: exp},
	}

	ranks := RankExposures(inputs, nil, 0)
	// Raw 75 * 2.0 * BlindMultiplier(1) ≈ 150 — capped at
	// ScoreCatastrophic.
	assertScoreClose(t, ranks[0].ExposureScore.Value(), float64(ScoreCatastrophic))
}

// TestRankExposures_CappedAtCeiling pins the cap explicitly: any
// combination that would otherwise exceed ScoreCatastrophic must clamp.
func TestRankExposures_CappedAtCeiling(t *testing.T) {
	inputs := []RankInput{
		{ControlID: "CTL.EXTREME", AssetID: "asset-1", ControlSeverity: policy.SeverityCritical, UnsafeDurationHours: 2000 * 24},
	}
	ranks := RankExposures(inputs, nil, 0)
	if got := ranks[0].ExposureScore.Value(); got != float64(ScoreCatastrophic) {
		t.Errorf("extreme score = %f, want %d", got, ScoreCatastrophic)
	}
}

func TestRankExposures_Empty(t *testing.T) {
	ranks := RankExposures(nil, nil, 0)
	if ranks != nil {
		t.Errorf("got %v, want nil", ranks)
	}
}

func TestRankExposures_TieBreak(t *testing.T) {
	inputs := []RankInput{
		{ControlID: "CTL.B", AssetID: asset.ID("z"), ControlSeverity: policy.SeverityHigh, UnsafeDurationHours: 24},
		{ControlID: "CTL.A", AssetID: asset.ID("z"), ControlSeverity: policy.SeverityHigh, UnsafeDurationHours: 24},
	}
	ranks := RankExposures(inputs, nil, 0)
	if ranks[0].ControlID != "CTL.A" {
		t.Errorf("rank 0 = %s, want CTL.A (tie-break by ID)", ranks[0].ControlID)
	}
}
