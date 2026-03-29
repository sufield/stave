package retention

import (
	"testing"
	"time"
)

func TestTier_Validate(t *testing.T) {
	tests := []struct {
		name    string
		tier    Tier
		wantErr bool
	}{
		{"valid 30d", Tier{OlderThan: "30d"}, false},
		{"valid 168h", Tier{OlderThan: "168h"}, false},
		{"empty older_than", Tier{OlderThan: ""}, true},
		{"invalid duration", Tier{OlderThan: "notaduration"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.tier.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() err=%v, wantErr=%v", err, tt.wantErr)
			}
		})
	}
}

func TestTier_Duration(t *testing.T) {
	tests := []struct {
		name    string
		tier    Tier
		want    time.Duration
		wantErr bool
	}{
		{"30d", Tier{OlderThan: "30d"}, 30 * 24 * time.Hour, false},
		{"168h", Tier{OlderThan: "168h"}, 168 * time.Hour, false},
		{"empty returns zero", Tier{OlderThan: ""}, 0, false},
		{"invalid", Tier{OlderThan: "xyz"}, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.tier.Duration()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Duration() err=%v, wantErr=%v", err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Fatalf("Duration()=%v, want %v", got, tt.want)
			}
		})
	}
}

func TestTier_MinRetained(t *testing.T) {
	tests := []struct {
		name    string
		keepMin int
		want    int
	}{
		{"positive value", 5, 5},
		{"zero defaults", 0, DefaultKeepMin},
		{"negative defaults", -1, DefaultKeepMin},
		{"one", 1, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tier := Tier{OlderThan: "1d", KeepMin: tt.keepMin}
			if got := tier.MinRetained(); got != tt.want {
				t.Fatalf("MinRetained()=%d, want %d", got, tt.want)
			}
		})
	}
}

func TestTier_ParseDuration(t *testing.T) {
	tests := []struct {
		name    string
		tier    Tier
		want    time.Duration
		wantErr bool
	}{
		{"valid", Tier{OlderThan: "7d"}, 7 * 24 * time.Hour, false},
		{"empty returns error", Tier{OlderThan: ""}, 0, true},
		{"invalid returns error", Tier{OlderThan: "bad"}, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.tier.ParseDuration()
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseDuration() err=%v, wantErr=%v", err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Fatalf("ParseDuration()=%v, want %v", got, tt.want)
			}
		})
	}
}

func TestTier_EffectiveKeepMin(t *testing.T) {
	tier := Tier{OlderThan: "1d", KeepMin: 3}
	if got := tier.EffectiveKeepMin(); got != 3 {
		t.Fatalf("EffectiveKeepMin()=%d, want 3", got)
	}
	tier.KeepMin = 0
	if got := tier.EffectiveKeepMin(); got != DefaultKeepMin {
		t.Fatalf("EffectiveKeepMin()=%d, want %d", got, DefaultKeepMin)
	}
}

func TestRule_Validate(t *testing.T) {
	tests := []struct {
		name    string
		rule    Rule
		wantErr bool
	}{
		{"valid", Rule{Pattern: "*.json", Tier: "default"}, false},
		{"empty pattern", Rule{Pattern: "", Tier: "default"}, true},
		{"empty tier", Rule{Pattern: "*.json", Tier: ""}, true},
		{"both empty", Rule{Pattern: "", Tier: ""}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.rule.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() err=%v, wantErr=%v", err, tt.wantErr)
			}
		})
	}
}

func TestDefaultKeepMin(t *testing.T) {
	if DefaultKeepMin < 1 {
		t.Fatalf("DefaultKeepMin=%d, want >= 1", DefaultKeepMin)
	}
}

func TestPlanPrune_AllExpired(t *testing.T) {
	now := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	items := []Candidate{
		{Index: 0, CapturedAt: now.AddDate(0, 0, -60)},
		{Index: 1, CapturedAt: now.AddDate(0, 0, -50)},
		{Index: 2, CapturedAt: now.AddDate(0, 0, -40)},
		{Index: 3, CapturedAt: now.AddDate(0, 0, -35)},
	}

	out := PlanPrune(items, Criteria{
		Now:       now,
		OlderThan: 30 * 24 * time.Hour,
		KeepMin:   2,
	})
	// All 4 expired, but keepMin=2 means at most 2 prunable.
	if len(out) != 2 {
		t.Fatalf("len(out)=%d, want 2", len(out))
	}
}

func TestPlanPrune_NoneExpired(t *testing.T) {
	now := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	items := []Candidate{
		{Index: 0, CapturedAt: now.AddDate(0, 0, -5)},
		{Index: 1, CapturedAt: now.AddDate(0, 0, -3)},
		{Index: 2, CapturedAt: now.AddDate(0, 0, -1)},
	}

	out := PlanPrune(items, Criteria{
		Now:       now,
		OlderThan: 30 * 24 * time.Hour,
		KeepMin:   2,
	})
	if len(out) != 0 {
		t.Fatalf("len(out)=%d, want 0", len(out))
	}
}

func TestPlanPrune_Empty(t *testing.T) {
	out := PlanPrune(nil, Criteria{
		Now:       time.Now(),
		OlderThan: time.Hour,
		KeepMin:   0,
	})
	if out != nil {
		t.Fatalf("expected nil for empty input, got %v", out)
	}
}

func TestPlanPrune_ZeroOlderThan(t *testing.T) {
	now := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	items := []Candidate{
		{Index: 0, CapturedAt: now.Add(-time.Hour)},
		{Index: 1, CapturedAt: now.Add(-time.Minute)},
		{Index: 2, CapturedAt: now.Add(time.Second)},
	}

	out := PlanPrune(items, Criteria{
		Now:       now,
		OlderThan: 0,
		KeepMin:   1,
	})
	// Cutoff = now, so items before now are prunable. Item 0 and 1 are before now.
	// maxPrunable = 3 - 1 = 2
	if len(out) != 2 {
		t.Fatalf("len(out)=%d, want 2", len(out))
	}
}
