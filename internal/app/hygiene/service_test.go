package hygiene

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/evaluation/risk"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/policy"
)

func TestComputeUpcomingItems_DeterministicOrder(t *testing.T) {
	base := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	controls := []policy.ControlDefinition{
		testControl("CTL.B", "2h"),
		testControl("CTL.A", "2h"),
	}
	snapshots := []asset.Snapshot{
		{
			CapturedAt: base,
			Assets: []asset.Asset{
				testUnsafeResource(true),
			},
		},
		{
			CapturedAt: base.Add(1 * time.Hour),
			Assets: []asset.Asset{
				testUnsafeResource(true),
			},
		},
	}

	var expected []upcomingItem
	for i := range 20 {
		items := computeUpcomingItems(controls, snapshots, RiskOptions{GlobalMaxUnsafe: 4 * time.Hour, Now: base.Add(time.Hour)})
		if len(items) != 2 {
			t.Fatalf("iteration %d: items len = %d, want 2", i, len(items))
		}
		if i == 0 {
			expected = items
			continue
		}
		for j := range items {
			if items[j].ControlID != expected[j].ControlID || items[j].DueAt != expected[j].DueAt || items[j].Status != expected[j].Status {
				t.Fatalf("iteration %d: non-deterministic order item[%d]=%+v expected=%+v", i, j, items[j], expected[j])
			}
		}
	}

	if expected[0].ControlID != "CTL.A" || expected[1].ControlID != "CTL.B" {
		t.Fatalf("sorted control order = [%s, %s], want [CTL.A, CTL.B]", expected[0].ControlID, expected[1].ControlID)
	}
}

func TestComputeUpcomingItems_ResetsOnSafeTransition(t *testing.T) {
	base := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	controls := []policy.ControlDefinition{
		testControl("CTL.A", "2h"),
	}
	snapshots := []asset.Snapshot{
		{CapturedAt: base, Assets: []asset.Asset{testUnsafeResource(true)}},
		{CapturedAt: base.Add(1 * time.Hour), Assets: []asset.Asset{testUnsafeResource(false)}},
		{CapturedAt: base.Add(2 * time.Hour), Assets: []asset.Asset{testUnsafeResource(true)}},
	}

	items := computeUpcomingItems(controls, snapshots, RiskOptions{GlobalMaxUnsafe: 6 * time.Hour, Now: base.Add(2 * time.Hour)})
	if len(items) != 1 {
		t.Fatalf("items len = %d, want 1", len(items))
	}

	wantDueAt := base.Add(4 * time.Hour) // reset at t+2h and threshold 2h
	if !items[0].DueAt.Equal(wantDueAt) {
		t.Fatalf("dueAt = %s, want %s", items[0].DueAt, wantDueAt)
	}
	if items[0].Status != risk.Upcoming {
		t.Fatalf("status = %s, want %s", items[0].Status, risk.Upcoming)
	}
}

func TestApplyUpcomingFilter_NormalizationAndDueWithin(t *testing.T) {
	dueSoon := 2 * time.Hour
	items := []upcomingItem{
		{
			ControlID: "CTL.A",
			AssetType: kernel.TypeStorageBucket,
			Status:    risk.Overdue,
			Remaining: -1 * time.Hour,
		},
		{
			ControlID: "CTL.B",
			AssetType: kernel.TypeIAMRole,
			Status:    risk.Upcoming,
			Remaining: 4 * time.Hour,
		},
		{
			ControlID: "CTL.C",
			AssetType: kernel.TypeStorageBucket,
			Status:    risk.Upcoming,
			Remaining: 1 * time.Hour,
		},
	}

	filtered := applyUpcomingFilter(items, RiskOptions{
		AssetTypes: []kernel.AssetType{kernel.TypeStorageBucket},
		Statuses:   []risk.Status{risk.Upcoming},
		DueWithin:  &dueSoon,
	})

	if len(filtered) != 1 {
		t.Fatalf("filtered len = %d, want 1 (%v)", len(filtered), filtered)
	}
	if filtered[0].ControlID != "CTL.C" {
		t.Fatalf("filtered control ID = %s, want CTL.C", filtered[0].ControlID)
	}
}

func TestComputeUpcomingItems_UsesFallbackThresholdRules(t *testing.T) {
	base := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	snapshots := []asset.Snapshot{
		{CapturedAt: base, Assets: []asset.Asset{testUnsafeResource(true)}},
		{CapturedAt: base.Add(1 * time.Hour), Assets: []asset.Asset{testUnsafeResource(true)}},
	}

	invalid := []policy.ControlDefinition{testControl("CTL.A", "not-a-duration")}
	items := computeUpcomingItems(invalid, snapshots, RiskOptions{GlobalMaxUnsafe: 5 * time.Hour, Now: base.Add(time.Hour)})
	if len(items) != 1 {
		t.Fatalf("items len = %d, want 1", len(items))
	}
	if want := base.Add(5 * time.Hour); !items[0].DueAt.Equal(want) {
		t.Fatalf("dueAt = %s, want fallback dueAt %s", items[0].DueAt, want)
	}

	zero := []policy.ControlDefinition{testControl("CTL.B", "0h")}
	items = computeUpcomingItems(zero, snapshots, RiskOptions{GlobalMaxUnsafe: 5 * time.Hour, Now: base.Add(time.Hour)})
	if len(items) != 1 {
		t.Fatalf("zero-threshold items len = %d, want 1", len(items))
	}
	if want := base; !items[0].DueAt.Equal(want) {
		t.Fatalf("zero-threshold dueAt = %s, want %s", items[0].DueAt, want)
	}
}

func TestComputeRisk_WithViolations(t *testing.T) {
	base := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	now := base.Add(2 * time.Hour)
	controls := []policy.ControlDefinition{
		testControl("CTL.A", ""),
	}
	snapshots := []asset.Snapshot{
		{CapturedAt: base, Assets: []asset.Asset{testUnsafeResource(true)}},
		{CapturedAt: base.Add(1 * time.Hour), Assets: []asset.Asset{testUnsafeResource(true)}},
	}

	svc := NewService()
	stats := svc.ComputeRisk(controls, snapshots, RiskOptions{
		GlobalMaxUnsafe:  30 * time.Minute,
		Now:              now,
		DueSoonThreshold: 2 * time.Hour,
		ToolVersion:      "test",
	})
	if stats.CurrentViolations == 0 {
		t.Fatalf("expected violations in risk stats, got %+v", stats)
	}
	if stats.UpcomingTotal == 0 {
		t.Fatalf("expected upcoming metrics in risk stats, got %+v", stats)
	}
}

func TestComputeRisk_EmptyInput(t *testing.T) {
	svc := NewService()
	stats := svc.ComputeRisk(nil, nil, RiskOptions{
		GlobalMaxUnsafe:  24 * time.Hour,
		Now:              time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
		DueSoonThreshold: time.Hour,
	})
	if stats != (RiskStats{}) {
		t.Fatalf("empty risk expected, got %+v", stats)
	}
}

func TestComputeUpcomingSummary_AndSummarize(t *testing.T) {
	base := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	controls := []policy.ControlDefinition{
		testControl("CTL.A", "2h"),
	}
	snapshots := []asset.Snapshot{
		{CapturedAt: base, Assets: []asset.Asset{testUnsafeResource(true)}},
		{CapturedAt: base.Add(1 * time.Hour), Assets: []asset.Asset{testUnsafeResource(true)}},
	}
	opts := RiskOptions{
		GlobalMaxUnsafe:  4 * time.Hour,
		Now:              base.Add(1 * time.Hour),
		DueSoonThreshold: 90 * time.Minute,
		Statuses:         []risk.Status{risk.Upcoming},
		AssetTypes:       []kernel.AssetType{kernel.TypeStorageBucket},
	}

	summary := computeUpcomingSummary(controls, snapshots, opts)
	if summary.Total != 1 || summary.DueSoon != 1 {
		t.Fatalf("unexpected summary: %+v", summary)
	}

	manual := risk.Items{
		{Status: risk.Overdue, Remaining: -time.Hour},
		{Status: risk.DueNow, Remaining: 0},
		{Status: risk.Upcoming, Remaining: 30 * time.Minute},
		{Status: risk.Upcoming, Remaining: 4 * time.Hour},
	}.Summarize(time.Hour)
	if manual.Overdue != 1 || manual.DueNow != 1 || manual.DueSoon != 1 || manual.Later != 1 || manual.Total != 4 {
		t.Fatalf("unexpected manual summary: %+v", manual)
	}
}

func testControl(id string, threshold string) policy.ControlDefinition {
	params := policy.ControlParams{}
	if threshold != "" {
		params["max_unsafe_duration"] = threshold
	}

	ctl := policy.ControlDefinition{
		ID:     kernel.ControlID(id),
		Name:   id,
		Type:   policy.TypeUnsafeDuration,
		Params: params,
		UnsafePredicate: policy.UnsafePredicate{
			Any: []policy.PredicateRule{
				{
					Field: "properties.unsafe",
					Op:    "eq",
					Value: true,
				},
			},
		},
	}
	_ = ctl.Prepare() // error is ok for invalid test durations
	return ctl
}

func testUnsafeResource(unsafe bool) asset.Asset {
	return asset.Asset{
		ID:     asset.ID("res-1"),
		Type:   kernel.TypeStorageBucket,
		Vendor: kernel.VendorAWS,
		Properties: map[string]any{
			"unsafe": unsafe,
		},
	}
}
