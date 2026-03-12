package hygiene

import (
	"testing"
	"time"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/evaluation/risk"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/policy"
)

func TestComputeUpcomingSummary_FilterIntegration(t *testing.T) {
	base := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	dueSoon := 2 * time.Hour
	controls := []policy.ControlDefinition{
		testControl("CTL.A", "2h"),
	}
	snapshots := []asset.Snapshot{
		{CapturedAt: base, Assets: []asset.Asset{testUnsafeResource(true)}},
		{CapturedAt: base.Add(1 * time.Hour), Assets: []asset.Asset{testUnsafeResource(true)}},
	}

	summary := computeUpcomingSummary(controls, snapshots, RiskOptions{
		GlobalMaxUnsafe:  4 * time.Hour,
		Now:              base.Add(1 * time.Hour),
		DueSoonThreshold: 90 * time.Minute,
		Statuses:         []risk.Status{risk.StatusUpcoming},
		AssetTypes:       []kernel.AssetType{kernel.AssetType("storage_bucket")},
		DueWithin:        &dueSoon,
	})
	if summary.Total != 1 || summary.DueSoon != 1 {
		t.Fatalf("unexpected summary: %+v", summary)
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
	if stats != (appcontracts.RiskStats{}) {
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
		Statuses:         []risk.Status{risk.StatusUpcoming},
		AssetTypes:       []kernel.AssetType{kernel.AssetType("storage_bucket")},
	}

	summary := computeUpcomingSummary(controls, snapshots, opts)
	if summary.Total != 1 || summary.DueSoon != 1 {
		t.Fatalf("unexpected summary: %+v", summary)
	}

	manual := risk.Items{
		{Status: risk.StatusOverdue, Remaining: -time.Hour},
		{Status: risk.StatusDueNow, Remaining: 0},
		{Status: risk.StatusUpcoming, Remaining: 30 * time.Minute},
		{Status: risk.StatusUpcoming, Remaining: 4 * time.Hour},
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
		Type:   kernel.AssetType("storage_bucket"),
		Vendor: kernel.VendorAWS,
		Properties: map[string]any{
			"unsafe": unsafe,
		},
	}
}
