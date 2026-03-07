package upcoming

import (
	"strings"
	"testing"
	"time"

	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/policy"
)

func TestComputeUpcomingItems_SortsChronologicallyAndComputesStatus(t *testing.T) {
	t1 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	now := time.Date(2026, 1, 2, 12, 0, 0, 0, time.UTC)

	snapshots := []asset.Snapshot{
		{
			CapturedAt: t1,
			Assets: []asset.Asset{
				{
					ID: "bucket-a",
					Properties: map[string]any{
						"public": true,
					},
				},
			},
		},
		{
			CapturedAt: t2,
			Assets: []asset.Asset{
				{
					ID: "bucket-a",
					Properties: map[string]any{
						"public": true,
					},
				},
			},
		},
	}

	ctl24h := policy.ControlDefinition{
		ID:   "CTL.24H",
		Type: policy.TypeUnsafeDuration,
		UnsafePredicate: policy.UnsafePredicate{
			Any: []policy.PredicateRule{
				{Field: "properties.public", Op: "eq", Value: true},
			},
		},
		Params: policy.ControlParams{
			"max_unsafe_duration": "24h",
		},
	}
	_ = ctl24h.Prepare()

	ctl48h := policy.ControlDefinition{
		ID:   "CTL.48H",
		Type: policy.TypeUnsafeDuration,
		UnsafePredicate: policy.UnsafePredicate{
			Any: []policy.PredicateRule{
				{Field: "properties.public", Op: "eq", Value: true},
			},
		},
		Params: policy.ControlParams{
			"max_unsafe_duration": "48h",
		},
	}
	_ = ctl48h.Prepare()

	controls := []policy.ControlDefinition{ctl24h, ctl48h}

	items := computeUpcomingItems(snapshots, controls, UpcomingComputeOptions{GlobalMaxUnsafe: 168 * time.Hour, Now: now})
	if len(items) != 2 {
		t.Fatalf("expected 2 upcoming items, got %d", len(items))
	}

	if items[0].ControlID != "CTL.24H" {
		t.Fatalf("expected first item CTL.24H, got %s", items[0].ControlID)
	}
	if items[0].Status != "OVERDUE" {
		t.Fatalf("expected first status OVERDUE, got %s", items[0].Status)
	}
	if items[1].ControlID != "CTL.48H" {
		t.Fatalf("expected second item CTL.48H, got %s", items[1].ControlID)
	}
	if items[1].Status != "UPCOMING" {
		t.Fatalf("expected second status UPCOMING, got %s", items[1].Status)
	}
	if !items[0].DueAt.Before(items[1].DueAt) {
		t.Fatalf("expected due times sorted ascending: %s !< %s", items[0].DueAt, items[1].DueAt)
	}
}

func TestRenderUpcomingMarkdown_NoItems(t *testing.T) {
	now := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	out := renderUpcomingMarkdown(nil, UpcomingSummary{}, UpcomingRenderOptions{Now: now, DueSoonThreshold: 24 * time.Hour})
	if !strings.Contains(out, "No upcoming snapshot action items.") {
		t.Fatalf("expected no-items message, got: %s", out)
	}
}

func TestSummarizeUpcoming_DueSoonBuckets(t *testing.T) {
	now := time.Date(2026, 1, 2, 12, 0, 0, 0, time.UTC)
	items := []UpcomingItem{
		{Status: "OVERDUE", Remaining: -2 * time.Hour, DueAt: now.Add(-2 * time.Hour)},
		{Status: "DUE_NOW", Remaining: 0, DueAt: now},
		{Status: "UPCOMING", Remaining: 3 * time.Hour, DueAt: now.Add(3 * time.Hour)},
		{Status: "UPCOMING", Remaining: 72 * time.Hour, DueAt: now.Add(72 * time.Hour)},
	}
	s := summarizeUpcoming(items, 6*time.Hour)
	if s.Overdue != 1 || s.DueNow != 1 || s.DueSoon != 1 || s.Later != 1 || s.Total != 4 {
		t.Fatalf("unexpected summary: %+v", s)
	}
	md := renderUpcomingSummaryMarkdown(s, 6*time.Hour)
	if !strings.Contains(md, "Due soon (<= 6h): **1**") {
		t.Fatalf("expected due-soon line in summary markdown, got: %s", md)
	}
}

func TestNewUpcomingFilter_InvalidStatus(t *testing.T) {
	_, err := newUpcomingFilter(UpcomingFilterCriteria{Statuses: []string{"later"}})
	if err == nil {
		t.Fatal("expected invalid status error")
	}
	if !strings.Contains(err.Error(), "invalid --status") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestApplyUpcomingFilter(t *testing.T) {
	now := time.Date(2026, 1, 2, 12, 0, 0, 0, time.UTC)
	items := []UpcomingItem{
		{
			DueAt:     now.Add(2 * time.Hour),
			Status:    "UPCOMING",
			ControlID: "CTL.TEST.A.001",
			AssetType: "res:aws:s3:bucket",
		},
		{
			DueAt:     now.Add(72 * time.Hour),
			Status:    "UPCOMING",
			ControlID: "CTL.TEST.B.001",
			AssetType: "res:aws:s3:bucket",
		},
		{
			DueAt:     now.Add(-1 * time.Hour),
			Status:    "OVERDUE",
			ControlID: "CTL.TEST.A.001",
			AssetType: "res:aws:s3:bucket",
		},
	}
	dueWithin := 24 * time.Hour
	filter, err := newUpcomingFilter(UpcomingFilterCriteria{
		ControlIDs: []kernel.ControlID{"CTL.TEST.A.001"},
		AssetTypes: []kernel.AssetType{"res:aws:s3:bucket"},
		Statuses:   []string{"OVERDUE", "UPCOMING"},
		DueWithin:  &dueWithin,
	})
	if err != nil {
		t.Fatalf("new filter: %v", err)
	}
	filtered := applyUpcomingFilter(items, now, filter)
	if len(filtered) != 2 {
		t.Fatalf("expected 2 filtered items, got %d", len(filtered))
	}
	for _, item := range filtered {
		if item.ControlID != "CTL.TEST.A.001" {
			t.Fatalf("unexpected control in filtered results: %+v", item)
		}
		if item.DueAt.Sub(now) > dueWithin {
			t.Fatalf("item outside due-within filter: %+v", item)
		}
	}
}
