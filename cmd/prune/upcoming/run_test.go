package upcoming

import (
	"strings"
	"testing"
	"time"

	textout "github.com/sufield/stave/internal/adapters/output/text"
	stavecel "github.com/sufield/stave/internal/cel"
	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/evaluation/risk"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/policy"
	"github.com/sufield/stave/internal/domain/predicate"
)

func TestComputeAndMapItems_SortsChronologicallyAndComputesStatus(t *testing.T) {
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
				{Field: predicate.NewFieldPath("properties.public"), Op: predicate.OpEq, Value: policy.Bool(true)},
			},
		},
		Params: policy.NewParams(map[string]any{
			"max_unsafe_duration": "24h",
		}),
	}
	_ = ctl24h.Prepare()

	ctl48h := policy.ControlDefinition{
		ID:   "CTL.48H",
		Type: policy.TypeUnsafeDuration,
		UnsafePredicate: policy.UnsafePredicate{
			Any: []policy.PredicateRule{
				{Field: predicate.NewFieldPath("properties.public"), Op: predicate.OpEq, Value: policy.Bool(true)},
			},
		},
		Params: policy.NewParams(map[string]any{
			"max_unsafe_duration": "48h",
		}),
	}
	_ = ctl48h.Prepare()

	controls := []policy.ControlDefinition{ctl24h, ctl48h}

	riskItems := risk.ComputeItems(risk.Request{
		Controls:        controls,
		Snapshots:       snapshots,
		GlobalMaxUnsafe: 168 * time.Hour,
		Now:             now,
		PredicateEval:   stavecel.MustPredicateEval(),
	})
	items := mapRiskItems(riskItems)
	if len(items) != 2 {
		t.Fatalf("expected 2 upcoming items, got %d", len(items))
	}

	if items[0].ControlID != "CTL.24H" {
		t.Fatalf("expected first item CTL.24H, got %s", items[0].ControlID)
	}
	if items[0].Status != risk.StatusOverdue {
		t.Fatalf("expected first status OVERDUE, got %s", items[0].Status)
	}
	if items[1].ControlID != "CTL.48H" {
		t.Fatalf("expected second item CTL.48H, got %s", items[1].ControlID)
	}
	if items[1].Status != risk.StatusUpcoming {
		t.Fatalf("expected second status UPCOMING, got %s", items[1].Status)
	}
	if !items[0].DueAt.Before(items[1].DueAt) {
		t.Fatalf("expected due times sorted ascending: %s !< %s", items[0].DueAt, items[1].DueAt)
	}
}

func TestRenderUpcomingMarkdown_NoItems(t *testing.T) {
	now := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	out := textout.RenderUpcomingMarkdown(nil, textout.UpcomingSummary{}, textout.UpcomingRenderOptions{Now: now, DueSoonThreshold: 24 * time.Hour})
	if !strings.Contains(out, "No upcoming snapshot action items.") {
		t.Fatalf("expected no-items message, got: %s", out)
	}
}

func TestSummarizeUpcoming_DueSoonBuckets(t *testing.T) {
	now := time.Date(2026, 1, 2, 12, 0, 0, 0, time.UTC)
	items := []Item{
		{Status: risk.StatusOverdue, Remaining: -2 * time.Hour, DueAt: now.Add(-2 * time.Hour)},
		{Status: risk.StatusDueNow, Remaining: 0, DueAt: now},
		{Status: risk.StatusUpcoming, Remaining: 3 * time.Hour, DueAt: now.Add(3 * time.Hour)},
		{Status: risk.StatusUpcoming, Remaining: 72 * time.Hour, DueAt: now.Add(72 * time.Hour)},
	}
	s := summarizeUpcoming(items, 6*time.Hour)
	if s.Overdue != 1 || s.DueNow != 1 || s.DueSoon != 1 || s.Later != 1 || s.Total != 4 {
		t.Fatalf("unexpected summary: %+v", s)
	}
	md := textout.RenderUpcomingSummaryMarkdown(toAdapterSummary(s), 6*time.Hour)
	if !strings.Contains(md, "Due soon (<= 6h): **1**") {
		t.Fatalf("expected due-soon line in summary markdown, got: %s", md)
	}
}

func TestNewUpcomingFilter_InvalidStatus(t *testing.T) {
	_, err := newUpcomingFilter(FilterCriteria{Statuses: []string{"later"}})
	if err == nil {
		t.Fatal("expected invalid status error")
	}
	if !strings.Contains(err.Error(), "invalid status") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRiskItemsFilter(t *testing.T) {
	now := time.Date(2026, 1, 2, 12, 0, 0, 0, time.UTC)
	riskItems := risk.Items{
		{
			DueAt:     now.Add(2 * time.Hour),
			Status:    risk.StatusUpcoming,
			ControlID: "CTL.TEST.A.001",
			AssetType: "res:aws:s3:bucket",
			Remaining: 2 * time.Hour,
		},
		{
			DueAt:     now.Add(72 * time.Hour),
			Status:    risk.StatusUpcoming,
			ControlID: "CTL.TEST.B.001",
			AssetType: "res:aws:s3:bucket",
			Remaining: 72 * time.Hour,
		},
		{
			DueAt:     now.Add(-1 * time.Hour),
			Status:    risk.StatusOverdue,
			ControlID: "CTL.TEST.A.001",
			AssetType: "res:aws:s3:bucket",
			Remaining: -1 * time.Hour,
		},
	}
	filter, err := newUpcomingFilter(FilterCriteria{
		ControlIDs: []kernel.ControlID{"CTL.TEST.A.001"},
		AssetTypes: []kernel.AssetType{"res:aws:s3:bucket"},
		Statuses:   []string{"OVERDUE", "UPCOMING"},
		DueWithin:  24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("new filter: %v", err)
	}
	filtered := riskItems.Filter(filter)
	items := mapRiskItems(filtered)
	if len(items) != 2 {
		t.Fatalf("expected 2 filtered items, got %d", len(items))
	}
	for _, item := range items {
		if item.ControlID != "CTL.TEST.A.001" {
			t.Fatalf("unexpected control in filtered results: %+v", item)
		}
	}
}

func TestRiskFilterCriteria_FromNewUpcomingFilter(t *testing.T) {
	criteria, err := newUpcomingFilter(FilterCriteria{
		ControlIDs: []kernel.ControlID{"CTL.A"},
		AssetTypes: []kernel.AssetType{kernel.AssetType("storage_bucket")},
		Statuses:   []string{"OVERDUE"},
		DueWithin:  12 * time.Hour,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(criteria.ControlIDs) != 1 {
		t.Fatalf("expected 1 control ID, got %d", len(criteria.ControlIDs))
	}
	if _, ok := criteria.ControlIDs["CTL.A"]; !ok {
		t.Fatal("expected CTL.A in control IDs")
	}
	if len(criteria.Statuses) != 1 {
		t.Fatalf("expected 1 status, got %d", len(criteria.Statuses))
	}
	if _, ok := criteria.Statuses[risk.StatusOverdue]; !ok {
		t.Fatal("expected OVERDUE in statuses")
	}
	if criteria.MaxRemaining != 12*time.Hour {
		t.Fatalf("expected MaxRemaining=%v, got %v", 12*time.Hour, criteria.MaxRemaining)
	}
}

func TestRiskFilterCriteria_EmptyPassesAll(t *testing.T) {
	items := risk.Items{
		{Status: risk.StatusOverdue, ControlID: "CTL.A"},
		{Status: risk.StatusUpcoming, ControlID: "CTL.B"},
	}
	criteria := risk.FilterCriteria{}
	filtered := items.Filter(criteria)
	if len(filtered) != 2 {
		t.Fatalf("empty filter should pass all items, got %d", len(filtered))
	}
}

func TestRiskFilterCriteria_ViaInlineToSet(t *testing.T) {
	controlIDs := []kernel.ControlID{"CTL.A", "CTL.B"}
	set := make(map[kernel.ControlID]struct{}, len(controlIDs))
	for _, item := range controlIDs {
		set[item] = struct{}{}
	}
	if len(set) != 2 {
		t.Fatalf("expected set of 2, got %d", len(set))
	}
}
