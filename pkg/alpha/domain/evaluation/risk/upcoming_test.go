package risk

import (
	"testing"
	"time"

	"github.com/sufield/stave/pkg/alpha/domain/asset"
	"github.com/sufield/stave/pkg/alpha/domain/kernel"
	"github.com/sufield/stave/pkg/alpha/domain/policy"
	"github.com/sufield/stave/pkg/alpha/domain/predicate"
)

func TestComputeItems_DeterministicOrder(t *testing.T) {
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

	celEval := mustPredicateEval()
	var expected []ThresholdItem
	for i := range 20 {
		items := ComputeItems(ThresholdRequest{
			Controls:                controls,
			Snapshots:               snapshots,
			GlobalMaxUnsafeDuration: 4 * time.Hour,
			Now:                     base.Add(time.Hour),
			PredicateEval:           celEval,
		})
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

func TestComputeItems_ResetsOnSafeTransition(t *testing.T) {
	base := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	controls := []policy.ControlDefinition{
		testControl("CTL.A", "2h"),
	}
	snapshots := []asset.Snapshot{
		{CapturedAt: base, Assets: []asset.Asset{testUnsafeResource(true)}},
		{CapturedAt: base.Add(1 * time.Hour), Assets: []asset.Asset{testUnsafeResource(false)}},
		{CapturedAt: base.Add(2 * time.Hour), Assets: []asset.Asset{testUnsafeResource(true)}},
	}

	items := ComputeItems(ThresholdRequest{
		Controls:                controls,
		Snapshots:               snapshots,
		GlobalMaxUnsafeDuration: 6 * time.Hour,
		Now:                     base.Add(2 * time.Hour),
		PredicateEval:           mustPredicateEval(),
	})
	if len(items) != 1 {
		t.Fatalf("items len = %d, want 1", len(items))
	}

	wantDueAt := base.Add(4 * time.Hour) // reset at t+2h and threshold 2h
	if !items[0].DueAt.Equal(wantDueAt) {
		t.Fatalf("dueAt = %s, want %s", items[0].DueAt, wantDueAt)
	}
	if items[0].Status != StatusUpcoming {
		t.Fatalf("status = %s, want %s", items[0].Status, StatusUpcoming)
	}
}

func TestComputeItems_UsesFallbackThresholdRules(t *testing.T) {
	base := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	snapshots := []asset.Snapshot{
		{CapturedAt: base, Assets: []asset.Asset{testUnsafeResource(true)}},
		{CapturedAt: base.Add(1 * time.Hour), Assets: []asset.Asset{testUnsafeResource(true)}},
	}

	celEval := mustPredicateEval()
	invalid := []policy.ControlDefinition{testControl("CTL.A", "not-a-duration")}
	items := ComputeItems(ThresholdRequest{
		Controls:                invalid,
		Snapshots:               snapshots,
		GlobalMaxUnsafeDuration: 5 * time.Hour,
		Now:                     base.Add(time.Hour),
		PredicateEval:           celEval,
	})
	if len(items) != 1 {
		t.Fatalf("items len = %d, want 1", len(items))
	}
	if want := base.Add(5 * time.Hour); !items[0].DueAt.Equal(want) {
		t.Fatalf("dueAt = %s, want fallback dueAt %s", items[0].DueAt, want)
	}

	zero := []policy.ControlDefinition{testControl("CTL.B", "0h")}
	items = ComputeItems(ThresholdRequest{
		Controls:                zero,
		Snapshots:               snapshots,
		GlobalMaxUnsafeDuration: 5 * time.Hour,
		Now:                     base.Add(time.Hour),
		PredicateEval:           celEval,
	})
	if len(items) != 1 {
		t.Fatalf("zero-threshold items len = %d, want 1", len(items))
	}
	if want := base; !items[0].DueAt.Equal(want) {
		t.Fatalf("zero-threshold dueAt = %s, want %s", items[0].DueAt, want)
	}
}

func TestSortItems_StatusUrgencyOrder(t *testing.T) {
	due := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	items := []ThresholdItem{
		{DueAt: due, Status: StatusUpcoming, ControlID: "CTL.A", AssetID: "r1"},
		{DueAt: due, Status: StatusDueNow, ControlID: "CTL.A", AssetID: "r1"},
		{DueAt: due, Status: StatusOverdue, ControlID: "CTL.A", AssetID: "r1"},
	}
	sortItems(items)

	// OVERDUE is most urgent, then DUE_NOW, then UPCOMING.
	want := []ThresholdStatus{StatusOverdue, StatusDueNow, StatusUpcoming}
	for i, w := range want {
		if items[i].Status != w {
			t.Fatalf("items[%d].Status = %s, want %s", i, items[i].Status, w)
		}
	}
}

func TestFilter_ByControlAndStatus(t *testing.T) {
	items := ThresholdItems{
		{ControlID: "CTL.A", AssetType: kernel.AssetType("storage_bucket"), Status: StatusOverdue, Remaining: -1 * time.Hour},
		{ControlID: "CTL.B", AssetType: kernel.AssetType("iam_role"), Status: StatusUpcoming, Remaining: 4 * time.Hour},
		{ControlID: "CTL.C", AssetType: kernel.AssetType("storage_bucket"), Status: StatusUpcoming, Remaining: 1 * time.Hour},
	}

	filtered := items.Filter(ThresholdFilter{
		AssetTypes:   map[kernel.AssetType]struct{}{kernel.AssetType("storage_bucket"): {}},
		Statuses:     map[ThresholdStatus]struct{}{StatusUpcoming: {}},
		MaxRemaining: 2 * time.Hour,
	})

	if len(filtered) != 1 {
		t.Fatalf("filtered len = %d, want 1", len(filtered))
	}
	if filtered[0].ControlID != "CTL.C" {
		t.Fatalf("filtered control ID = %s, want CTL.C", filtered[0].ControlID)
	}
}

func TestFilter_EmptyPassesAll(t *testing.T) {
	items := ThresholdItems{
		{ControlID: "CTL.A", Status: StatusOverdue},
		{ControlID: "CTL.B", Status: StatusUpcoming},
	}
	filtered := items.Filter(ThresholdFilter{})
	if len(filtered) != 2 {
		t.Fatalf("empty filter should pass all items, got %d", len(filtered))
	}
}

func testControl(id string, threshold string) policy.ControlDefinition {
	var params policy.ControlParams
	if threshold != "" {
		params = policy.NewParams(map[string]any{"max_unsafe_duration": threshold})
	}

	ctl := policy.ControlDefinition{
		ID:     kernel.ControlID(id),
		Name:   id,
		Type:   policy.TypeUnsafeDuration,
		Params: params,
		UnsafePredicate: policy.UnsafePredicate{
			Any: []policy.PredicateRule{
				{
					Field: predicate.NewFieldPath("properties.unsafe"),
					Op:    "eq",
					Value: policy.Bool(true),
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
		Vendor: kernel.Vendor("aws"),
		Properties: map[string]any{
			"unsafe": unsafe,
		},
	}
}
