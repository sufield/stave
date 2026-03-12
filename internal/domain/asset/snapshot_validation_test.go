package asset

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/domain/diag"
	"github.com/sufield/stave/internal/domain/kernel"
)

func TestSnapshotsCheckTimeSanity_DedupesDuplicateTimestamps(t *testing.T) {
	ts := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	snaps := Snapshots{
		{CapturedAt: ts},
		{CapturedAt: ts},
		{CapturedAt: ts},
	}

	ctx := snaps.analyze()
	issues := snaps.checkTimeSanity(ctx, time.Time{})

	dupCount := 0
	for _, issue := range issues {
		if issue.Code == diag.CodeDuplicateTimestamp {
			dupCount++
		}
	}

	if dupCount != 1 {
		t.Fatalf("duplicate timestamp issue count = %d, want 1 (%v)", dupCount, issues)
	}
}

func TestSnapshotsCheckIdentityConsistency_DeterministicOrdering(t *testing.T) {
	snaps := Snapshots{
		{
			CapturedAt: time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC),
			Assets: []Asset{
				{ID: "b", Type: kernel.AssetType("storage_bucket")},
				{ID: "a", Type: kernel.AssetType("storage_bucket")},
			},
		},
		{
			CapturedAt: time.Date(2026, 1, 11, 0, 0, 0, 0, time.UTC),
			Assets: []Asset{
				{ID: "b", Type: kernel.AssetType("iam_role")},
				{ID: "c", Type: kernel.AssetType("storage_bucket")},
			},
		},
	}

	ctx := snaps.analyze()
	issues := snaps.checkIdentityConsistency(ctx)

	var orderedIDs []string
	for _, issue := range issues {
		id, _ := issue.Evidence.Get("asset_id")
		if id != "" {
			orderedIDs = append(orderedIDs, id)
		}
	}

	// Reused type issue first, then single-appearance IDs sorted.
	want := []string{"b", "a", "c"}
	if len(orderedIDs) != len(want) {
		t.Fatalf("ordered IDs len = %d, want %d (%v)", len(orderedIDs), len(want), orderedIDs)
	}
	for i := range want {
		if orderedIDs[i] != want[i] {
			t.Fatalf("ordered IDs[%d] = %q, want %q (all=%v)", i, orderedIDs[i], want[i], orderedIDs)
		}
	}
}

func TestSnapshotsCheckTimeSanity_ReportsFirstUnsortedPair(t *testing.T) {
	snaps := Snapshots{
		{CapturedAt: time.Date(2026, 1, 12, 0, 0, 0, 0, time.UTC)},
		{CapturedAt: time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC)},
		{CapturedAt: time.Date(2026, 1, 11, 0, 0, 0, 0, time.UTC)},
	}

	ctx := snaps.analyze()
	issues := snaps.checkTimeSanity(ctx, time.Time{})

	var gotSnapshotAt, gotComesBefore string
	var found bool
	for _, issue := range issues {
		if issue.Code == diag.CodeSnapshotsUnsorted {
			gotSnapshotAt, _ = issue.Evidence.Get("snapshot_at")
			gotComesBefore, _ = issue.Evidence.Get("comes_before")
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected %s issue, got: %v", diag.CodeSnapshotsUnsorted, issues)
	}
	if gotSnapshotAt != "2026-01-10T00:00:00Z" {
		t.Fatalf("snapshot_at=%q, want %q", gotSnapshotAt, "2026-01-10T00:00:00Z")
	}
	if gotComesBefore != "2026-01-12T00:00:00Z" {
		t.Fatalf("comes_before=%q, want %q", gotComesBefore, "2026-01-12T00:00:00Z")
	}
}

func TestSnapshotsCheckTimeSanity_ReportsNowBeforeLatest(t *testing.T) {
	snaps := Snapshots{
		{CapturedAt: time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC)},
		{CapturedAt: time.Date(2026, 1, 12, 0, 0, 0, 0, time.UTC)},
	}

	ctx := snaps.analyze()
	now := time.Date(2026, 1, 11, 0, 0, 0, 0, time.UTC)
	issues := snaps.checkTimeSanity(ctx, now)

	var nowIssueFound bool
	for _, issue := range issues {
		if issue.Code != diag.CodeNowBeforeSnapshots {
			continue
		}
		nowIssueFound = true
		if issue.Command != "stave validate --now 2026-01-12T00:00:00Z" {
			t.Fatalf("command=%q", issue.Command)
		}
		latest, _ := issue.Evidence.Get("latest_snapshot")
		if latest != "2026-01-12T00:00:00Z" {
			t.Fatalf("latest_snapshot=%q", latest)
		}
	}
	if !nowIssueFound {
		t.Fatalf("expected %s issue, got: %v", diag.CodeNowBeforeSnapshots, issues)
	}
}
