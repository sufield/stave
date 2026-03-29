package text

import (
	"strings"
	"testing"
	"time"
)

func TestRenderUpcomingMarkdown_NoItems(t *testing.T) {
	opts := UpcomingRenderOptions{
		Now:              time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC),
		DueSoonThreshold: 24 * time.Hour,
	}
	summary := UpcomingSummary{}
	out := RenderUpcomingMarkdown(nil, summary, opts)
	if !strings.Contains(out, "No upcoming snapshot action items.") {
		t.Fatalf("expected no-items message, got:\n%s", out)
	}
	if !strings.Contains(out, "# Upcoming Snapshot Action Items") {
		t.Fatalf("missing header, got:\n%s", out)
	}
}

func TestRenderUpcomingMarkdown_WithItems(t *testing.T) {
	now := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	opts := UpcomingRenderOptions{
		Now:              now,
		DueSoonThreshold: 24 * time.Hour,
	}
	items := []UpcomingItem{
		{
			DueAt:          now.Add(2 * time.Hour),
			Status:         "UPCOMING",
			ControlID:      "CTL.A",
			AssetID:        "res-1",
			AssetType:      "aws:s3:bucket",
			FirstUnsafeAt:  now.Add(-22 * time.Hour),
			LastSeenUnsafe: now,
			Threshold:      24 * time.Hour,
			Remaining:      2 * time.Hour,
		},
	}
	summary := UpcomingSummary{DueSoon: 1, Total: 1}
	out := RenderUpcomingMarkdown(items, summary, opts)

	if !strings.Contains(out, "| Due At (UTC) |") {
		t.Fatalf("missing table header, got:\n%s", out)
	}
	if !strings.Contains(out, "CTL.A") {
		t.Fatalf("missing control ID, got:\n%s", out)
	}
	if !strings.Contains(out, "res-1") {
		t.Fatalf("missing asset ID, got:\n%s", out)
	}
}

func TestRenderUpcomingSummaryMarkdown(t *testing.T) {
	summary := UpcomingSummary{
		Overdue: 1,
		DueNow:  2,
		DueSoon: 3,
		Later:   4,
		Total:   10,
	}
	out := RenderUpcomingSummaryMarkdown(summary, 24*time.Hour)
	if !strings.Contains(out, "## Snapshot SLA Summary") {
		t.Fatalf("missing summary header, got:\n%s", out)
	}
	if !strings.Contains(out, "Overdue: **1**") {
		t.Fatalf("missing overdue count, got:\n%s", out)
	}
	if !strings.Contains(out, "Total action items: **10**") {
		t.Fatalf("missing total count, got:\n%s", out)
	}
}

func TestFormatRemaining(t *testing.T) {
	tests := []struct {
		name string
		d    time.Duration
		want string
	}{
		{"zero", 0, "0h"},
		{"positive", 2 * time.Hour, "2h"},
		{"negative", -3 * time.Hour, "-3h"},
		{"positive minutes", 90 * time.Minute, "1h"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatRemaining(tt.d)
			if got != tt.want {
				t.Errorf("FormatRemaining(%v) = %q, want %q", tt.d, got, tt.want)
			}
		})
	}
}
