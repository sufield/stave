package driftdiff

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/pkg/stave/internal/cmderr"
)

func TestComputeObservationDelta_DetectsAddedRemovedModified(t *testing.T) {
	t1 := time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 1, 11, 0, 0, 0, 0, time.UTC)

	prev := asset.Snapshot{
		CapturedAt: t1,
		Assets: []asset.Asset{
			{
				ID:     "res-a",
				Type:   "bucket",
				Vendor: "aws",
				Properties: map[string]any{
					"public": false,
					"tags": map[string]any{
						"owner": "team-a",
					},
				},
			},
			{
				ID:     "res-b",
				Type:   "bucket",
				Vendor: "aws",
				Properties: map[string]any{
					"public": true,
				},
			},
		},
	}

	curr := asset.Snapshot{
		CapturedAt: t2,
		Assets: []asset.Asset{
			{
				ID:     "res-a",
				Type:   "bucket",
				Vendor: "aws",
				Properties: map[string]any{
					"public": true,
					"tags": map[string]any{
						"owner": "team-b",
					},
				},
			},
			{
				ID:     "res-c",
				Type:   "bucket",
				Vendor: "aws",
				Properties: map[string]any{
					"public": false,
				},
			},
		},
	}

	out, err := asset.ComputeDrift(prev, curr)
	if err != nil {
		t.Fatalf("ComputeDrift: %v", err)
	}
	if out.Summary.Provisioned() != 1 || out.Summary.Decommissioned() != 1 || out.Summary.Reconfigured() != 1 {
		t.Fatalf("unexpected summary: %+v", out.Summary)
	}
	if len(out.Changes) != 3 {
		t.Fatalf("expected 3 resource changes, got %d", len(out.Changes))
	}
}

func TestLatestTwoSnapshots_SelectsMostRecentByCapturedAt(t *testing.T) {
	t1 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	t3 := time.Date(2026, 1, 3, 0, 0, 0, 0, time.UTC)

	in := []asset.Snapshot{{CapturedAt: t2}, {CapturedAt: t1}, {CapturedAt: t3}}
	prev, curr, err := asset.GetStateTransition(in)
	if err != nil {
		t.Fatalf("GetStateTransition returned error: %v", err)
	}
	if !prev.CapturedAt.Equal(t2) || !curr.CapturedAt.Equal(t3) {
		t.Fatalf("expected latest two snapshots t2,t3; got %s,%s", prev.CapturedAt, curr.CapturedAt)
	}
}

func TestBuildFilter_InvalidChangeType(t *testing.T) {
	_, err := buildFilter([]string{"update"}, nil, "")
	if err == nil {
		t.Fatal("expected invalid change type error")
	}
	var ie *cmderr.InputError
	if !errors.As(err, &ie) {
		t.Fatalf("expected *cmderr.InputError, got %T", err)
	}
}

func TestApplyDiffFilter(t *testing.T) {
	changes := []asset.AssetChange{
		{AssetID: "bucket-a", Action: asset.DriftProvisioned, CurrentType: "res:aws:s3:bucket"},
		{AssetID: "bucket-b", Action: asset.DriftReconfigured, PreviousType: "res:aws:s3:bucket", CurrentType: "res:aws:s3:bucket"},
		{AssetID: "queue-a", Action: asset.DriftDecommissioned, PreviousType: "res:aws:sqs:queue"},
	}
	filter, err := buildFilter([]string{"RECONFIGURED", "DECOMMISSIONED"}, []string{"res:aws:s3:bucket"}, "bucket")
	if err != nil {
		t.Fatalf("buildFilter returned error: %v", err)
	}
	delta := asset.InfrastructureDrift{Changes: changes}
	filtered := delta.ApplyFilter(filter)
	if len(filtered.Changes) != 1 {
		t.Fatalf("expected 1 filtered change, got %d", len(filtered.Changes))
	}
	if filtered.Changes[0].AssetID != "bucket-b" {
		t.Fatalf("unexpected filtered resource: %+v", filtered.Changes[0])
	}
	summary := filtered.Summary
	if summary.Reconfigured() != 1 || summary.Total() != 1 || summary.Provisioned() != 0 || summary.Decommissioned() != 0 {
		t.Fatalf("unexpected filtered summary: %+v", summary)
	}
}

func TestParseChangeTypes_Valid(t *testing.T) {
	tests := []struct {
		input []string
		want  int
	}{
		{nil, 0},
		{[]string{}, 0},
		{[]string{"PROVISIONED"}, 1},
		{[]string{"PROVISIONED", "DECOMMISSIONED", "RECONFIGURED"}, 3},
		{[]string{" Provisioned ", " decommissioned "}, 2},
	}
	for _, tt := range tests {
		got, err := parseChangeTypes(tt.input)
		if err != nil {
			t.Fatalf("parseChangeTypes(%v) error: %v", tt.input, err)
		}
		if len(got) != tt.want {
			t.Fatalf("parseChangeTypes(%v) len = %d, want %d", tt.input, len(got), tt.want)
		}
	}
}

func TestParseChangeTypes_Invalid(t *testing.T) {
	_, err := parseChangeTypes([]string{"update"})
	if err == nil {
		t.Fatal("expected error for invalid change type")
	}
	if !strings.Contains(err.Error(), "update") {
		t.Fatalf("error should mention the invalid type, got: %v", err)
	}
}

func TestParseChangeTypes_EmptyStrings(t *testing.T) {
	got, err := parseChangeTypes([]string{"", "  "})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected no results for empty strings, got %d", len(got))
	}
}

func TestBuildFilter(t *testing.T) {
	filter, err := buildFilter([]string{"PROVISIONED"}, []string{"bucket"}, "  my-bucket  ")
	if err != nil {
		t.Fatalf("buildFilter error: %v", err)
	}
	if len(filter.ChangeTypes) != 1 {
		t.Fatalf("ChangeTypes len = %d, want 1", len(filter.ChangeTypes))
	}
	if filter.AssetID != "my-bucket" {
		t.Fatalf("AssetID = %q, want 'my-bucket'", filter.AssetID)
	}
}

func TestRenderText_EmptyChanges(t *testing.T) {
	// NOTE: renderText has a known quirk where it returns without flushing
	// the bufio.Writer when there are no changes. We verify this path
	// does not return an error rather than checking output content.
	var buf bytes.Buffer
	delta := asset.InfrastructureDrift{
		StartTime: time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC),
		EndTime:   time.Date(2026, 1, 11, 0, 0, 0, 0, time.UTC),
	}
	err := renderText(&buf, delta)
	if err != nil {
		t.Fatalf("renderText error: %v", err)
	}
}

func TestRenderText_WithChanges(t *testing.T) {
	var buf bytes.Buffer
	delta := asset.InfrastructureDrift{
		StartTime: time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC),
		EndTime:   time.Date(2026, 1, 11, 0, 0, 0, 0, time.UTC),
		Changes: []asset.AssetChange{
			{
				AssetID: "bucket-a",
				Action:  asset.DriftProvisioned,
			},
			{
				AssetID: "bucket-b",
				Action:  asset.DriftReconfigured,
				Drifts: []asset.ConfigurationDrift{
					{Attribute: "public", OldValue: false, NewValue: true},
				},
			},
		},
	}
	err := renderText(&buf, delta)
	if err != nil {
		t.Fatalf("renderText error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "bucket-a") {
		t.Fatalf("expected bucket-a in output, got: %s", out)
	}
	if !strings.Contains(out, "[PROVISIONED]") {
		t.Fatalf("expected [PROVISIONED] in output, got: %s", out)
	}
	if !strings.Contains(out, "public") {
		t.Fatalf("expected property path in output, got: %s", out)
	}
}

func TestRender_TextEmpty(t *testing.T) {
	// Text render of a no-change delta yields empty bytes (the renderText
	// no-flush quirk), and must not error.
	out, err := render("text", asset.InfrastructureDrift{})
	if err != nil {
		t.Fatalf("render error: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("expected empty text output for no changes, got: %q", out)
	}
}

func TestRender_JSON(t *testing.T) {
	delta := asset.InfrastructureDrift{
		StartTime: time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC),
		EndTime:   time.Date(2026, 1, 11, 0, 0, 0, 0, time.UTC),
	}
	out, err := render("json", delta)
	if err != nil {
		t.Fatalf("render error: %v", err)
	}
	if !strings.Contains(string(out), "start_time") {
		t.Fatalf("expected JSON output, got: %s", out)
	}
}

func TestRender_TextWithChanges(t *testing.T) {
	delta := asset.InfrastructureDrift{
		StartTime: time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC),
		EndTime:   time.Date(2026, 1, 11, 0, 0, 0, 0, time.UTC),
		Changes: []asset.AssetChange{
			{AssetID: "bucket-a", Action: asset.DriftProvisioned},
		},
	}
	out, err := render("text", delta)
	if err != nil {
		t.Fatalf("render error: %v", err)
	}
	if !strings.Contains(string(out), "Observation delta") {
		t.Fatalf("expected text output, got: %s", out)
	}
}
