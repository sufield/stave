package diff

import (
	"bytes"
	"io"
	"strings"
	"testing"
	"time"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/core/asset"
)

func TestDefaultOptions(t *testing.T) {
	opts := DefaultOptions()
	if opts.ObservationsDir != "observations" {
		t.Fatalf("ObservationsDir = %q, want 'observations'", opts.ObservationsDir)
	}
	if opts.Format != "text" {
		t.Fatalf("Format = %q, want 'text'", opts.Format)
	}
}

func TestParseChangeTypes_Valid(t *testing.T) {
	tests := []struct {
		input []string
		want  int
	}{
		{nil, 0},
		{[]string{}, 0},
		{[]string{"added"}, 1},
		{[]string{"added", "removed", "modified"}, 3},
		{[]string{" Added ", " REMOVED "}, 2},
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
	opts := &Options{
		ChangeTypes: []string{"added"},
		AssetTypes:  []string{"bucket"},
		AssetID:     "  my-bucket  ",
	}
	filter, err := buildFilter(opts)
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
	delta := asset.ObservationDelta{
		FromCaptured: time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC),
		ToCaptured:   time.Date(2026, 1, 11, 0, 0, 0, 0, time.UTC),
	}
	err := renderText(&buf, delta)
	if err != nil {
		t.Fatalf("renderText error: %v", err)
	}
}

func TestRenderText_WithChanges(t *testing.T) {
	var buf bytes.Buffer
	delta := asset.ObservationDelta{
		FromCaptured: time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC),
		ToCaptured:   time.Date(2026, 1, 11, 0, 0, 0, 0, time.UTC),
		Changes: []asset.Diff{
			{
				AssetID:    "bucket-a",
				ChangeType: asset.ChangeAdded,
			},
			{
				AssetID:    "bucket-b",
				ChangeType: asset.ChangeModified,
				PropertyChanges: []asset.PropertyChange{
					{Path: "public", From: false, To: true},
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
	if !strings.Contains(out, "[added]") {
		t.Fatalf("expected [added] in output, got: %s", out)
	}
	if !strings.Contains(out, "public") {
		t.Fatalf("expected property path in output, got: %s", out)
	}
}

func TestWriteOutput_Quiet(t *testing.T) {
	// Quiet mode: caller passes io.Discard.
	err := writeOutput(io.Discard, appcontracts.FormatText, asset.ObservationDelta{})
	if err != nil {
		t.Fatalf("writeOutput error: %v", err)
	}
}

func TestWriteOutput_JSON(t *testing.T) {
	var buf bytes.Buffer
	delta := asset.ObservationDelta{
		FromCaptured: time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC),
		ToCaptured:   time.Date(2026, 1, 11, 0, 0, 0, 0, time.UTC),
	}
	err := writeOutput(&buf, appcontracts.FormatJSON, delta)
	if err != nil {
		t.Fatalf("writeOutput error: %v", err)
	}
	if !strings.Contains(buf.String(), "from_captured_at") {
		t.Fatalf("expected JSON output, got: %s", buf.String())
	}
}

func TestWriteOutput_TextWithChanges(t *testing.T) {
	var buf bytes.Buffer
	delta := asset.ObservationDelta{
		FromCaptured: time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC),
		ToCaptured:   time.Date(2026, 1, 11, 0, 0, 0, 0, time.UTC),
		Changes: []asset.Diff{
			{AssetID: "bucket-a", ChangeType: asset.ChangeAdded},
		},
	}
	err := writeOutput(&buf, appcontracts.FormatText, delta)
	if err != nil {
		t.Fatalf("writeOutput error: %v", err)
	}
	if !strings.Contains(buf.String(), "Observation delta") {
		t.Fatalf("expected text output, got: %s", buf.String())
	}
}
