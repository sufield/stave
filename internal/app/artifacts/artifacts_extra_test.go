package artifacts

import (
	"strings"
	"testing"

	"github.com/sufield/stave/internal/app/catalog"
)

// ---------------------------------------------------------------------------
// WriteCSV
// ---------------------------------------------------------------------------

func TestWriteCSV_WithHeader(t *testing.T) {
	var buf strings.Builder
	rows := []catalog.ControlRow{
		{ID: "CTL.TEST.001", Name: "Test"},
	}
	cols := []string{"id", "name"}
	if err := WriteCSV(&buf, rows, cols, true); err != nil {
		t.Fatalf("WriteCSV: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "id,name") {
		t.Fatalf("missing header: %s", out)
	}
	if !strings.Contains(out, "CTL.TEST.001") {
		t.Fatalf("missing data: %s", out)
	}
}

func TestWriteCSV_NoHeader(t *testing.T) {
	var buf strings.Builder
	rows := []catalog.ControlRow{
		{ID: "CTL.TEST.001", Name: "Test"},
	}
	cols := []string{"id"}
	if err := WriteCSV(&buf, rows, cols, false); err != nil {
		t.Fatalf("WriteCSV: %v", err)
	}
	out := buf.String()
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected 1 line (no header), got %d", len(lines))
	}
}

// ---------------------------------------------------------------------------
// WriteTable
// ---------------------------------------------------------------------------

func TestWriteTable_Empty(t *testing.T) {
	var buf strings.Builder
	if err := WriteTable(&buf, nil, []string{"id"}, true); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "No controls") {
		t.Fatalf("expected 'No controls': %s", buf.String())
	}
}

func TestWriteTable_WithRows(t *testing.T) {
	var buf strings.Builder
	rows := []catalog.ControlRow{
		{ID: "CTL.TEST.001", Name: "Test"},
	}
	if err := WriteTable(&buf, rows, []string{"id", "name"}, true); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "CTL.TEST.001") {
		t.Fatalf("missing data: %s", buf.String())
	}
}

// ---------------------------------------------------------------------------
// FormatControlOutput CSV
// ---------------------------------------------------------------------------

func TestFormatControlOutput_CSV(t *testing.T) {
	var buf strings.Builder
	cfg := catalog.ListConfig{Format: "csv", Columns: "id,name"}
	rows := []catalog.ControlRow{
		{ID: "CTL.TEST.001", Name: "Test"},
	}
	if err := FormatControlOutput(&buf, cfg, rows); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "CTL.TEST.001") {
		t.Fatalf("missing data: %s", buf.String())
	}
}

func TestFormatControlOutput_Unsupported(t *testing.T) {
	var buf strings.Builder
	cfg := catalog.ListConfig{Format: "xml", Columns: "id"}
	err := FormatControlOutput(&buf, cfg, nil)
	if err == nil {
		t.Fatal("expected error for unsupported format")
	}
}

// ---------------------------------------------------------------------------
// FormatByExtension edge cases
// ---------------------------------------------------------------------------

func TestFormatByExtension_JSON(t *testing.T) {
	input := []byte(`{"schema_version":"obs.v0.1","captured_at":"2026-01-01T00:00:00Z","generated_by":{"source_type":"test","tool":"test"},"assets":[]}`)
	out, err := FormatByExtension("test.json", input)
	if err != nil {
		t.Fatal(err)
	}
	if out == nil {
		t.Fatal("expected non-nil output for .json")
	}
}

func TestFormatByExtension_YML(t *testing.T) {
	out, err := FormatByExtension("test.yml", []byte("key: value\n"))
	if err != nil {
		t.Fatal(err)
	}
	if out == nil {
		t.Fatal("expected non-nil output for .yml")
	}
}
