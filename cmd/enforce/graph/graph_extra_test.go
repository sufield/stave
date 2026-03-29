package graph

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/sanitize"
)

func TestParseFormat_Valid(t *testing.T) {
	tests := []struct {
		input string
		want  Format
	}{
		{"dot", FormatDot},
		{"json", FormatJSON},
		{"DOT", FormatDot},
		{"JSON", FormatJSON},
		{" dot ", FormatDot},
	}
	for _, tt := range tests {
		got, err := ParseFormat(tt.input)
		if err != nil {
			t.Errorf("ParseFormat(%q) error = %v", tt.input, err)
		}
		if got != tt.want {
			t.Errorf("ParseFormat(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestParseFormat_Invalid(t *testing.T) {
	_, err := ParseFormat("svg")
	if err == nil {
		t.Fatal("expected error for invalid format")
	}
}

func TestDefaultCoverageOptions(t *testing.T) {
	opts := defaultCoverageOptions()
	if opts.Format != "dot" {
		t.Fatalf("Format = %q, want dot", opts.Format)
	}
	if opts.ObservationsDir != "observations" {
		t.Fatalf("ObservationsDir = %q", opts.ObservationsDir)
	}
}

func TestDotQuote(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"hello", `"hello"`},
		{`say "hi"`, `"say \\"hi\\""`},
		{`back\slash`, `"back\\slash"`},
	}
	for _, tt := range tests {
		got := dotQuote(tt.input)
		if got != tt.want {
			t.Errorf("dotQuote(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestCoverageAssets(t *testing.T) {
	assets := []asset.Asset{
		{ID: "bucket-b"},
		{ID: "bucket-a"},
	}
	m, ids := coverageAssets(assets)
	if len(m) != 2 {
		t.Fatalf("map len = %d", len(m))
	}
	if len(ids) != 2 {
		t.Fatalf("ids len = %d", len(ids))
	}
	// Should be sorted
	if ids[0] != "bucket-a" {
		t.Fatalf("first id = %q, want bucket-a", ids[0])
	}
}

func TestCoverageAssets_Empty(t *testing.T) {
	m, ids := coverageAssets(nil)
	if len(m) != 0 {
		t.Fatalf("map len = %d", len(m))
	}
	if ids != nil {
		t.Fatalf("ids = %v, want nil", ids)
	}
}

func TestCoverageControlIDs(t *testing.T) {
	controls := []policy.ControlDefinition{
		{ID: "CTL.B.001"},
		{ID: "CTL.A.001"},
	}
	ids := coverageControlIDs(controls)
	if len(ids) != 2 {
		t.Fatalf("len = %d", len(ids))
	}
	if ids[0] != "CTL.B.001" {
		t.Fatalf("[0] = %q", ids[0])
	}
}

func TestUncoveredAssets(t *testing.T) {
	all := []string{"a", "b", "c"}
	covered := map[string]bool{"b": true}
	uncovered := uncoveredAssets(all, covered)
	if len(uncovered) != 2 {
		t.Fatalf("len = %d", len(uncovered))
	}
}

func TestCoverageEdges_NilEval(t *testing.T) {
	controls := []policy.ControlDefinition{{ID: "CTL.A.001"}}
	assetMap := map[string]asset.Asset{"bucket-1": {ID: "bucket-1"}}
	assetIDs := []string{"bucket-1"}
	edges, covered := CoverageEdges(controls, assetMap, assetIDs, nil, nil)
	if len(edges) != 0 {
		t.Fatalf("edges = %d", len(edges))
	}
	if len(covered) != 0 {
		t.Fatalf("covered = %d", len(covered))
	}
}

func TestBuildResult(t *testing.T) {
	controls := []policy.ControlDefinition{{ID: "CTL.A.001"}}
	latest := asset.Snapshot{
		Assets: []asset.Asset{{ID: "bucket-1"}},
	}
	result := buildResult(controls, latest, nil)
	if len(result.Controls) != 1 {
		t.Fatalf("Controls = %d", len(result.Controls))
	}
	if len(result.Assets) != 1 {
		t.Fatalf("Assets = %d", len(result.Assets))
	}
	// No eval -> all uncovered
	if len(result.UncoveredAssets) != 1 {
		t.Fatalf("UncoveredAssets = %d", len(result.UncoveredAssets))
	}
}

func TestWriteDOT(t *testing.T) {
	result := CoverageResult{
		Controls:        []string{"CTL.A.001"},
		Assets:          []string{"bucket-1", "bucket-2"},
		Edges:           []CoverageEdge{{ControlID: "CTL.A.001", AssetID: "bucket-1"}},
		UncoveredAssets: []string{"bucket-2"},
	}
	san := sanitize.New()
	var buf bytes.Buffer
	if err := writeDOT(&buf, result, san); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "digraph StaveCoverage") {
		t.Fatal("missing digraph header")
	}
	if !strings.Contains(out, "CTL.A.001") {
		t.Fatal("missing control node")
	}
	if !strings.Contains(out, "bucket-2") {
		t.Fatal("missing uncovered asset")
	}
	if !strings.Contains(out, "lightyellow") {
		t.Fatal("uncovered asset should be lightyellow")
	}
}

func TestWriteJSON(t *testing.T) {
	result := CoverageResult{
		Controls:        []string{"CTL.A.001"},
		Assets:          []string{"bucket-1"},
		Edges:           []CoverageEdge{{ControlID: "CTL.A.001", AssetID: "bucket-1"}},
		UncoveredAssets: []string{},
	}
	san := sanitize.New()
	var buf bytes.Buffer
	if err := writeJSON(&buf, result, san); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, `"controls"`) {
		t.Fatal("missing controls key")
	}
}

func TestWriteResult_DOT(t *testing.T) {
	result := CoverageResult{Controls: []string{"CTL.A"}, Assets: []string{"a"}}
	san := sanitize.New()
	var buf bytes.Buffer
	if err := writeResult(&buf, FormatDot, result, san); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "digraph") {
		t.Fatal("expected DOT output")
	}
}

func TestWriteResult_JSON(t *testing.T) {
	result := CoverageResult{Controls: []string{"CTL.A"}, Assets: []string{"a"}}
	san := sanitize.New()
	var buf bytes.Buffer
	if err := writeResult(&buf, FormatJSON, result, san); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"controls"`) {
		t.Fatal("expected JSON output")
	}
}

func TestWriteResult_Unknown(t *testing.T) {
	san := sanitize.New()
	var buf bytes.Buffer
	if err := writeResult(&buf, Format("yaml"), CoverageResult{}, san); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 0 {
		t.Fatal("unknown format should produce no output")
	}
}

func TestNewRunner(t *testing.T) {
	r := NewRunner(nil, nil)
	if r == nil {
		t.Fatal("expected non-nil runner")
	}
}

// Ensure exported types compile as expected.
var _ kernel.Sanitizer = sanitize.New()
