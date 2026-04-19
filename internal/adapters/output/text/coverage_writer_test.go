package text

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sufield/stave/internal/core/evaluation/coverage"
)

func renderCoverage(idx *coverage.CoverageIndex) string {
	w := &FindingWriter{}
	var buf bytes.Buffer
	d := &drawer{w: &buf}
	w.writeCoveragePosture(d, idx)
	return buf.String()
}

func TestWriteCoveragePosture_Nil(t *testing.T) {
	got := renderCoverage(nil)
	if got != "" {
		t.Errorf("nil index should produce no output, got: %q", got)
	}
}

func TestWriteCoveragePosture_Empty(t *testing.T) {
	got := renderCoverage(&coverage.CoverageIndex{ByTool: map[string]map[string]coverage.DomainCoverage{}})
	if got != "" {
		t.Errorf("empty index should produce no output, got: %q", got)
	}
}

func TestWriteCoveragePosture_SingleToolWithInventory(t *testing.T) {
	idx := &coverage.CoverageIndex{
		ByTool: map[string]map[string]coverage.DomainCoverage{
			"prowler": {
				"s3": {Covered: 17, Total: 21, NotCoveredChecks: []string{"check_a", "check_b"}},
			},
		},
	}
	got := renderCoverage(idx)
	wantSubstrings := []string{
		"Coverage posture",
		"prowler / s3: 17 of 21 checks covered",
		"Not covered (prowler s3): check_a, check_b",
	}
	for _, want := range wantSubstrings {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q\n--- output ---\n%s", want, got)
		}
	}
}

func TestWriteCoveragePosture_MultipleToolsAlphabetized(t *testing.T) {
	idx := &coverage.CoverageIndex{
		ByTool: map[string]map[string]coverage.DomainCoverage{
			"zeta-tool": {"s3": {Covered: 1, Total: 2, NotCoveredChecks: []string{"z"}}},
			"alpha":     {"s3": {Covered: 1, Total: 2, NotCoveredChecks: []string{"a"}}},
		},
	}
	got := renderCoverage(idx)
	alphaIdx := strings.Index(got, "alpha / s3")
	zetaIdx := strings.Index(got, "zeta-tool / s3")
	if alphaIdx < 0 || zetaIdx < 0 {
		t.Fatalf("missing tool entries in output: %s", got)
	}
	if alphaIdx > zetaIdx {
		t.Errorf("tools not sorted alphabetically: %s", got)
	}
}

func TestWriteCoveragePosture_NoInventoryNoTotal(t *testing.T) {
	idx := &coverage.CoverageIndex{
		ByTool: map[string]map[string]coverage.DomainCoverage{
			"unknown-tool": {
				"_unmatched": {Covered: 3, Total: 0, NotCoveredChecks: nil},
			},
		},
	}
	got := renderCoverage(idx)
	want := "unknown-tool / _unmatched: 3 checks covered (no inventory)"
	if !strings.Contains(got, want) {
		t.Errorf("output missing %q\n--- output ---\n%s", want, got)
	}
	if strings.Contains(got, "Not covered") {
		t.Errorf("no-inventory should not show 'Not covered' line: %s", got)
	}
}

func TestWriteCoveragePosture_NotCoveredCappedAtFive(t *testing.T) {
	long := []string{"a", "b", "c", "d", "e", "f", "g"}
	idx := &coverage.CoverageIndex{
		ByTool: map[string]map[string]coverage.DomainCoverage{
			"tool-x": {
				"d": {Covered: 1, Total: 8, NotCoveredChecks: long},
			},
		},
	}
	got := renderCoverage(idx)
	if !strings.Contains(got, "a, b, c, d, e, ...") {
		t.Errorf("expected truncated list with ellipsis, got: %s", got)
	}
	if strings.Contains(got, ", f") || strings.Contains(got, ", g") {
		t.Errorf("entries beyond cap should not appear: %s", got)
	}
}

func TestWriteCoveragePosture_FullyCoveredOmitsNotCoveredLine(t *testing.T) {
	idx := &coverage.CoverageIndex{
		ByTool: map[string]map[string]coverage.DomainCoverage{
			"tool-x": {
				"d": {Covered: 5, Total: 5, NotCoveredChecks: nil},
			},
		},
	}
	got := renderCoverage(idx)
	if !strings.Contains(got, "5 of 5 checks covered") {
		t.Errorf("missing coverage line: %s", got)
	}
	if strings.Contains(got, "Not covered") {
		t.Errorf("full coverage should omit 'Not covered' line: %s", got)
	}
}
