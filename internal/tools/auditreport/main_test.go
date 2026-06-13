package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sampleLintJSON = `{
  "Issues": [
    {"FromLinter":"interfacebloat","Text":"the interface has more than 10 methods: 12","Pos":{"Filename":"internal/a/a.go","Line":10}},
    {"FromLinter":"gochecknoglobals","Text":"table is a global variable","Pos":{"Filename":"internal/a/a.go","Line":5}},
    {"FromLinter":"gochecknoinits","Text":"don't use init function","Pos":{"Filename":"internal/b/b.go","Line":1}},
    {"FromLinter":"forbidigo","Text":"use of ` + "`panic`" + ` forbidden","Pos":{"Filename":"internal/c/c.go","Line":42}}
  ],
  "Report": {}
}`

const sampleGoroutineJSON = `{
  "schema":"goroutinescan.v1",
  "goroutines":[
    {"file":"internal/d/d.go","line":7,"func":"Worker","managed":false,"signals":[]},
    {"file":"internal/e/e.go","line":3,"func":"Run","managed":true,"signals":["waitgroup"]}
  ],
  "summary":{"total":2,"unmanaged":1}
}`

const sampleChurn = "    184 cmd/commands.go\n     5 internal/a/a.go\n     2 internal/c/c.go\n"

func TestParseLintJSON(t *testing.T) {
	fs, err := parseLintJSON(strings.NewReader(sampleLintJSON))
	if err != nil {
		t.Fatalf("parseLintJSON: %v", err)
	}
	if len(fs) != 4 {
		t.Fatalf("want 4 findings, got %d", len(fs))
	}
	if fs[0].Linter != "interfacebloat" || fs[0].File != "internal/a/a.go" || fs[0].Line != 10 {
		t.Errorf("unexpected first finding: %+v", fs[0])
	}
}

func TestParseChurn(t *testing.T) {
	m, err := parseChurn(strings.NewReader(sampleChurn))
	if err != nil {
		t.Fatalf("parseChurn: %v", err)
	}
	if m["cmd/commands.go"] != 184 || m["internal/a/a.go"] != 5 {
		t.Errorf("unexpected churn map: %v", m)
	}
}

func TestBuildReport_Dimensions(t *testing.T) {
	findings, _ := parseLintJSON(strings.NewReader(sampleLintJSON))
	grs, _ := parseGoroutines(strings.NewReader(sampleGoroutineJSON))
	churn, _ := parseChurn(strings.NewReader(sampleChurn))

	rep := buildReport(findings, grs, churn, "2026-06-13", "abc1234")

	if len(rep.Dimensions) != 4 {
		t.Fatalf("want 4 dimensions, got %d", len(rep.Dimensions))
	}
	by := map[string]Dimension{}
	for _, d := range rep.Dimensions {
		by[d.Key] = d
	}
	if by["DIM1"].Count != 1 || by["DIM1"].Files != 1 {
		t.Errorf("DIM1 = count %d files %d, want 1/1", by["DIM1"].Count, by["DIM1"].Files)
	}
	if by["DIM2"].Count != 2 || by["DIM2"].Files != 2 {
		t.Errorf("DIM2 = count %d files %d, want 2/2", by["DIM2"].Count, by["DIM2"].Files)
	}
	if by["DIM3"].Count != 1 {
		t.Errorf("DIM3 count = %d, want 1", by["DIM3"].Count)
	}
	// DIM4 = unmanaged goroutines only (1 of 2).
	if by["DIM4"].Count != 1 {
		t.Errorf("DIM4 count = %d, want 1 (only unmanaged)", by["DIM4"].Count)
	}
	// Hotspot score = count × max(churn,1). internal/a/a.go has churn 5, 1 global → 5.
	var aScore int
	for _, h := range by["DIM2"].Hotspots {
		if h.File == "internal/a/a.go" {
			aScore = h.Score
		}
	}
	if aScore != 5 {
		t.Errorf("DIM2 internal/a/a.go score = %d, want 5 (1 × churn 5)", aScore)
	}
	if !rep.ChurnAvailable {
		t.Error("ChurnAvailable should be true with non-empty churn")
	}
	if by["DIM2"].RecommendedCeiling != "≤ 2 (current count; ratchet toward 0)" {
		t.Errorf("DIM2 ceiling = %q", by["DIM2"].RecommendedCeiling)
	}
	// Sample fixture has 1 interfacebloat finding, so DIM1 count is 1.
	if by["DIM1"].RecommendedCeiling != "≤ 1 (current count; ratchet toward 0)" {
		t.Errorf("DIM1 ceiling = %q", by["DIM1"].RecommendedCeiling)
	}
	// Clean-dimension (count 0) ceiling path:
	if got := ceilingFor(0); got != "0 — clean; gate to forbid new violations" {
		t.Errorf("ceilingFor(0) = %q", got)
	}
}

func TestChurnUnavailableBanner(t *testing.T) {
	findings, _ := parseLintJSON(strings.NewReader(sampleLintJSON))
	grs, _ := parseGoroutines(strings.NewReader(sampleGoroutineJSON))

	repEmpty := buildReport(findings, grs, map[string]int{}, "2026-06-13", "abc1234")
	if repEmpty.ChurnAvailable {
		t.Error("ChurnAvailable should be false with empty churn")
	}
	if !strings.Contains(renderMarkdown(repEmpty), "Churn ranking SKIPPED") {
		t.Error("missing churn-unavailable banner when churn is empty")
	}

	churn, _ := parseChurn(strings.NewReader(sampleChurn))
	repFull := buildReport(findings, grs, churn, "2026-06-13", "abc1234")
	if strings.Contains(renderMarkdown(repFull), "Churn ranking SKIPPED") {
		t.Error("banner should be absent when churn is available")
	}
}

func writeTemp(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRun_WritesAndCheckDetectsDrift(t *testing.T) {
	dir := t.TempDir()
	cfg := config{
		Lint:       writeTemp(t, dir, "lint.json", sampleLintJSON),
		Goroutines: writeTemp(t, dir, "gr.json", sampleGoroutineJSON),
		Churn:      writeTemp(t, dir, "churn.txt", sampleChurn),
		Out:        filepath.Join(dir, "baseline.md"),
		JSON:       filepath.Join(dir, "baseline.json"),
		Now:        "2026-06-13",
		Commit:     "abc1234",
		Stderr:     os.Stderr,
	}

	if err := run(cfg); err != nil {
		t.Fatalf("run(write): %v", err)
	}

	md, err := os.ReadFile(cfg.Out)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"# Go Best-Practices Audit Baseline",
		"**Commit:** abc1234",
		"## Summary",
		"## DIM1 — Interface segregation",
		"## DIM2 — Package-level global state",
		"## DIM3 — Errors, not panics",
		"## DIM4 — Concurrency with channels/context",
		"## Verification commands",
	} {
		if !strings.Contains(string(md), want) {
			t.Errorf("markdown missing %q", want)
		}
	}

	jb, err := os.ReadFile(cfg.JSON)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(jb), `"hotspots": null`) || strings.Contains(string(jb), `"dimensions": null`) {
		t.Errorf("json arrays must serialize as [] not null:\n%s", jb)
	}
	var rep Report
	if err := json.Unmarshal(jb, &rep); err != nil {
		t.Fatalf("sidecar not valid JSON: %v", err)
	}
	if rep.Schema == "" || len(rep.Dimensions) != 4 {
		t.Errorf("sidecar schema=%q dims=%d", rep.Schema, len(rep.Dimensions))
	}

	// -check on unchanged outputs: no drift.
	check := cfg
	check.Check = true
	if err := run(check); err != nil {
		t.Errorf("run(-check) on fresh outputs should pass, got: %v", err)
	}

	// -check after tampering: drift detected (non-nil error).
	if err := os.WriteFile(cfg.Out, append(md, []byte("\ntampered\n")...), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := run(check); err == nil {
		t.Errorf("run(-check) should fail on drifted markdown")
	}
}

func TestRender_Deterministic(t *testing.T) {
	findings, _ := parseLintJSON(strings.NewReader(sampleLintJSON))
	grs, _ := parseGoroutines(strings.NewReader(sampleGoroutineJSON))
	churn, _ := parseChurn(strings.NewReader(sampleChurn))
	rep := buildReport(findings, grs, churn, "2026-06-13", "abc1234")

	md1, md2 := renderMarkdown(rep), renderMarkdown(rep)
	if md1 != md2 {
		t.Error("markdown render not deterministic")
	}
	j1, _ := renderJSON(rep)
	j2, _ := renderJSON(rep)
	if string(j1) != string(j2) {
		t.Error("json render not deterministic")
	}
}
