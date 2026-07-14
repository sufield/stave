// Command auditreport aggregates the Go best-practices audit detectors into a
// single deterministic baseline: it reads the report-only golangci-lint JSON
// (.Issues[]), the goroutinescan JSON, and per-file churn counts, then writes a
// human-readable markdown baseline plus a machine-readable JSON sidecar.
//
// It is report-only and advisory — the baseline gates nothing. With -check it
// regenerates in memory and exits non-zero if the on-disk baseline has drifted
// (a manual check; NOT wired into CI, since churn is per-commit volatile).
//
// Design + verified syntax: docs/superpowers/specs/2026-06-13-go-best-practices-audit-design.md.
//
// Usage:
//
//	go run ./internal/tools/auditreport \
//	  -lint audit-lint.json -goroutines goroutines.json -churn churn.txt \
//	  -out docs/audits/go-best-practices-baseline.md \
//	  -json docs/audits/go-best-practices-baseline.json \
//	  -eval-time <RFC3339> -commit <sha>
package main

import (
	"bufio"
	"bytes"
	"cmp"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
)

const (
	reportSchema = "go-best-practices-baseline.v1"
	sampleCap    = 5  // representative sites shown per dimension
	hotspotShow  = 10 // hotspot rows shown per dimension in markdown
)

// Finding is one detector hit, normalized across linters and the goroutine scan.
type Finding struct {
	File   string
	Line   int
	Linter string
	Text   string
}

// GoroutineRec mirrors one entry of the goroutinescan.v1 JSON.
type GoroutineRec struct {
	File    string   `json:"file"`
	Line    int      `json:"line"`
	Func    string   `json:"func"`
	Managed bool     `json:"managed"`
	Signals []string `json:"signals"`
}

// Hotspot is a per-file rollup ranked by Score = violations × max(churn, 1).
type Hotspot struct {
	File  string `json:"file"`
	Count int    `json:"count"`
	Churn int    `json:"churn"`
	Score int    `json:"score"`
}

// Sample is a representative finding site.
type Sample struct {
	File string `json:"file"`
	Line int    `json:"line"`
	Text string `json:"text"`
}

// Dimension is one of the four audit dimensions with its rolled-up findings.
type Dimension struct {
	Key                string    `json:"key"`
	Title              string    `json:"title"`
	Detectors          []string  `json:"detectors"`
	Count              int       `json:"count"`
	Files              int       `json:"files"`
	RecommendedCeiling string    `json:"recommended_ceiling"`
	Hotspots           []Hotspot `json:"hotspots"`
	Samples            []Sample  `json:"samples"`
}

// Report is the full deterministic baseline document.
type Report struct {
	Schema         string      `json:"schema"`
	Date           string      `json:"date"`
	Commit         string      `json:"commit"`
	ChurnAvailable bool        `json:"churn_available"`
	Dimensions     []Dimension `json:"dimensions"`
}

type config struct {
	Lint       string
	Goroutines string
	Churn      string
	Out        string
	JSON       string
	EvalTime   string
	Commit     string
	Check      bool
	Stderr     io.Writer
}

func main() {
	cfg := config{Stderr: os.Stderr}
	flag.StringVar(&cfg.Lint, "lint", "", "path to report-only golangci-lint JSON (.Issues[])")
	flag.StringVar(&cfg.Goroutines, "goroutines", "", "path to goroutinescan JSON")
	flag.StringVar(&cfg.Churn, "churn", "", "path to churn counts (`<n> <path>` per line)")
	flag.StringVar(&cfg.Out, "out", "../docs-internal/retrospectives/go-best-practices-baseline.md", "markdown output path")
	flag.StringVar(&cfg.JSON, "json", "../docs-internal/retrospectives/go-best-practices-baseline.json", "JSON sidecar output path")
	flag.StringVar(&cfg.EvalTime, "eval-time", "", "date for the header (deterministic; e.g. HEAD committer date)")
	flag.StringVar(&cfg.Commit, "commit", "", "commit SHA for the header")
	flag.BoolVar(&cfg.Check, "check", false, "verify the on-disk baseline matches current inputs; non-zero exit on drift")
	flag.Parse()
	if err := run(cfg); err != nil {
		fmt.Fprintln(os.Stderr, "auditreport:", err)
		os.Exit(1)
	}
}

func run(cfg config) error {
	findings, err := loadLint(cfg.Lint)
	if err != nil {
		return err
	}
	grs, err := loadGoroutines(cfg.Goroutines)
	if err != nil {
		return err
	}
	churn, err := loadChurn(cfg.Churn)
	if err != nil {
		return err
	}

	rep := buildReport(findings, grs, churn, cfg.EvalTime, cfg.Commit)
	md := renderMarkdown(rep)
	js, err := renderJSON(rep)
	if err != nil {
		return err
	}

	if cfg.Check {
		return checkDrift(cfg, md, js)
	}
	if err := os.WriteFile(cfg.Out, []byte(md), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", cfg.Out, err)
	}
	if err := os.WriteFile(cfg.JSON, js, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", cfg.JSON, err)
	}
	return nil
}

func checkDrift(cfg config, md string, js []byte) error {
	var drifted []string
	if existing, err := os.ReadFile(cfg.Out); err != nil || string(existing) != md {
		drifted = append(drifted, cfg.Out)
	}
	if existing, err := os.ReadFile(cfg.JSON); err != nil || !bytes.Equal(existing, js) {
		drifted = append(drifted, cfg.JSON)
	}
	if len(drifted) > 0 {
		fmt.Fprintf(cfg.Stderr, "audit baseline drift in: %s\nrun `make audit` to regenerate\n", strings.Join(drifted, ", "))
		return fmt.Errorf("audit baseline out of date: %s", strings.Join(drifted, ", "))
	}
	return nil
}

// ── input loading ──────────────────────────────────────────────

func loadLint(path string) ([]Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open lint json %s: %w", path, err)
	}
	defer f.Close()
	return parseLintJSON(f)
}

func loadGoroutines(path string) ([]GoroutineRec, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open goroutines json %s: %w", path, err)
	}
	defer f.Close()
	return parseGoroutines(f)
}

func loadChurn(path string) (map[string]int, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open churn %s: %w", path, err)
	}
	defer f.Close()
	return parseChurn(f)
}

// lintDoc is the golangci-lint native JSON shape (top-level Issues array).
type lintDoc struct {
	Issues []struct {
		FromLinter string `json:"FromLinter"`
		Text       string `json:"Text"`
		Pos        struct {
			Filename string `json:"Filename"`
			Line     int    `json:"Line"`
		} `json:"Pos"`
	} `json:"Issues"`
}

func parseLintJSON(r io.Reader) ([]Finding, error) {
	var doc lintDoc
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return nil, fmt.Errorf("decode lint json: %w", err)
	}
	out := make([]Finding, 0, len(doc.Issues))
	for _, is := range doc.Issues {
		out = append(out, Finding{
			File:   is.Pos.Filename,
			Line:   is.Pos.Line,
			Linter: is.FromLinter,
			Text:   strings.TrimSpace(is.Text),
		})
	}
	return out, nil
}

func parseGoroutines(r io.Reader) ([]GoroutineRec, error) {
	var doc struct {
		Goroutines []GoroutineRec `json:"goroutines"`
	}
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return nil, fmt.Errorf("decode goroutines json: %w", err)
	}
	return doc.Goroutines, nil
}

func parseChurn(r io.Reader) (map[string]int, error) {
	m := map[string]int{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		n, err := strconv.Atoi(fields[0])
		if err != nil {
			continue // not a "<count> <path>" line
		}
		m[strings.Join(fields[1:], " ")] = n
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scan churn: %w", err)
	}
	return m, nil
}

// ── report assembly ────────────────────────────────────────────

func buildReport(findings []Finding, grs []GoroutineRec, churn map[string]int, date, commit string) Report {
	byLinter := func(linters ...string) []Finding {
		want := map[string]struct{}{}
		for _, l := range linters {
			want[l] = struct{}{}
		}
		var out []Finding
		for _, f := range findings {
			if _, ok := want[f.Linter]; ok {
				out = append(out, f)
			}
		}
		return out
	}

	var goroutineFindings []Finding
	for _, g := range grs {
		if g.Managed {
			continue
		}
		goroutineFindings = append(goroutineFindings, Finding{
			File:   g.File,
			Line:   g.Line,
			Linter: "goroutinescan",
			Text:   fmt.Sprintf("unmanaged goroutine in %s (heuristic — confirm)", g.Func),
		})
	}

	dims := []Dimension{
		buildDimension("DIM1", "Interface segregation", []string{"interfacebloat"}, byLinter("interfacebloat"), churn),
		buildDimension("DIM2", "Package-level global state", []string{"gochecknoglobals", "gochecknoinits"}, byLinter("gochecknoglobals", "gochecknoinits"), churn),
		buildDimension("DIM3", "Errors, not panics", []string{"forbidigo"}, byLinter("forbidigo"), churn),
		buildDimension("DIM4", "Concurrency with channels/context", []string{"goroutinescan"}, goroutineFindings, churn),
	}
	for i := range dims {
		dims[i].RecommendedCeiling = ceilingFor(dims[i].Count)
	}
	return Report{
		Schema:         reportSchema,
		Date:           date,
		Commit:         commit,
		ChurnAvailable: len(churn) > 0,
		Dimensions:     dims,
	}
}

// ceilingFor renders the recommended ratchet ceiling for a dimension, calibrated
// to the current count (the lint-debt-baseline pattern: a count that may only
// decrease). The follow-on enforcement spec drops this in as the starting gate.
func ceilingFor(count int) string {
	if count == 0 {
		return "0 — clean; gate to forbid new violations"
	}
	return fmt.Sprintf("≤ %d (current count; ratchet toward 0)", count)
}

func buildDimension(key, title string, detectors []string, findings []Finding, churn map[string]int) Dimension {
	perFile := map[string]int{}
	for _, f := range findings {
		perFile[f.File]++
	}

	hotspots := make([]Hotspot, 0, len(perFile))
	for file, cnt := range perFile {
		ch := churnFor(churn, file)
		hotspots = append(hotspots, Hotspot{File: file, Count: cnt, Churn: ch, Score: cnt * max(ch, 1)})
	}
	slices.SortFunc(hotspots, func(a, b Hotspot) int {
		if n := cmp.Compare(b.Score, a.Score); n != 0 {
			return n
		}
		if n := cmp.Compare(b.Count, a.Count); n != 0 {
			return n
		}
		return cmp.Compare(a.File, b.File)
	})

	sorted := append([]Finding(nil), findings...)
	slices.SortFunc(sorted, func(a, b Finding) int {
		if n := cmp.Compare(a.File, b.File); n != 0 {
			return n
		}
		if n := cmp.Compare(a.Line, b.Line); n != 0 {
			return n
		}
		return cmp.Compare(a.Text, b.Text)
	})
	samples := make([]Sample, 0, sampleCap)
	for _, f := range sorted {
		if len(samples) >= sampleCap {
			break
		}
		samples = append(samples, Sample{File: f.File, Line: f.Line, Text: f.Text})
	}

	return Dimension{
		Key:       key,
		Title:     title,
		Detectors: detectors,
		Count:     len(findings),
		Files:     len(perFile),
		Hotspots:  hotspots,
		Samples:   samples,
	}
}

// churnFor looks up a file's revision count, tolerating a leading module prefix
// (churn paths are repo-root-relative; finding paths are module-relative).
func churnFor(churn map[string]int, file string) int {
	if v, ok := churn[file]; ok {
		return v
	}
	if v, ok := churn["stave/"+file]; ok {
		return v
	}
	return 0
}

// ── rendering ──────────────────────────────────────────────────

func renderMarkdown(rep Report) string {
	var b strings.Builder
	b.WriteString("# Go Best-Practices Audit Baseline\n\n")
	fmt.Fprintf(&b, "**Date:** %s\n", rep.Date)
	fmt.Fprintf(&b, "**Commit:** %s\n", rep.Commit)
	b.WriteString("**Mode:** report-only (advisory) — this baseline gates nothing.\n\n")
	b.WriteString("Reproducible snapshot of Go best-practice violations across four dimensions in " +
		"the `stave/` module (non-test, non-vendor, non-generated). Churn columns are informational " +
		"and per-commit volatile — not a gate. Hotspot Score = violations × max(churn, 1). " +
		"Regenerate with `make audit`; design in " +
		"`docs/superpowers/specs/2026-06-13-go-best-practices-audit-design.md`.\n\n")

	if !rep.ChurnAvailable {
		b.WriteString("> **Churn ranking SKIPPED** — no churn data available; hotspots are ranked by violation count only (Score = violations).\n\n")
	}

	b.WriteString("## Summary\n\n")
	b.WriteString("| Dimension | Detector(s) | Violations | Files | Recommended ceiling |\n")
	b.WriteString("|---|---|---:|---:|---|\n")
	for _, d := range rep.Dimensions {
		fmt.Fprintf(&b, "| %s — %s | %s | %d | %d | %s |\n", d.Key, d.Title, strings.Join(d.Detectors, ", "), d.Count, d.Files, d.RecommendedCeiling)
	}
	b.WriteString("\n")

	for _, d := range rep.Dimensions {
		fmt.Fprintf(&b, "## %s — %s\n\n", d.Key, d.Title)
		fmt.Fprintf(&b, "_Detector(s): %s. %d violation(s) across %d file(s). Recommended ratchet ceiling: %s._\n\n",
			strings.Join(d.Detectors, ", "), d.Count, d.Files, d.RecommendedCeiling)
		if d.Count == 0 {
			b.WriteString("No violations at the configured threshold — not a current problem area.\n\n")
			continue
		}

		shown := d.Hotspots
		truncated := 0
		if len(shown) > hotspotShow {
			truncated = len(shown) - hotspotShow
			shown = shown[:hotspotShow]
		}
		fmt.Fprintf(&b, "### Hotspots (top %d of %d files, by Score = violations × max(churn, 1))\n\n", len(shown), d.Files)
		b.WriteString("| Score | Violations | Churn | File |\n")
		b.WriteString("|---:|---:|---:|---|\n")
		for _, h := range shown {
			fmt.Fprintf(&b, "| %d | %d | %d | `%s` |\n", h.Score, h.Count, h.Churn, h.File)
		}
		if truncated > 0 {
			fmt.Fprintf(&b, "\n_…and %d more file(s); see the JSON sidecar for the full list._\n", truncated)
		}
		b.WriteString("\n### Representative sites\n\n")
		for _, s := range d.Samples {
			fmt.Fprintf(&b, "- `%s:%d` — %s\n", s.File, s.Line, s.Text)
		}
		b.WriteString("\n")
	}

	b.WriteString("## Already enforced (context)\n\n")
	b.WriteString("- **DIM3 errors:** the wrap/return side is already gated by `errcheck`/`errorlint`/`wrapcheck`/`nilerr`; this baseline adds the `forbidigo` ban on `panic`/`os.Exit`/`log.Fatal*` in library code (only `panic` occurs outside the path-excluded `cmd/`).\n")
	b.WriteString("- **DIM4 context:** `containedctx`/`fatcontext`/`noctx` already gate context structure; `goroutinescan` flags unmanaged raw `go` launches. The heuristic is function-body-scoped and name-based, so a flag NEEDS MANUAL CONFIRMATION and the count is a FLOOR: an incidental lifecycle signal (or one managing a sibling goroutine) can mask a fire-and-forget launch, and teardown extracted to a sibling method reads as unmanaged.\n\n")

	b.WriteString("## Verification commands\n\n")
	b.WriteString("```bash\n")
	b.WriteString("golangci-lint run -c .golangci.audit.yml --output.json.path stdout --show-stats=false --issues-exit-code 0 ./...\n")
	b.WriteString("go run ./internal/tools/goroutinescan -root .\n")
	b.WriteString("git log --format= --name-only --relative -- '*.go' | grep -v _test.go | sort | uniq -c | sort -rn\n")
	b.WriteString("```\n")
	return b.String()
}

func renderJSON(rep Report) ([]byte, error) {
	b, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal report: %w", err)
	}
	return append(b, '\n'), nil
}
