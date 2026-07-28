//go:build ignore

// Command discovery — Datalog reachability + condition verification chain discovery.
//
// Discovers attack chains in a Stave snapshot that aren't covered
// by the existing manually authored chain YAMLs. The pipeline:
//
//	stave export-sir --format jsonl  →  JSONL facts
//	extract.go                       →  per-predicate .facts TSVs
//	souffle discovery.dl             →  path-tracking reachability
//	verify (--verify)                →  per-chain condition satisfiability
//	dedup against chains/*.yaml      →  novel vs confirmed
//	report
//
// Usage:
//
//	go run ./reasoning/souffle/discovery/*.go \
//	    -snapshot observations/ -controls controls/
//
//	go run ./reasoning/souffle/discovery/*.go \
//	    -jsonl /tmp/facts.jsonl -novel-only -verify
//
//	go run ./reasoning/souffle/discovery/*.go \
//	    -snapshot observations/ -query escalation -json -verify
//
// Run from the stave/ directory so relative paths resolve.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
)

type options struct {
	jsonl      string
	snapshot   string
	controls   string
	chains     string
	stave      string
	souffle    string
	out        string
	now        string
	query      string
	novelOnly  bool
	jsonOutput bool
	verify     bool
	maxHops    int
}

func parseFlags() *options {
	opts := &options{}
	flag.StringVar(&opts.jsonl, "jsonl", "", "Pre-existing JSONL fact stream (mutually exclusive with -snapshot).")
	flag.StringVar(&opts.snapshot, "snapshot", "", "Snapshot observations directory.")
	flag.StringVar(&opts.controls, "controls", "controls", "Controls directory.")
	flag.StringVar(&opts.chains, "chains", "chains", "Chain YAML directory for dedup.")
	flag.StringVar(&opts.stave, "stave", "./stave", "Path to stave binary.")
	flag.StringVar(&opts.souffle, "souffle", "souffle", "Path to souffle binary.")
	flag.StringVar(&opts.out, "out", "", "Output directory (default: temp).")
	flag.StringVar(&opts.now, "now", "2026-01-15T00:00:00Z", "--eval-time for deterministic output.")
	flag.StringVar(&opts.query, "query", "all", "Security queries: all|escalation|exfil|external|confused-deputy.")
	flag.BoolVar(&opts.novelOnly, "novel-only", false, "Only show paths not covered by existing chains.")
	flag.BoolVar(&opts.jsonOutput, "json", false, "Output as JSON.")
	flag.BoolVar(&opts.verify, "verify", false, "Verify path conditions are satisfiable.")
	flag.IntVar(&opts.maxHops, "max-hops", 5, "Maximum path depth (1-5).")
	flag.Parse()

	if opts.jsonl == "" && opts.snapshot == "" {
		fmt.Fprintln(os.Stderr, "discovery: supply -snapshot <dir> or -jsonl <file>")
		os.Exit(2)
	}
	if opts.jsonl != "" && opts.snapshot != "" {
		fmt.Fprintln(os.Stderr, "discovery: -jsonl and -snapshot are mutually exclusive")
		os.Exit(2)
	}
	if opts.maxHops < 1 || opts.maxHops > 5 {
		fmt.Fprintln(os.Stderr, "discovery: -max-hops must be 1-5")
		os.Exit(2)
	}
	return opts
}

func main() {
	opts := parseFlags()

	workDir := opts.out
	if workDir == "" {
		d, err := os.MkdirTemp("", "chain-discovery-*")
		if err != nil {
			fail("mktemp: %v", err)
		}
		defer os.RemoveAll(d)
		workDir = d
	} else {
		os.MkdirAll(workDir, 0o755)
	}

	_, thisFile, _, _ := runtime.Caller(0)
	discoveryDir := filepath.Dir(thisFile)
	iamDir := filepath.Join(discoveryDir, "..", "iam")

	// 1. Get JSONL facts.
	fmt.Fprintln(os.Stderr, "── Step 1: export SIR facts ──")
	jsonlPath := filepath.Join(workDir, "facts.jsonl")
	if opts.jsonl != "" {
		data, err := os.ReadFile(opts.jsonl)
		if err != nil {
			fail("read jsonl: %v", err)
		}
		os.WriteFile(jsonlPath, data, 0o644)
	} else {
		data, err := exportSIR(opts)
		if err != nil {
			fail("export-sir: %v", err)
		}
		os.WriteFile(jsonlPath, data, 0o644)
	}
	lineCount := countLines(jsonlPath)
	fmt.Fprintf(os.Stderr, "  %d facts exported\n", lineCount)

	// 2. Split JSONL into per-predicate .facts files.
	fmt.Fprintln(os.Stderr, "── Step 2: split facts ──")
	factsDir := filepath.Join(workDir, "facts")
	if err := runExtract(opts, iamDir, jsonlPath, factsDir); err != nil {
		fail("extract: %v", err)
	}
	factFiles, _ := filepath.Glob(filepath.Join(factsDir, "*.facts"))
	fmt.Fprintf(os.Stderr, "  %d predicate files\n", len(factFiles))

	// 3. Run Soufflé with discovery.dl.
	fmt.Fprintln(os.Stderr, "── Step 3: Soufflé reachability ──")
	souffleOut := filepath.Join(workDir, "souffle")
	if err := runSouffle(opts, iamDir, discoveryDir, factsDir, souffleOut); err != nil {
		fail("souffle: %v", err)
	}

	// 4. Parse Soufflé output.
	fmt.Fprintln(os.Stderr, "── Step 4: parse results ──")
	results, err := parseResults(souffleOut, opts)
	if err != nil {
		fail("parse results: %v", err)
	}

	// 5. Verify path conditions (optional).
	var verification map[int]verifyStatus
	if opts.verify {
		fmt.Fprintln(os.Stderr, "── Step 5: verify path conditions ──")
		verification = verifyAll(results, souffleOut)
	}

	// 6. Load known chains for dedup.
	fmt.Fprintln(os.Stderr, "── Step 6: dedup against known chains ──")
	knownChains, err := loadChains(opts.chains)
	if err != nil {
		fail("load chains: %v", err)
	}

	novel, confirmed := dedup(results, knownChains)
	fmt.Fprintf(os.Stderr, "  %d novel, %d confirmed\n", len(novel), len(confirmed))

	// 7. Report.
	if opts.novelOnly {
		confirmed = nil
	}

	counts := parseCounts(souffleOut)
	if opts.jsonOutput {
		reportJSONVerified(results, novel, confirmed, counts, verification)
	} else {
		reportTextVerified(results, novel, confirmed, counts, opts, verification)
	}
}

func exportSIR(opts *options) ([]byte, error) {
	args := []string{
		"export-sir",
		"--controls", opts.controls,
		"--observations", opts.snapshot,
		"--eval-time", opts.now,
		"--format", "jsonl",
	}
	cmd := exec.Command(opts.stave, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%w\nstderr: %s", err, stderr.String())
	}
	return stdout.Bytes(), nil
}

func runExtract(opts *options, iamDir, jsonlPath, factsDir string) error {
	extractGo := filepath.Join(iamDir, "extract.go")
	args := []string{
		"run", extractGo,
		"-jsonl", jsonlPath,
		"-out", factsDir,
	}
	cmd := exec.Command("go", args...)
	cmd.Stdout = io.Discard
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%w\nstderr: %s", err, stderr.String())
	}
	return nil
}

func runSouffle(opts *options, iamDir, discoveryDir, factsDir, outDir string) error {
	os.MkdirAll(outDir, 0o755)
	dlPath := filepath.Join(discoveryDir, "discovery.dl")
	args := []string{
		dlPath,
		"-F", factsDir,
		"-D", outDir,
		"-I", iamDir,
	}
	cmd := exec.Command(opts.souffle, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%w\nstderr: %s", err, stderr.String())
	}
	return nil
}

// ── Soufflé CSV parsing ──

type discoveredPath struct {
	Category string   `json:"category"`
	Source   string   `json:"source"`
	Target   string   `json:"target"`
	Action   string   `json:"action,omitempty"`
	ViaRole  string   `json:"via_role,omitempty"`
	Service  string   `json:"service,omitempty"`
	Hops     int      `json:"hops"`
	Path     []string `json:"path"`
}

func parseResults(souffleOut string, opts *options) ([]discoveredPath, error) {
	var all []discoveredPath

	q := opts.query

	if q == "all" || q == "escalation" {
		paths, err := parseEscalation(souffleOut)
		if err != nil {
			return nil, err
		}
		all = append(all, paths...)
	}
	if q == "all" || q == "exfil" {
		paths, err := parseExfil(souffleOut)
		if err != nil {
			return nil, err
		}
		all = append(all, paths...)
	}
	if q == "all" || q == "external" {
		paths, err := parseExternal(souffleOut)
		if err != nil {
			return nil, err
		}
		all = append(all, paths...)
	}
	if q == "all" || q == "confused-deputy" {
		paths, err := parseConfusedDeputy(souffleOut)
		if err != nil {
			return nil, err
		}
		all = append(all, paths...)
	}

	// Filter by max-hops.
	var filtered []discoveredPath
	for _, p := range all {
		if p.Hops <= opts.maxHops {
			filtered = append(filtered, p)
		}
	}

	slices.SortFunc(filtered, func(a, b discoveredPath) int {
		if a.Category != b.Category {
			return strings.Compare(a.Category, b.Category)
		}
		if a.Hops != b.Hops {
			return a.Hops - b.Hops
		}
		return strings.Compare(a.Source, b.Source)
	})
	return filtered, nil
}

func parseEscalation(dir string) ([]discoveredPath, error) {
	lines, err := readCSV(filepath.Join(dir, "escalation_path.csv"))
	if err != nil {
		return nil, err
	}
	var out []discoveredPath
	for _, cols := range lines {
		if len(cols) < 6 {
			continue
		}
		hops, _ := strconv.Atoi(cols[2])
		path := filterHops(cols[3:6])
		path = append(path, cols[1])
		out = append(out, discoveredPath{
			Category: "escalation",
			Source:   cols[0],
			Target:   cols[1],
			Hops:     hops,
			Path:     path,
		})
	}
	return out, nil
}

func parseExfil(dir string) ([]discoveredPath, error) {
	lines, err := readCSV(filepath.Join(dir, "exfil_path.csv"))
	if err != nil {
		return nil, err
	}
	var out []discoveredPath
	for _, cols := range lines {
		if len(cols) < 4 {
			continue
		}
		hops, _ := strconv.Atoi(cols[3])
		out = append(out, discoveredPath{
			Category: "exfiltration",
			Source:   cols[0],
			Target:   cols[1],
			ViaRole:  cols[2],
			Hops:     hops,
			Path:     []string{cols[0], cols[2], cols[1]},
		})
	}
	return out, nil
}

func parseExternal(dir string) ([]discoveredPath, error) {
	lines, err := readCSV(filepath.Join(dir, "external_reach.csv"))
	if err != nil {
		return nil, err
	}
	var out []discoveredPath
	for _, cols := range lines {
		if len(cols) < 5 {
			continue
		}
		hops, _ := strconv.Atoi(cols[4])
		out = append(out, discoveredPath{
			Category: "external-reach",
			Source:   cols[0],
			Target:   cols[1],
			Action:   cols[2],
			ViaRole:  cols[3],
			Hops:     hops,
			Path:     []string{cols[0], cols[3], cols[1]},
		})
	}
	return out, nil
}

func parseConfusedDeputy(dir string) ([]discoveredPath, error) {
	lines, err := readCSV(filepath.Join(dir, "confused_deputy_path.csv"))
	if err != nil {
		return nil, err
	}
	var out []discoveredPath
	for _, cols := range lines {
		if len(cols) < 4 {
			continue
		}
		out = append(out, discoveredPath{
			Category: "confused-deputy",
			Source:   cols[0],
			Target:   cols[2],
			Action:   cols[3],
			Service:  cols[1],
			Hops:     1,
			Path:     []string{cols[1], cols[0], cols[2]},
		})
	}
	return out, nil
}

func parseCounts(dir string) map[string]int {
	counts := map[string]int{}
	lines, err := readCSV(filepath.Join(dir, "_discovery_count.csv"))
	if err != nil {
		return counts
	}
	for _, cols := range lines {
		if len(cols) >= 2 {
			n, _ := strconv.Atoi(cols[1])
			counts[cols[0]] = n
		}
	}
	return counts
}

// ── Utilities ──

func readCSV(path string) ([][]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var rows [][]string
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		rows = append(rows, strings.Split(line, "\t"))
	}
	return rows, nil
}

func filterHops(hops []string) []string {
	var out []string
	for _, h := range hops {
		if h != "" && h != "—" {
			out = append(out, h)
		}
	}
	return out
}

func countLines(path string) int {
	data, _ := os.ReadFile(path)
	n := 0
	for _, b := range data {
		if b == '\n' {
			n++
		}
	}
	return n
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "discovery: "+format+"\n", args...)
	os.Exit(1)
}

// ── JSON output ──

type jsonReport struct {
	Counts       map[string]int          `json:"counts"`
	Novel        []discoveredPath        `json:"novel"`
	Confirmed    []discoveredPath        `json:"confirmed,omitempty"`
	Verification map[string]verifyStatus `json:"verification,omitempty"`
	Total        int                     `json:"total"`
}

func reportJSON(all []discoveredPath, novel, confirmed []discoveredPath, counts map[string]int) {
	reportJSONVerified(all, novel, confirmed, counts, nil)
}

func reportJSONVerified(all []discoveredPath, novel, confirmed []discoveredPath, counts map[string]int, verification map[int]verifyStatus) {
	r := jsonReport{
		Counts:    counts,
		Novel:     novel,
		Confirmed: confirmed,
		Total:     len(all),
	}
	if r.Novel == nil {
		r.Novel = []discoveredPath{}
	}
	if verification != nil {
		r.Verification = make(map[string]verifyStatus, len(verification))
		for i, v := range verification {
			r.Verification[fmt.Sprintf("%d", i)] = v
		}
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(r)
}
