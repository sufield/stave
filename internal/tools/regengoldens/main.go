// Command regengoldens regenerates e2e fixture goldens and reports a
// categorized diff so the developer can tell metadata churn apart from
// behavioral change before committing.
//
// Usage:
//
//	go run ./internal/tools/regengoldens               # regenerate all and report
//	go run ./internal/tools/regengoldens -dry-run      # preview without writing
//	go run ./internal/tools/regengoldens -filter s3    # regex filter on fixture name
//
// Invoked from the `regenerate-goldens` Makefile target. The tool wraps
// the existing `./stave apply` / `check` / `enforce` invocations — it
// does not change the regeneration mechanism, it just batches and
// classifies.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const stavePath = "./stave"
const nowFlag = "2026-01-11T00:00:00Z"
const profileNow = "2026-01-15T00:00:00Z"
const maxUnsafe = "168h"

type diffCategory int

const (
	catClean diffCategory = iota
	catFingerprintOnly
	catMetadataOnly
	catBehavioral
	catMixed
	catError
)

func (c diffCategory) String() string {
	switch c {
	case catClean:
		return "CLEAN"
	case catFingerprintOnly:
		return "FINGERPRINT-ONLY"
	case catMetadataOnly:
		return "METADATA-ONLY"
	case catBehavioral:
		return "BEHAVIORAL"
	case catMixed:
		return "MIXED"
	case catError:
		return "ERROR"
	}
	return "?"
}

type fixtureReport struct {
	Fixture  string
	Category diffCategory
	Details  []string
	Err      error
}

func main() {
	dryRun := flag.Bool("dry-run", false, "preview diffs without writing goldens")
	filter := flag.String("filter", "", "regex filter on fixture directory name")
	rootFlag := flag.String("root", "testdata/e2e", "fixture root directory")
	flag.Parse()

	var filterRE *regexp.Regexp
	if *filter != "" {
		var err error
		filterRE, err = regexp.Compile(*filter)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid -filter regex: %v\n", err)
			os.Exit(2)
		}
	}

	if _, err := os.Stat(stavePath); err != nil {
		fmt.Fprintf(os.Stderr, "stave binary not found at %s — run `make build` first\n", stavePath)
		os.Exit(2)
	}

	entries, err := os.ReadDir(*rootFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read %s: %v\n", *rootFlag, err)
		os.Exit(2)
	}

	var reports []fixtureReport
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if filterRE != nil && !filterRE.MatchString(name) {
			continue
		}
		fixDir := filepath.Join(*rootFlag, name)
		r := processFixture(name, fixDir, *dryRun)
		reports = append(reports, r)
	}

	printReport(reports, *dryRun)
}

// processFixture runs the correct stave invocation for the fixture, diffs
// the result against the existing goldens, classifies, and (unless
// dry-run) writes updated goldens.
func processFixture(name, fixDir string, dryRun bool) fixtureReport {
	r := fixtureReport{Fixture: name}

	stdout, exitCode, err := runStave(fixDir)
	if err != nil {
		r.Category = catError
		r.Err = err
		return r
	}

	goldens := detectGoldens(fixDir)
	if len(goldens) == 0 {
		r.Category = catClean
		return r
	}

	cat := catClean
	for _, g := range goldens {
		newContent, derivErr := deriveGolden(g, stdout, exitCode)
		if derivErr != nil {
			r.Category = catError
			r.Err = derivErr
			return r
		}
		oldContent, _ := os.ReadFile(filepath.Join(fixDir, g))
		subCat, detail := classifyDiff(g, oldContent, newContent)
		if detail != "" {
			r.Details = append(r.Details, detail)
		}
		cat = mergeCategory(cat, subCat)
		if !dryRun && subCat != catClean {
			if err := os.WriteFile(filepath.Join(fixDir, g), newContent, 0o644); err != nil {
				r.Category = catError
				r.Err = err
				return r
			}
		}
	}
	r.Category = cat
	return r
}

// runStave picks the invocation shape from the fixture layout (command.txt,
// profile-style, or default apply with args.txt) and returns stdout + exit.
func runStave(fixDir string) ([]byte, int, error) {
	cmdFile := filepath.Join(fixDir, "command.txt")
	obsFile := filepath.Join(fixDir, "observations.json")
	goldenFile := filepath.Join(fixDir, "golden.json")

	switch {
	case exists(cmdFile):
		content, err := os.ReadFile(cmdFile)
		if err != nil {
			return nil, 0, err
		}
		expanded := strings.ReplaceAll(strings.TrimSpace(string(content)), "$CASE_DIR", fixDir)
		// Match the e2e harness's pre-run cleanup so enforce-style fixtures
		// don't inherit a stale outdir that flips the exit code.
		os.RemoveAll(filepath.Join(fixDir, "outdir"))
		return runCmd(strings.Fields(expanded))
	case exists(obsFile) && exists(goldenFile):
		profile := inferProfile(filepath.Base(fixDir))
		args := []string{
			"apply",
			"--profile", profile,
			"--input", obsFile,
			"--now", profileNow,
		}
		if profile == "hipaa" {
			args = append(args, "--include-all")
		}
		return runCmd(args)
	default:
		args := []string{
			"apply",
			"--controls", filepath.Join(fixDir, "controls"),
			"--observations", filepath.Join(fixDir, "observations"),
			"--max-unsafe", maxUnsafe,
			"--now", nowFlag,
		}
		if argsData, err := os.ReadFile(filepath.Join(fixDir, "args.txt")); err == nil {
			extra := strings.ReplaceAll(strings.TrimSpace(string(argsData)), "$CASE_DIR", fixDir)
			args = append(args, strings.Fields(extra)...)
		}
		return runCmd(args)
	}
}

func inferProfile(dirName string) string {
	switch {
	case strings.HasPrefix(dirName, "aws-s3-"):
		return "aws-s3"
	case strings.Contains(dirName, "hipaa"):
		return "hipaa"
	}
	return "aws-s3"
}

func runCmd(args []string) ([]byte, int, error) {
	cmd := exec.Command(stavePath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	exitCode := 0
	if exitErr, ok := err.(*exec.ExitError); ok {
		exitCode = exitErr.ExitCode()
	} else if err != nil {
		return nil, 0, fmt.Errorf("exec: %w\nstderr: %s", err, stderr.String())
	}
	return stdout.Bytes(), exitCode, nil
}

// detectGoldens lists golden filenames present in the fixture dir.
func detectGoldens(fixDir string) []string {
	candidates := []string{
		"expected.out.json",
		"expected.summary.json",
		"expected.findings.count",
		"expected.exit",
		"expected.input_hashes.json",
		"expected.source_evidence.json",
		"expected.out.sarif",
		"golden.json",
	}
	var found []string
	for _, c := range candidates {
		if exists(filepath.Join(fixDir, c)) {
			found = append(found, c)
		}
	}
	return found
}

// deriveGolden produces the updated byte content for a given golden file
// from the freshly-captured stdout + exit.
func deriveGolden(golden string, stdout []byte, exitCode int) ([]byte, error) {
	switch golden {
	case "expected.out.json", "golden.json":
		return stdout, nil
	case "expected.summary.json":
		return extractJSON(stdout, "summary")
	case "expected.findings.count":
		return extractFindingsCount(stdout)
	case "expected.exit":
		return fmt.Appendf(nil, "%d\n", exitCode), nil
	case "expected.input_hashes.json":
		return extractJSON(stdout, "run", "input_hashes")
	case "expected.source_evidence.json":
		return extractSourceEvidence(stdout)
	case "expected.out.sarif":
		return stdout, nil
	}
	return nil, fmt.Errorf("unknown golden type: %s", golden)
}

func extractJSON(stdout []byte, path ...string) ([]byte, error) {
	var m map[string]any
	if err := json.Unmarshal(stdout, &m); err != nil {
		return nil, err
	}
	var cur any = m
	for _, k := range path {
		mm, ok := cur.(map[string]any)
		if !ok {
			return []byte("{}\n"), nil
		}
		cur = mm[k]
	}
	out, err := json.MarshalIndent(cur, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

func extractFindingsCount(stdout []byte) ([]byte, error) {
	var m map[string]any
	if err := json.Unmarshal(stdout, &m); err != nil {
		return nil, err
	}
	findings, _ := m["findings"].([]any)
	return fmt.Appendf(nil, "%d", len(findings)), nil
}

func extractSourceEvidence(stdout []byte) ([]byte, error) {
	var m map[string]any
	if err := json.Unmarshal(stdout, &m); err != nil {
		return nil, err
	}
	findings, _ := m["findings"].([]any)
	out := map[string]any{}
	for _, f := range findings {
		fm, _ := f.(map[string]any)
		ev, _ := fm["evidence"].(map[string]any)
		if se, ok := ev["source_evidence"]; ok {
			cid, _ := fm["control_id"].(string)
			out[cid] = se
		}
	}
	buf, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(buf, '\n'), nil
}

// classifyDiff compares old and new golden bytes and returns the diff
// category plus a short human-readable detail string. Returns catClean
// if they match after stripping volatile fields (tool_version, extensions).
func classifyDiff(goldenName string, oldBytes, newBytes []byte) (diffCategory, string) {
	if bytes.Equal(oldBytes, newBytes) {
		return catClean, ""
	}

	// Non-JSON goldens (count + exit): compare trimmed so the trailing-
	// newline convention difference between legacy (no \n) and newer
	// (trailing \n) fixtures doesn't show up as a false-positive
	// behavioral diff. Any real value change is BEHAVIORAL.
	if goldenName == "expected.findings.count" || goldenName == "expected.exit" {
		oldT := strings.TrimSpace(string(oldBytes))
		newT := strings.TrimSpace(string(newBytes))
		if oldT == newT {
			return catClean, ""
		}
		return catBehavioral, fmt.Sprintf("%s: %q → %q", goldenName, oldT, newT)
	}

	// SARIF: fall back to byte-level diff as BEHAVIORAL (SARIF field
	// mapping to metadata-vs-behavioral isn't defined here; err safer).
	if goldenName == "expected.out.sarif" {
		return catBehavioral, fmt.Sprintf("%s: sarif content changed", goldenName)
	}

	var oldVal, newVal any
	oldErr := json.Unmarshal(oldBytes, &oldVal)
	newErr := json.Unmarshal(newBytes, &newVal)
	if oldErr != nil || newErr != nil {
		return catBehavioral, fmt.Sprintf("%s: unparseable JSON diff", goldenName)
	}

	stripVolatile(oldVal)
	stripVolatile(newVal)

	paths := diffPaths(oldVal, newVal, "")
	if len(paths) == 0 {
		return catClean, ""
	}

	hasFingerprint := false
	hasMetadata := false
	hasBehavioral := false
	for _, p := range paths {
		switch classifyPath(p) {
		case "fingerprint":
			hasFingerprint = true
		case "metadata":
			hasMetadata = true
		default:
			hasBehavioral = true
		}
	}

	switch {
	case hasBehavioral && hasMetadata:
		return catMixed, fmt.Sprintf("%s: %s", goldenName, summarizePaths(paths, 4))
	case hasBehavioral:
		return catBehavioral, fmt.Sprintf("%s: %s", goldenName, summarizePaths(paths, 4))
	case hasMetadata:
		return catMetadataOnly, fmt.Sprintf("%s: %s", goldenName, summarizePaths(paths, 4))
	case hasFingerprint:
		return catFingerprintOnly, fmt.Sprintf("%s: run.policy_fingerprint", goldenName)
	}
	return catClean, ""
}

// stripVolatile removes fields the test harness ignores (tool_version,
// extensions) so they don't falsely drive the diff category.
func stripVolatile(v any) {
	m, ok := v.(map[string]any)
	if !ok {
		return
	}
	delete(m, "extensions")
	if run, ok := m["run"].(map[string]any); ok {
		delete(run, "tool_version")
	}
}

// diffPaths walks two JSON values and returns a sorted list of dot-paths
// that differ between them.
func diffPaths(a, b any, prefix string) []string {
	var out []string
	switch av := a.(type) {
	case map[string]any:
		bv, ok := b.(map[string]any)
		if !ok {
			return []string{prefix}
		}
		keys := make(map[string]struct{})
		for k := range av {
			keys[k] = struct{}{}
		}
		for k := range bv {
			keys[k] = struct{}{}
		}
		var sorted []string
		for k := range keys {
			sorted = append(sorted, k)
		}
		sort.Strings(sorted)
		for _, k := range sorted {
			child := k
			if prefix != "" {
				child = prefix + "." + k
			}
			out = append(out, diffPaths(av[k], bv[k], child)...)
		}
	case []any:
		bv, ok := b.([]any)
		if !ok {
			return []string{prefix}
		}
		if len(av) != len(bv) {
			return []string{prefix + "[len]"}
		}
		for i := range av {
			out = append(out, diffPaths(av[i], bv[i], fmt.Sprintf("%s[%d]", prefix, i))...)
		}
	default:
		aj, _ := json.Marshal(a)
		bj, _ := json.Marshal(b)
		if !bytes.Equal(aj, bj) {
			out = append(out, prefix)
		}
	}
	return out
}

// classifyPath returns "fingerprint", "metadata", or "behavioral" for a
// dot-path diffed between two goldens.
//
// Metadata paths are purely projected from the control YAML (name,
// description, compliance, remediation, exposure). Everything else —
// findings identity, count, severity, evidence, summary, status,
// risk_signals, top_exposures, run fields other than fingerprint — is
// treated as behavioral so the developer is prompted to review.
func classifyPath(path string) string {
	if path == "run.policy_fingerprint" {
		return "fingerprint"
	}
	// findings[i].<metadata-subfield>
	if strings.HasPrefix(path, "findings[") {
		// extract the sub-path after the index
		rest := path
		if _, after, found := strings.Cut(path, "]."); found {
			rest = after
		}
		switch {
		case rest == "control_name",
			rest == "control_description",
			strings.HasPrefix(rest, "control_compliance"),
			strings.HasPrefix(rest, "remediation."),
			strings.HasPrefix(rest, "exposure."):
			return "metadata"
		}
	}
	return "behavioral"
}

func summarizePaths(paths []string, limit int) string {
	if len(paths) <= limit {
		return strings.Join(paths, ", ")
	}
	return fmt.Sprintf("%s … (+%d more)", strings.Join(paths[:limit], ", "), len(paths)-limit)
}

func mergeCategory(a, b diffCategory) diffCategory {
	if a == catError || b == catError {
		return catError
	}
	// Most-severe wins for aggregating over multiple goldens in a fixture.
	rank := func(c diffCategory) int {
		switch c {
		case catMixed:
			return 4
		case catBehavioral:
			return 3
		case catMetadataOnly:
			return 2
		case catFingerprintOnly:
			return 1
		}
		return 0
	}
	// If one is behavioral and the other is metadata, the combination is MIXED.
	if (a == catBehavioral && b == catMetadataOnly) || (a == catMetadataOnly && b == catBehavioral) {
		return catMixed
	}
	if rank(a) >= rank(b) {
		return a
	}
	return b
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// printReport emits the human-readable summary.
func printReport(reports []fixtureReport, dryRun bool) {
	mode := "write mode"
	if dryRun {
		mode = "dry-run mode"
	}
	counts := map[diffCategory]int{}
	for _, r := range reports {
		counts[r.Category]++
	}

	fmt.Println("Golden regeneration report")
	fmt.Println("==========================")
	fmt.Printf("Mode:              %s\n", mode)
	fmt.Printf("Fixtures scanned:  %d\n", len(reports))
	fmt.Printf("  CLEAN:           %d\n", counts[catClean])
	fmt.Printf("  FINGERPRINT-ONLY:%d\n", counts[catFingerprintOnly])
	fmt.Printf("  METADATA-ONLY:   %d\n", counts[catMetadataOnly])
	fmt.Printf("  BEHAVIORAL:      %d\n", counts[catBehavioral])
	fmt.Printf("  MIXED:           %d\n", counts[catMixed])
	fmt.Printf("  ERROR:           %d\n", counts[catError])
	fmt.Println()

	printGroup("Behavioral diffs (inspect before committing)", reports, catBehavioral)
	printGroup("Mixed diffs (inspect before committing)", reports, catMixed)
	printGroup("Errors", reports, catError)
	if counts[catMetadataOnly] > 0 {
		printGroup("Metadata-only diffs (safe to commit)", reports, catMetadataOnly)
	}
	if counts[catFingerprintOnly] > 0 {
		fmt.Println("Fingerprint-only diffs (safe to commit):")
		n := 0
		for _, r := range reports {
			if r.Category == catFingerprintOnly {
				fmt.Printf("  %s\n", r.Fixture)
				n++
				if n >= 10 {
					fmt.Printf("  … (+%d more)\n", counts[catFingerprintOnly]-10)
					break
				}
			}
		}
		fmt.Println()
	}
}

func printGroup(title string, reports []fixtureReport, cat diffCategory) {
	var matches []fixtureReport
	for _, r := range reports {
		if r.Category == cat {
			matches = append(matches, r)
		}
	}
	if len(matches) == 0 {
		return
	}
	fmt.Printf("%s:\n", title)
	for _, r := range matches {
		fmt.Printf("  %s\n", r.Fixture)
		if r.Err != nil {
			fmt.Printf("    error: %v\n", r.Err)
		}
		for _, d := range r.Details {
			fmt.Printf("    %s\n", d)
		}
	}
	fmt.Println()
}
