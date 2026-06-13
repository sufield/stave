// Command regengoldens regenerates e2e fixture goldens and reports a
// categorized diff so the developer can tell metadata churn apart from
// behavioral change before committing.
//
// Usage:
//
//	go run ./internal/tools/regengoldens                  # regenerate all and report
//	go run ./internal/tools/regengoldens -dry-run         # preview without writing
//	go run ./internal/tools/regengoldens -filter s3       # regex filter on fixture name
//	go run ./internal/tools/regengoldens -since HEAD~1    # only fixtures affected by recent control/pack changes
//
// Fixtures are processed sequentially. A previous parallel implementation
// (NumCPU goroutines feeding a worker pool) produced 0-byte fixture
// outputs intermittently — likely fd-exhaustion or pipe-read truncation
// under heavy concurrent fork/exec. Sequential is ~5–10 minutes for the
// full 2525-fixture suite; for iterative work scope with -filter or
// -since.
//
// The -since flag computes "affected domains" from `git diff --name-only
// <ref>` and skips fixtures whose controls dir does not reference any
// affected domain. Adding a single domain's controls (e.g. CTL.OPENSEARCH.*)
// scopes regen to that domain's fixtures, cutting full-suite cost from
// ~50 min to ~30 s. Non-pack changes (chains, schemas, code) fall back
// to a full regen.
//
// Invoked from the `regenerate-goldens` Makefile target. The tool wraps
// the existing `./stave apply` / `check` / `enforce` invocations — it
// does not change the regeneration mechanism, it just batches and
// classifies.
package main

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
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

type fixtureReport struct {
	Fixture  string
	Category diffCategory
	Details  []string
	Err      error
}

// fixtureTimeout caps a single stave invocation. Long enough that
// healthy fixtures finish comfortably, short enough that a stuck
// or runaway invocation doesn't wedge the whole regen.
const fixtureTimeout = 30 * time.Second

// maxWorkers caps -workers regardless of what the operator asked
// for. The cost models exec.Command + JSON parse + golden diff,
// which is mostly I/O; 8 saturates a typical dev machine without
// thrashing the disk.
const maxWorkers = 8

func main() {
	dryRun := flag.Bool("dry-run", false, "preview diffs without writing goldens")
	filter := flag.String("filter", "", "regex filter on fixture directory name")
	rootFlag := flag.String("root", "testdata/e2e", "fixture root directory")
	since := flag.String("since", "", "regen only fixtures affected by control/pack changes vs this git ref (e.g. HEAD~1); empty = full regen")
	changedOnly := flag.Bool("changed-only", false, "convenience for -since=HEAD; regenerate only fixtures affected by working-tree changes")
	workers := flag.Int("workers", 4, "number of fixtures to process in parallel (default 4, max 8)")
	sequential := flag.Bool("sequential", false, "force sequential processing (overrides -workers); useful for debugging")
	// failOnBehavioral turns the human-discipline rule ("review BEHAVIORAL
	// + MIXED before commit") into an exit-code gate suitable for CI.
	// Default off keeps day-to-day local regen unchanged. CI uses
	// `-fail-on-behavioral` to fail the build if any fixture's diff
	// category isn't auto-acceptable (CLEAN / FINGERPRINT-ONLY /
	// METADATA-ONLY). Mixed and behavioral diffs require explicit
	// PR approval, not silent acceptance.
	failOnBehavioral := flag.Bool("fail-on-behavioral", false, "exit non-zero if any fixture has a BEHAVIORAL or MIXED diff; benign categories (CLEAN/FINGERPRINT-ONLY/METADATA-ONLY) are auto-accepted")
	flag.Parse()

	if *changedOnly && *since == "" {
		*since = "HEAD"
	}

	if *workers < 1 {
		*workers = 1
	}
	if *workers > maxWorkers {
		fmt.Fprintf(os.Stderr, "-workers capped at %d\n", maxWorkers)
		*workers = maxWorkers
	}
	if *sequential {
		*workers = 1
	}

	var filterRE *regexp.Regexp
	if *filter != "" {
		var err error
		filterRE, err = regexp.Compile(*filter)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid -filter regex: %v\n", err)
			os.Exit(2)
		}
	}

	// Compute affected domains from git diff. nil result → full regen
	// (either flag unset, or non-pack changes detected).
	var affected map[string]struct{}
	if *since != "" {
		var err error
		affected, err = affectedDomains(*since)
		if err != nil {
			fmt.Fprintf(os.Stderr, "compute affected domains vs %s: %v\n", *since, err)
			os.Exit(2)
		}
		if affected == nil {
			fmt.Fprintf(os.Stderr, "non-pack changes detected vs %s; falling back to full regen\n", *since)
		} else if len(affected) == 0 {
			fmt.Fprintf(os.Stderr, "no control / pack changes vs %s; nothing to regenerate\n", *since)
		} else {
			fmt.Fprintf(os.Stderr, "affected domains vs %s: %s\n", *since, joinSorted(affected))
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

	// First pass: decide which fixtures are in scope. Print the
	// up-front total so the operator knows how much work the run
	// will do — large regen passes are slow and the early signal
	// helps with abort-or-wait decisions.
	type job struct{ name, fixDir string }
	var jobs []job
	skipped := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if filterRE != nil && !filterRE.MatchString(name) {
			continue
		}
		fixDir := filepath.Join(*rootFlag, name)
		if affected != nil && !fixtureIntersectsAffected(fixDir, affected) {
			skipped++
			continue
		}
		jobs = append(jobs, job{name: name, fixDir: fixDir})
	}
	if skipped > 0 && affected != nil {
		fmt.Fprintf(os.Stderr, "skipped %d fixtures unaffected by changes vs %s\n", skipped, *since)
	}
	scopeNote := "all fixtures"
	if affected != nil {
		scopeNote = fmt.Sprintf("affected by changes vs %s", *since)
	} else if filterRE != nil {
		scopeNote = fmt.Sprintf("matching -filter %q", *filter)
	}
	fmt.Fprintf(os.Stderr, "regenerating %d fixtures (%s) with %d worker(s); per-fixture timeout %s\n",
		len(jobs), scopeNote, *workers, fixtureTimeout)

	// Second pass: run with a bounded worker pool. A buffered
	// channel of size *workers acts as a semaphore — a worker
	// must acquire a slot before invoking stave, releasing on
	// completion. sync.WaitGroup tracks completion; results are
	// collected via a results channel, drained after Wait().
	reports := make([]fixtureReport, len(jobs))
	if *workers == 1 {
		for i, j := range jobs {
			reports[i] = processFixture(j.name, j.fixDir, *dryRun)
		}
	} else {
		sem := make(chan struct{}, *workers)
		var wg sync.WaitGroup
		for i, j := range jobs {
			wg.Add(1)
			sem <- struct{}{}
			go func() {
				defer wg.Done()
				defer func() { <-sem }()
				reports[i] = processFixture(j.name, j.fixDir, *dryRun)
			}()
		}
		wg.Wait()
	}

	// Inject per-job skipped placeholder rows so the report
	// preserves the "every fixture in the tree is accounted for"
	// invariant the printer relies on.
	if skipped > 0 && affected != nil {
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			name := e.Name()
			if filterRE != nil && !filterRE.MatchString(name) {
				continue
			}
			fixDir := filepath.Join(*rootFlag, name)
			if !fixtureIntersectsAffected(fixDir, affected) {
				reports = append(reports, fixtureReport{Fixture: name, Category: catClean})
			}
		}
	}

	slices.SortFunc(reports, func(a, b fixtureReport) int { return cmp.Compare(a.Fixture, b.Fixture) })
	printReport(reports, *dryRun)

	// Exit-code gate: when -fail-on-behavioral is set, surface a
	// non-zero exit if any fixture landed in a category that
	// requires human review. The benign categories (CLEAN /
	// FINGERPRINT-ONLY / METADATA-ONLY) flow through silently —
	// that's the "auto-accept" half of the rule. BEHAVIORAL +
	// MIXED + ERROR force CI to fail so the human PR step is the
	// gate, not the regen step.
	if *failOnBehavioral {
		var needsReview int
		for _, r := range reports {
			switch r.Category {
			case catBehavioral, catMixed, catError:
				needsReview++
			}
		}
		if needsReview > 0 {
			fmt.Fprintf(os.Stderr, "\n%d fixture(s) need human review (BEHAVIORAL / MIXED / ERROR). See sections above. Failing exit because -fail-on-behavioral is set.\n", needsReview)
			os.Exit(3)
		}
	}
}

// affectedDomains returns the set of domain tokens (lowercase) whose
// controls / chains / pack manifest changed since baseRef. Returns
// (nil, nil) to signal "fall back to full regen": at least one changed
// path lies inside the project subtree but outside the pack/control
// surface this tool understands (schemas, code, scripts, etc.).
//
// Heuristic mapping (after stripping the cwd's repo-relative prefix):
//   - controls/<domain>/...                              → affects domain
//   - internal/controldata/embedded/<dom>/...            → affects domain (synced copies)
//   - internal/builtin/pack/embedded/packs/<pack>.yaml   → affects pack
//   - chains/<word>_*.yaml                               → affects word
//
// Generated artifacts derived from the embedded controls are ignored:
//   - README.md, README.tmpl.md, docs/controls/reference.md
//
// Paths outside this tool's working subtree (i.e. that did NOT have the
// expected git prefix) are silently ignored — they cannot affect this
// project's goldens.
//
// Anything else inside the subtree triggers full-regen fallback. The
// list of out-of-scope paths is logged so the operator can see why
// scoping degraded.
func affectedDomains(baseRef string) (map[string]struct{}, error) {
	prefix, err := gitPrefix()
	if err != nil {
		return nil, err
	}
	diffOut, err := exec.Command("git", "diff", "--name-only", baseRef).Output()
	if err != nil {
		return nil, fmt.Errorf("git diff: %w", err)
	}
	// Include untracked-but-not-ignored files so newly authored controls
	// (typical case during iteration) count as "changed since baseRef".
	// `git ls-files --others` reports paths relative to cwd, while
	// `git diff` reports paths relative to repo root — prefix the
	// untracked entries so the prefix-strip logic below sees them
	// consistently.
	//
	// Intentional discard: a failed `git ls-files` (e.g. running outside
	// a repo, or an outdated git binary) just means we treat untracked
	// files as absent. The diff-based path still works; this is a
	// best-effort enrichment of the changed-files set, not a
	// correctness-critical step.
	untrackedOut, _ := exec.Command("git", "ls-files", "--others", "--exclude-standard").Output()
	if prefix != "" && len(untrackedOut) > 0 {
		var b strings.Builder
		for line := range strings.SplitSeq(string(untrackedOut), "\n") {
			if line == "" {
				continue
			}
			b.WriteString(prefix)
			b.WriteString(line)
			b.WriteByte('\n')
		}
		untrackedOut = []byte(b.String())
	}
	out := append(append([]byte{}, diffOut...), untrackedOut...)
	domains := map[string]struct{}{}
	var outOfScope []string
	for raw := range strings.SplitSeq(string(out), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		// Restrict to changes inside our subtree.
		if prefix != "" {
			rel, ok := strings.CutPrefix(line, prefix)
			if !ok {
				continue
			}
			line = rel
		}
		switch {
		case strings.HasPrefix(line, "controls/"):
			parts := strings.SplitN(line, "/", 3)
			if len(parts) >= 2 {
				domains[strings.ToLower(parts[1])] = struct{}{}
			}
		case strings.HasPrefix(line, "internal/controldata/embedded/"):
			parts := strings.SplitN(line, "/", 5)
			if len(parts) >= 4 {
				domains[strings.ToLower(parts[3])] = struct{}{}
			}
		case strings.HasPrefix(line, "internal/builtin/pack/embedded/packs/"):
			pack := strings.TrimSuffix(filepath.Base(line), ".yaml")
			if pack != "" {
				domains[strings.ToLower(pack)] = struct{}{}
			}
		case strings.HasPrefix(line, "chains/"):
			// Chain filenames are <domain>_<rest>.yaml. Domain is the
			// token before the first underscore.
			base := strings.TrimSuffix(filepath.Base(line), ".yaml")
			if dom, _, ok := strings.Cut(base, "_"); ok && dom != "" {
				domains[strings.ToLower(dom)] = struct{}{}
			} else {
				outOfScope = append(outOfScope, line)
			}
		case isGoldenSafe(line):
			// Generated artifact derived from the embedded controls;
			// no observable effect on golden output.
		default:
			outOfScope = append(outOfScope, line)
		}
	}
	if len(outOfScope) > 0 {
		fmt.Fprintf(os.Stderr, "out-of-scope changes vs %s (forcing full regen):\n", baseRef)
		for _, p := range outOfScope[:min(len(outOfScope), 5)] {
			fmt.Fprintf(os.Stderr, "  %s\n", p)
		}
		if len(outOfScope) > 5 {
			fmt.Fprintf(os.Stderr, "  … (+%d more)\n", len(outOfScope)-5)
		}
		return nil, nil
	}
	return domains, nil
}

// gitPrefix returns the cwd's path within the git repo (with trailing
// slash, or empty string if cwd is the repo root). Used to strip from
// `git diff` output so paths line up with our heuristic rules.
func gitPrefix() (string, error) {
	out, err := exec.Command("git", "rev-parse", "--show-prefix").Output()
	if err != nil {
		return "", fmt.Errorf("git rev-parse --show-prefix: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

// isGoldenSafe reports whether a changed path is a generated artifact
// or development-only tool that cannot affect e2e goldens. The README
// and control reference are produced from the embedded controls by
// `make readme` / `make docs-controls`. Files under internal/tools/
// are dev-time scripts; their build artifacts (this regen tool itself,
// genreadme, gencontroldocs) are rebuilt by the Makefile target before
// regen runs, so source-level edits don't change golden behavior.
func isGoldenSafe(path string) bool {
	switch path {
	case "README.md", "README.tmpl.md", "docs/controls/reference.md":
		return true
	}
	return strings.HasPrefix(path, "internal/tools/")
}

// fixtureIntersectsAffected reports whether the fixture references
// any affected domain. Returns true conservatively when the fixture's
// control set is not statically inspectable (command.txt-style or
// profile-style fixtures) so those always re-evaluate.
func fixtureIntersectsAffected(fixDir string, affected map[string]struct{}) bool {
	loaded := fixtureDomains(fixDir)
	if loaded == nil {
		return true
	}
	for d := range loaded {
		if _, ok := affected[d]; ok {
			return true
		}
	}
	return false
}

// fixtureDomains returns the set of domain tokens loaded by the fixture's
// controls dir, derived from the `id: CTL.<DOMAIN>.*` line in each YAML.
// Returns nil to indicate the fixture has no inspectable controls dir
// (caller should treat as "always affected").
func fixtureDomains(fixDir string) map[string]struct{} {
	dir := filepath.Join(fixDir, "controls")
	st, err := os.Stat(dir)
	if err != nil || !st.IsDir() {
		return nil
	}
	out := map[string]struct{}{}
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil || d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".yaml") && !strings.HasSuffix(path, ".yml") {
			return nil
		}
		if dom := domainFromControlYAML(path); dom != "" {
			out[dom] = struct{}{}
		}
		return nil
	})
	return out
}

// domainFromControlYAML reads the first `id:` line and extracts the
// domain token from a CTL.<DOMAIN>.* identifier. Returns "" if not
// matched.
func domainFromControlYAML(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 64*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "id:") {
			continue
		}
		id := strings.TrimSpace(strings.TrimPrefix(line, "id:"))
		// Strip optional quotes.
		id = strings.Trim(id, `"'`)
		parts := strings.Split(id, ".")
		if len(parts) >= 2 && strings.EqualFold(parts[0], "CTL") {
			return strings.ToLower(parts[1])
		}
		return ""
	}
	return ""
}

// joinSorted formats a domain set as a sorted comma-separated list for
// log output.
func joinSorted(set map[string]struct{}) string {
	names := make([]string, 0, len(set))
	for n := range set {
		names = append(names, n)
	}
	slices.Sort(names)
	return strings.Join(names, ", ")
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
		// Refuse to overwrite a JSON-typed golden with non-JSON
		// content. A regression that wrote a stave error payload
		// into expected.out.json corrupted the fixture and made
		// downstream e2e tests fail with confusing parse errors.
		// Preserve the prior file when the produced content isn't
		// valid JSON.
		if isJSONGolden(g) && !json.Valid(newContent) {
			r.Category = catError
			r.Err = fmt.Errorf("%s: produced output is not valid JSON; refusing to overwrite golden", g)
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
		// --format json: the CLI default flipped to text for first-time
		// human users, but these profile fixtures store JSON goldens.
		// Without this flag the tool produces text and the
		// "produced output is not valid JSON" guard rejects every regen.
		args := []string{
			"apply",
			"--profile", profile,
			"--input", obsFile,
			"--now", profileNow,
			"--format", "json",
		}
		if profile == "hipaa" {
			args = append(args, "--include-all")
		}
		return runCmd(args)
	default:
		// --format json: the CLI default is text (optimized for first-time
		// human users), but these fixtures store JSON-family goldens
		// (expected.out.json + summary/count/source_evidence derived from
		// it). A fixture that needs a different format (e.g. sarif) sets it
		// via args.txt, which is appended after this flag and so wins.
		args := []string{
			"apply",
			"--controls", filepath.Join(fixDir, "controls"),
			"--observations", filepath.Join(fixDir, "observations"),
			"--max-unsafe", maxUnsafe,
			"--now", nowFlag,
			"--format", "json",
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
	// Bound every invocation: a hung stave (deadlock, infinite
	// loop) would otherwise wedge the worker pool indefinitely.
	// Timeout errors return a recognizable error message so the
	// report can flag the fixture rather than silently continuing.
	ctx, cancel := context.WithTimeout(context.Background(), fixtureTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, stavePath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return nil, 0, fmt.Errorf("timeout after %s: %w\nstderr: %s", fixtureTimeout, ctx.Err(), stderr.String())
	}
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

	// SARIF: parse as JSON and reuse the path classifier. Stave's
	// SARIF-specific paths (under runs[].results[].properties) are
	// registered in classifyPath alongside the out.v0.1 paths.

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
		delete(run, "policy_fingerprint")
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
		slices.Sort(sorted)
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
		aj, errA := json.Marshal(a)
		bj, errB := json.Marshal(b)
		if errA != nil || errB != nil || !bytes.Equal(aj, bj) {
			out = append(out, prefix)
		}
	}
	return out
}

// classifyPath returns "fingerprint", "metadata", or "behavioral" for a
// dot-path diffed between two goldens.
//
// Metadata paths are purely projected from the control YAML (name,
// description, compliance, remediation, exposure, alternatives) or
// from the per-tool inventory (coverage_posture). Everything else —
// findings identity, count, severity, evidence, summary, status,
// risk_signals, top_exposures, run fields other than fingerprint — is
// treated as behavioral so the developer is prompted to review.
func classifyPath(path string) string {
	if path == "run.policy_fingerprint" {
		return "fingerprint"
	}
	// coverage_posture is computed entirely from declarative data
	// (control alternatives blocks + inventory files); changes here
	// reflect data-only edits, not detection behavior.
	if path == "coverage_posture" || strings.HasPrefix(path, "coverage_posture.") {
		return "metadata"
	}
	// remediation_groups[].fix_plan uses the same RemediationPlanDTO
	// as findings[].fix_plan; the command → action rename propagates
	// through both. Both field keys reflect the same underlying
	// string; identity-set is unchanged.
	if strings.HasPrefix(path, "remediation_groups[") {
		if strings.HasSuffix(path, ".fix_plan.command") || strings.HasSuffix(path, ".fix_plan.action") {
			return "metadata"
		}
	}
	// SARIF: per-result properties bag entries derived from finding
	// metadata. Identity-set unchanged; only the property values
	// reflect Stave-side metadata changes.
	if strings.HasPrefix(path, "runs[") && strings.Contains(path, ".results[") {
		switch {
		case strings.HasSuffix(path, ".properties.stave/classification"),
			strings.HasSuffix(path, ".properties.stave/scope_tags"),
			strings.Contains(path, ".properties.stave/scope_tags["),
			strings.HasSuffix(path, ".properties.alternatives"),
			strings.Contains(path, ".properties.alternatives["):
			return "metadata"
		}
	}
	// SARIF: per-rule properties bag entries derived from control
	// metadata. Same reasoning as the per-result case.
	if strings.HasPrefix(path, "runs[") && strings.Contains(path, ".tool.driver.rules[") {
		switch {
		case strings.HasSuffix(path, ".properties.alternatives"),
			strings.Contains(path, ".properties.alternatives["):
			return "metadata"
		}
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
			strings.HasPrefix(rest, "exposure."),
			rest == "alternatives",
			strings.HasPrefix(rest, "alternatives"),
			rest == "classification",
			rest == "scope_tags",
			strings.HasPrefix(rest, "scope_tags["):
			return "metadata"
		}
		// remediation_context.violation.reasoning[*].clause is the
		// translator-rendered prose embedded in JSON. The underlying
		// structured fields (observation_key, observed_value, operator)
		// remain behavioral; only the prose rendering is metadata.
		if strings.HasPrefix(rest, "remediation_context.violation.reasoning") &&
			strings.HasSuffix(rest, ".clause") {
			return "metadata"
		}
		// Sanitization-policy outputs: actual_value on Misconfiguration
		// entries and the derived remediation_context.changes fields
		// (current_value, description, required_value). All four reflect
		// the type-discriminated sanitizer's policy choices, not
		// detection behavior. The underlying finding identity-set is
		// unchanged.
		if strings.HasPrefix(rest, "evidence.misconfigurations") &&
			strings.HasSuffix(rest, ".actual_value") {
			return "metadata"
		}
		if strings.HasPrefix(rest, "remediation_context.changes") {
			switch {
			case strings.HasSuffix(rest, ".current_value"),
				strings.HasSuffix(rest, ".description"),
				strings.HasSuffix(rest, ".required_value"),
				strings.HasSuffix(rest, ".has_safe_default"):
				return "metadata"
			}
		}
		// Command → action field rename on remediation_context and
		// fix_plan. Both sides of the rename (the disappearing
		// "command" key and the new "action" key) reflect the same
		// underlying string (RemediationPlan.Command or
		// RemediationSpec.Action); identity-set is unchanged.
		switch rest {
		case "remediation_context.command", "remediation_context.action",
			"fix_plan.command", "fix_plan.action":
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

// isJSONGolden reports whether the golden file is expected to contain
// valid JSON (or SARIF, which is JSON). Non-JSON goldens
// (expected.exit, expected.findings.count) are excluded.
func isJSONGolden(name string) bool {
	switch name {
	case "expected.out.json",
		"expected.summary.json",
		"expected.input_hashes.json",
		"expected.source_evidence.json",
		"expected.out.sarif",
		"golden.json":
		return true
	}
	return false
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
