//go:build ignore

// Command validate — G2 cross-validation of the subset property.
//
// Runs `stave apply` against a snapshot, then runs the G0+G1 Soufflé
// pipeline (extract.go → schema.dl + rules.dl), then joins compound
// IAM findings against the effective_access relation. Classifies
// each finding as:
//
//	Match      — finding's asset_id appears as a principal_id in
//	             effective_access (the access graph reaches the
//	             asset CEL flagged)
//	CEL-only   — finding's asset_id is NOT a principal_id in
//	             effective_access (the access graph has no edges
//	             touching the asset). Sub-categorized:
//	  CEL-only / Access-graph applicable    — asset is an IAM principal
//	                                          (user/role) AND the
//	                                          finding's predicate paths
//	                                          look like they should
//	                                          have access-graph
//	                                          counterparts (no
//	                                          identity.escalation.*
//	                                          / blastradius. / etc.
//	                                          markers)
//	  CEL-only / Pattern-pre-computed       — asset is an IAM principal
//	                                          but the finding fires on
//	                                          pre-computed boolean
//	                                          facts (escalation
//	                                          pattern present, blast
//	                                          radius too wide, etc.)
//	                                          that aren't access-graph
//	                                          edges
//	Datalog-only — principal_id in effective_access with NO compound
//	             CEL finding pointing at it (novel detection
//	             headroom — what CIA queries will surface)
//
// Usage:
//
//	go run ./reasoning/souffle/iam/validate.go \
//	    -fixture testdata/e2e/e2e-forge-iam-escalate-passrole-autoscaling-fail \
//	    -out     /tmp/g2-validation
//
// The -fixture flag points at a Stave e2e fixture with controls/ and
// observations/ subdirs. The -out directory holds intermediate
// .facts files and the final csv reports.
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
	"slices"
	"strings"
)

type options struct {
	fixture      string
	controls     string
	observations string
	staveBinary  string
	souffleBin   string
	schemaDl     string
	rulesDl      string
	out          string
	now          string
}

func parseFlags() *options {
	opts := &options{}
	flag.StringVar(&opts.fixture, "fixture", "",
		"Path to a Stave e2e fixture (auto-resolves controls/ + observations/).")
	flag.StringVar(&opts.controls, "controls", "",
		"Path to controls directory (overrides -fixture).")
	flag.StringVar(&opts.observations, "observations", "",
		"Path to observations directory (overrides -fixture).")
	flag.StringVar(&opts.staveBinary, "stave", "./stave", "Path to stave binary.")
	flag.StringVar(&opts.souffleBin, "souffle", "souffle", "Path to souffle binary.")
	flag.StringVar(&opts.schemaDl, "schema", "reasoning/souffle/iam/schema.dl",
		"Path to schema.dl.")
	flag.StringVar(&opts.rulesDl, "rules", "reasoning/souffle/iam/rules.dl",
		"Path to rules.dl.")
	flag.StringVar(&opts.out, "out", "/tmp/g2-validation",
		"Output directory for intermediate files + final report.")
	flag.StringVar(&opts.now, "now", "2026-01-15T00:00:00Z",
		"--eval-time value passed to stave apply for deterministic output.")
	flag.Parse()

	if opts.fixture != "" {
		if opts.controls == "" {
			opts.controls = filepath.Join(opts.fixture, "controls")
		}
		if opts.observations == "" {
			opts.observations = filepath.Join(opts.fixture, "observations")
		}
	}
	if opts.controls == "" || opts.observations == "" {
		fmt.Fprintln(os.Stderr, "validate: must supply -fixture or both -controls and -observations")
		os.Exit(2)
	}
	return opts
}

// finding mirrors the subset of out.v0.1 schema this script reads.
// The full out.v0.1 has many more fields; we only need the ones
// that drive classification.
type finding struct {
	ControlID string `json:"control_id"`
	AssetID   string `json:"asset_id"`
	AssetType string `json:"asset_type"`
	Evidence  struct {
		Misconfigurations []struct {
			Property string `json:"property"`
		} `json:"misconfigurations"`
	} `json:"evidence"`
}

type applyOutput struct {
	Findings []finding `json:"findings"`
}

// classification holds per-finding classification result.
type classification struct {
	Category string // "Match", "CEL-only / Access-graph applicable", "CEL-only / Pattern-pre-computed"
	Finding  finding
	Reason   string
}

func main() {
	opts := parseFlags()

	if err := os.MkdirAll(opts.out, 0o755); err != nil {
		fail("mkdir output dir: %v", err)
	}

	// 1. Run stave apply → findings JSON.
	fmt.Println("──── Step 1: stave apply ────")
	findings, err := runStaveApply(opts)
	if err != nil {
		fail("stave apply: %v", err)
	}
	fmt.Printf("  total findings: %d\n", len(findings))

	// 2. Filter to compound IAM (heuristic: asset_type starts with aws_iam_).
	iamFindings := filterCompoundIAM(findings)
	fmt.Printf("  IAM findings (asset_type prefix aws_iam_): %d\n", len(iamFindings))

	// 3. Run G0 extract → .facts files.
	fmt.Println("──── Step 2: G0 extract ────")
	factsDir := filepath.Join(opts.out, "facts")
	if err := runExtract(opts, factsDir); err != nil {
		fail("extract: %v", err)
	}

	// 4. Run G1 rules → effective_access.csv.
	fmt.Println("──── Step 3: G1 rules ────")
	soufflyOut := filepath.Join(opts.out, "souffle")
	if err := runSouffle(opts, factsDir, soufflyOut); err != nil {
		fail("souffle: %v", err)
	}

	// 5. Parse effective_access — set of principal_ids.
	accessPrincipals, totalAccessRows, err := readEffectiveAccessPrincipals(soufflyOut)
	if err != nil {
		fail("read effective_access: %v", err)
	}
	fmt.Printf("  effective_access rows: %d\n", totalAccessRows)
	fmt.Printf("  distinct principals in effective_access: %d\n", len(accessPrincipals))

	// 6. Classify each IAM finding.
	fmt.Println("──── Step 4: classify findings ────")
	results := classifyFindings(iamFindings, accessPrincipals)

	// 7. Datalog-only — principals with effective_access but no CEL finding.
	cellPrincipals := map[string]struct{}{}
	for _, f := range iamFindings {
		cellPrincipals[f.AssetID] = struct{}{}
	}
	var datalogOnly []string
	for p := range accessPrincipals {
		if _, ok := cellPrincipals[p]; !ok {
			datalogOnly = append(datalogOnly, p)
		}
	}
	slices.Sort(datalogOnly)

	// 8. Report.
	report(opts, iamFindings, results, datalogOnly, totalAccessRows)
}

func runStaveApply(opts *options) ([]finding, error) {
	args := []string{
		"apply",
		"--controls", opts.controls,
		"--observations", opts.observations,
		"--eval-time", opts.now,
		"--format", "json",
	}
	cmd := exec.Command(opts.staveBinary, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		// Apply exits 3 when violations exist — that's the case we want.
		// Only fatal-fail on other exit codes.
		exitErr, ok := err.(*exec.ExitError)
		if !ok || exitErr.ExitCode() != 3 {
			return nil, fmt.Errorf("%w\nstderr: %s", err, stderr.String())
		}
	}
	var out applyOutput
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		return nil, fmt.Errorf("parse output JSON: %w", err)
	}
	return out.Findings, nil
}

func filterCompoundIAM(findings []finding) []finding {
	var out []finding
	for _, f := range findings {
		if strings.HasPrefix(f.AssetType, "aws_iam_") {
			out = append(out, f)
		}
	}
	return out
}

func runExtract(opts *options, factsDir string) error {
	args := []string{
		"run", "./reasoning/souffle/iam/extract.go",
		"-snapshot", opts.observations,
		"-controls", opts.controls,
		"-stave", opts.staveBinary,
		"-out", factsDir,
	}
	cmd := exec.Command("go", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Stdout = io.Discard
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("extract: %w\nstderr: %s", err, stderr.String())
	}
	return nil
}

func runSouffle(opts *options, factsDir, outDir string) error {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	args := []string{
		opts.rulesDl,
		"-F", factsDir,
		"-D", outDir,
		"-I", filepath.Dir(opts.rulesDl),
	}
	cmd := exec.Command(opts.souffleBin, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("souffle: %w\nstderr: %s", err, stderr.String())
	}
	return nil
}

func readEffectiveAccessPrincipals(souffleOut string) (map[string]struct{}, int, error) {
	path := filepath.Join(souffleOut, "effective_access.csv")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, err
	}
	principals := map[string]struct{}{}
	total := 0
	for line := range strings.SplitSeq(string(data), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) == 0 {
			continue
		}
		principals[fields[0]] = struct{}{}
		total++
	}
	return principals, total, nil
}

// patternPreComputed checks whether the finding's evidence
// references property paths that look like pre-computed booleans
// (escalation patterns, blast radius indicators, federation
// flags) — i.e., facts that aren't access-graph edges.
//
// Heuristic: if any misconfiguration property path starts with
// one of these prefixes, classify the finding as
// "Pattern-pre-computed" rather than "Access-graph applicable."
// This isn't an exhaustive list; it's the set the current
// compound IAM catalog uses.
var patternPrefixes = []string{
	"identity.escalation.",
	"identity.blastradius.",
	"identity.federation.",
	"identity.nep.",
	"identity.role.assume_chain_depth",
	"identity.role.cross_env",
	"identity.role.cross_account_trust",
	"identity.role.sensitive_resource_count",
	"identity.role.reachable_resources_count",
	"identity.user.sensitive_resource_count",
	"identity.user.reachable_resources_count",
	"identity.policy.shadow_logic",
	"identity.trust.",
	"identity.sso.",
	"identity.access_keys.",
	"identity.console_access.",
	"identity.password_policy.",
	"identity.credentials.",
}

func patternPreComputed(f finding) bool {
	for _, m := range f.Evidence.Misconfigurations {
		for _, prefix := range patternPrefixes {
			if strings.HasPrefix(m.Property, prefix) {
				return true
			}
		}
	}
	return false
}

func classifyFindings(findings []finding, accessPrincipals map[string]struct{}) []classification {
	var out []classification
	for _, f := range findings {
		if _, hit := accessPrincipals[f.AssetID]; hit {
			out = append(out, classification{
				Category: "Match",
				Finding:  f,
				Reason:   "asset_id appears in effective_access principal set",
			})
			continue
		}
		if patternPreComputed(f) {
			out = append(out, classification{
				Category: "CEL-only / Pattern-pre-computed",
				Finding:  f,
				Reason:   "fires on pre-computed boolean predicate (escalation/blastradius/etc.); access graph doesn't represent these as edges",
			})
			continue
		}
		out = append(out, classification{
			Category: "CEL-only / Access-graph applicable",
			Finding:  f,
			Reason:   "asset_id should appear in effective_access but doesn't — Datalog gap candidate",
		})
	}
	return out
}

func report(opts *options, findings []finding, results []classification, datalogOnly []string, totalAccessRows int) {
	counts := map[string]int{}
	for _, r := range results {
		counts[r.Category]++
	}

	fmt.Println()
	fmt.Println("──── G2 Cross-Validation Report ────")
	fmt.Printf("Fixture: %s\n", opts.fixture)
	fmt.Printf("Controls: %s\n", opts.controls)
	fmt.Printf("Observations: %s\n", opts.observations)
	fmt.Println()
	fmt.Printf("Compound IAM findings (asset_type prefix aws_iam_): %d\n", len(findings))
	fmt.Printf("effective_access rows: %d (distinct principals: %d)\n", totalAccessRows, totalAccessRows)
	fmt.Println()
	fmt.Println("Classification counts:")
	categories := []string{
		"Match",
		"CEL-only / Pattern-pre-computed",
		"CEL-only / Access-graph applicable",
	}
	for _, cat := range categories {
		fmt.Printf("  %-50s %d\n", cat, counts[cat])
	}
	fmt.Printf("  %-50s %d\n", "Datalog-only (principals not in CEL findings)", len(datalogOnly))
	fmt.Println()

	// CEL-only/Access-graph-applicable findings — investigate each
	if counts["CEL-only / Access-graph applicable"] > 0 {
		fmt.Println("CEL-only / Access-graph applicable — INVESTIGATE these:")
		for _, r := range results {
			if r.Category == "CEL-only / Access-graph applicable" {
				fmt.Printf("  %s on %s\n", r.Finding.ControlID, r.Finding.AssetID)
				for _, m := range r.Finding.Evidence.Misconfigurations {
					fmt.Printf("    property: %s\n", m.Property)
				}
			}
		}
		fmt.Println()
	}

	// Pattern-pre-computed findings — informational sample
	if counts["CEL-only / Pattern-pre-computed"] > 0 {
		fmt.Println("CEL-only / Pattern-pre-computed (first 5; expected category):")
		shown := 0
		for _, r := range results {
			if r.Category == "CEL-only / Pattern-pre-computed" {
				if shown >= 5 {
					break
				}
				fmt.Printf("  %s on %s\n", r.Finding.ControlID, r.Finding.AssetID)
				for _, m := range r.Finding.Evidence.Misconfigurations {
					fmt.Printf("    property: %s\n", m.Property)
				}
				shown++
			}
		}
		fmt.Println()
	}

	// Datalog-only (novel detection headroom)
	if len(datalogOnly) > 0 {
		fmt.Println("Datalog-only principals (novel detection headroom — first 10):")
		shown := 0
		for _, p := range datalogOnly {
			if shown >= 10 {
				break
			}
			fmt.Printf("  %s\n", p)
			shown++
		}
		fmt.Println()
	}

	// Exit code: zero if no CEL-only/Access-graph-applicable findings.
	if counts["CEL-only / Access-graph applicable"] > 0 {
		fmt.Println("FAIL: CEL-only / Access-graph applicable findings present — Datalog schema/rules gap.")
		os.Exit(1)
	}
	fmt.Println("PASS: zero CEL-only / Access-graph-applicable findings.")
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "validate: "+format+"\n", args...)
	os.Exit(1)
}
