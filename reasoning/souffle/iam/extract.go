//go:build ignore

// Command extract — G0 access-graph fact extractor for Phase 7.
//
// Reads a Stave snapshot (or a pre-computed JSONL fact stream) and
// writes per-predicate `.facts` TSV files Soufflé can consume via the
// .input directives in `schema.dl`.
//
// This is the Go port of `examples/engines/souffle/convert.sh`'s
// predicate-split logic, plus the optional first hop that invokes
// `stave export-sir --format jsonl` against a snapshot directory.
//
// Usage:
//
//	# Mode A: extract from a Stave snapshot directory.
//	go run ./reasoning/souffle/iam/extract.go \
//	    -snapshot ./observations \
//	    -out      ./facts
//
//	# Mode B: split a pre-existing JSONL fact stream (trial fixture).
//	go run ./reasoning/souffle/iam/extract.go \
//	    -jsonl reasoning-specs/trials/souffle-anonymous-reachability/input.jsonl \
//	    -out   /tmp/facts
//
// Run from the repo root so the `stave` binary resolves correctly
// in -snapshot mode and the relative paths to controls/ + observations/
// behave the same way the regular CLI does.
//
// Build-ignored (//go:build ignore) so the extractor doesn't ship in
// the production binary — same convention as
// internal/tools/scope-classifier/main.go.
package main

import (
	"bufio"
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

// declaredInputs is the union of input relations the .dl programs in
// reasoning/souffle/iam/ and examples/engines/souffle/ declare. The
// extractor pre-creates an empty .facts file for each — Soufflé treats
// missing input files as a warning, and empty files evaluate as the
// empty relation, which is the correct semantic for "the snapshot
// didn't carry this predicate."
//
// Sourced from schema.dl (G0) + the bundled examples; when schema.dl
// gains a new .input directive, append the predicate here.
var declaredInputs = []string{
	// Core asset-identification predicates.
	"has_type", "has_vendor", "has_severity",
	// IAM principal-effective permissions.
	"has_action", "has_resource",
	"has_deny_action", "has_deny_resource",
	"has_permission_action", "has_permission_resource",
	"has_condition", "has_condition_value",
	// Tags + asset-level annotations.
	"has_tag",
	// Role-assumption + trust graph.
	"can_assume",
	"cross_account_assumes",
	"trusts_service",
	"has_delegated_principal",
	"has_unknown_delegated_principal",
	"has_delegation_scope_exceeded_for",
	// Resource-policy edges.
	"resource_policy_principal",
	"resource_policy_action",
	// Cognito identity-pool mappings.
	"maps_unauth_to",
	"maps_auth_to",
	"allows_unauthenticated",
	"self_registration_unrestricted",
	// Lifecycle + provenance.
	"contributed_by",
	"is_decommissioned",
	"is_provisioned",
	"first_seen_at",
	"last_seen_at",
	// Exposure window + classification.
	"has_exposure_window",
	"has_forbidden_state",
	"has_forbidden_category",
	"has_incompatible_pair",
	"has_intent_rationale",
	"has_privilege_level",
	"has_unused_service",
	"has_data_event_logging",
	"has_mfa_enforced",
	"has_advanced_security_enabled",
	// G3 — emitted by emitAuthFacts/emitSensitivityFacts below,
	// not from the JSONL stream. Listed here so preCreateEmpty
	// is idempotent (it's a no-op for these because the G3 phase
	// already wrote them).
	"authorized",
	"sensitivity",
}

// G3 default config — mirrors stave-authorization.yaml at the
// repo root. The extractor uses these defaults unless -config
// points at a file the operator has tuned. YAML parsing is a
// future enhancement; for now the defaults are hardcoded and
// the -config flag exists as a forward-compatible placeholder.
var defaultOwnershipTagKeys = []string{"Owner", "Team"}
var defaultClassificationTagKey = "DataClassification"
var defaultHighSensitivityValues = []string{"PII", "PHI", "PCI"}

// IAM principal asset types — mirror schema.dl's is_principal_type.
// Used by the G3 emitter to discriminate principals from resources
// when generating authorized facts (tag-equality joins).
var iamPrincipalTypes = map[string]struct{}{
	"aws_iam_user":           {},
	"aws_iam_role":           {},
	"aws_iam_federated_role": {},
	"aws_iam_saml_provider":  {},
	"aws_iam_sso_config":     {},
}

// factLine matches the JSONL shape sirfacts emits. Only the three
// fields the .facts files need are mandatory; everything else is
// ignored for the split.
type factLine struct {
	Predicate string `json:"predicate"`
	Subject   string `json:"subject"`
	Object    string `json:"object"`
}

type options struct {
	jsonl       string
	snapshot    string
	controls    string
	staveBinary string
	out         string
	config      string
}

func parseFlags() *options {
	opts := &options{}
	flag.StringVar(&opts.jsonl, "jsonl", "",
		"Path to a pre-existing JSONL fact stream. Mutually exclusive with -snapshot.")
	flag.StringVar(&opts.snapshot, "snapshot", "",
		"Path to a Stave snapshot directory. Invokes `stave export-sir --format jsonl`.")
	flag.StringVar(&opts.controls, "controls", "controls",
		"Path to the control catalog directory (only used with -snapshot).")
	flag.StringVar(&opts.staveBinary, "stave", "stave",
		"Path to the stave binary (only used with -snapshot).")
	flag.StringVar(&opts.out, "out", "./facts",
		"Output directory for the per-predicate .facts files.")
	flag.StringVar(&opts.config, "config", "",
		"Path to stave-authorization.yaml. Placeholder for first iteration — defaults are hardcoded; this flag exists for forward compatibility.")
	flag.Parse()

	if opts.jsonl == "" && opts.snapshot == "" {
		fmt.Fprintln(os.Stderr, "extract: must supply either -jsonl <file> or -snapshot <dir>")
		os.Exit(2)
	}
	if opts.jsonl != "" && opts.snapshot != "" {
		fmt.Fprintln(os.Stderr, "extract: -jsonl and -snapshot are mutually exclusive")
		os.Exit(2)
	}
	return opts
}

func main() {
	opts := parseFlags()

	if err := os.MkdirAll(opts.out, 0o755); err != nil {
		fail("mkdir output dir: %v", err)
	}

	var stream io.Reader
	switch {
	case opts.jsonl != "":
		f, err := os.Open(opts.jsonl)
		if err != nil {
			fail("open jsonl: %v", err)
		}
		defer f.Close()
		stream = f

	case opts.snapshot != "":
		buf, err := runExportSIR(opts)
		if err != nil {
			fail("invoke stave export-sir: %v", err)
		}
		stream = bytes.NewReader(buf)
	}

	stats, err := split(stream, opts.out)
	if err != nil {
		fail("split JSONL: %v", err)
	}

	// G3 — derive authorized + sensitivity facts from the
	// per-asset tag data + asset type discrimination. Reads
	// has_tag.facts + has_type.facts (already written by split)
	// and writes authorized.facts + sensitivity.facts.
	g3stats, err := emitG3Facts(opts.out)
	if err != nil {
		fail("emit G3 facts: %v", err)
	}
	stats["authorized"] = g3stats["authorized"]
	stats["sensitivity"] = g3stats["sensitivity"]

	if err := preCreateEmpty(opts.out); err != nil {
		fail("pre-create empty facts: %v", err)
	}

	report(stats, opts.out)
}

// emitG3Facts reads has_tag.facts + has_type.facts (both produced
// by the JSONL split above) and emits authorized.facts +
// sensitivity.facts per the G3 product-decision model documented
// in docs/authorization-model.md.
//
// Authorization (default config: ownership_tag_keys = [Owner, Team]):
//
//	For each (resource, principal) pair where both carry the same
//	value under any ownership tag key, emit authorized(P, R).
//	Resources with no ownership tag are fail-open: emit
//	authorized(P, R) for EVERY principal (so untagged resources
//	don't generate false-positive unauthorized_access).
//
// Sensitivity (default config: DataClassification ∈ {PII, PHI, PCI}):
//
//	For each resource with a high-value tag, emit sensitivity(R, "high").
//	Resources without the tag emit sensitivity(R, "standard").
//
// Returns per-relation counts for the report.
func emitG3Facts(outDir string) (map[string]int, error) {
	hasTags, err := readFactPairs(filepath.Join(outDir, "has_tag.facts"))
	if err != nil {
		return nil, fmt.Errorf("read has_tag.facts: %w", err)
	}
	hasTypes, err := readFactPairs(filepath.Join(outDir, "has_type.facts"))
	if err != nil {
		return nil, fmt.Errorf("read has_type.facts: %w", err)
	}

	// Partition assets into principals + resources via has_type.
	principals := map[string]struct{}{}
	resources := map[string]struct{}{}
	for _, t := range hasTypes {
		if _, ok := iamPrincipalTypes[t.Object]; ok {
			principals[t.Subject] = struct{}{}
		} else if strings.HasPrefix(t.Object, "aws_") {
			resources[t.Subject] = struct{}{}
		}
	}

	// Index tags by asset → (tag_key → tag_value). Each tag fact
	// is "key=value"; split on the first '='.
	tagsByAsset := map[string]map[string]string{}
	for _, t := range hasTags {
		idx := strings.Index(t.Object, "=")
		if idx < 0 {
			continue
		}
		key := t.Object[:idx]
		val := t.Object[idx+1:]
		if tagsByAsset[t.Subject] == nil {
			tagsByAsset[t.Subject] = map[string]string{}
		}
		tagsByAsset[t.Subject][key] = val
	}

	// Build authorized.facts.
	authPath := filepath.Join(outDir, "authorized.facts")
	authFile, err := os.Create(authPath)
	if err != nil {
		return nil, fmt.Errorf("create %s: %w", authPath, err)
	}
	defer authFile.Close()

	authCount := 0
	// Stable iteration order for determinism.
	resList := sortedKeys(resources)
	prinList := sortedKeys(principals)

	for _, r := range resList {
		ownerValues := ownershipValues(tagsByAsset[r])
		if len(ownerValues) == 0 {
			// Fail-open: authorize every principal.
			for _, p := range prinList {
				fmt.Fprintf(authFile, "%s\t%s\n", p, r)
				authCount++
			}
			continue
		}
		// Tagged resource: authorize principals whose ownership tags
		// match ANY of the resource's ownership values.
		for _, p := range prinList {
			if hasMatchingOwnership(tagsByAsset[p], ownerValues) {
				fmt.Fprintf(authFile, "%s\t%s\n", p, r)
				authCount++
			}
		}
	}

	// Build sensitivity.facts.
	sensPath := filepath.Join(outDir, "sensitivity.facts")
	sensFile, err := os.Create(sensPath)
	if err != nil {
		return nil, fmt.Errorf("create %s: %w", sensPath, err)
	}
	defer sensFile.Close()

	highValues := map[string]struct{}{}
	for _, v := range defaultHighSensitivityValues {
		highValues[v] = struct{}{}
	}
	sensCount := 0
	for _, r := range resList {
		level := "standard"
		if v, ok := tagsByAsset[r][defaultClassificationTagKey]; ok {
			if _, okHigh := highValues[v]; okHigh {
				level = "high"
			}
		}
		fmt.Fprintf(sensFile, "%s\t%s\n", r, level)
		sensCount++
	}

	return map[string]int{
		"authorized":  authCount,
		"sensitivity": sensCount,
	}, nil
}

// ownershipValues returns the resource's set of ownership-tag values
// (the union across all configured ownership tag keys).
func ownershipValues(tags map[string]string) []string {
	if tags == nil {
		return nil
	}
	var out []string
	seen := map[string]struct{}{}
	for _, key := range defaultOwnershipTagKeys {
		if v, ok := tags[key]; ok {
			if _, okSeen := seen[v]; !okSeen {
				out = append(out, v)
				seen[v] = struct{}{}
			}
		}
	}
	return out
}

// hasMatchingOwnership returns true if any of the principal's
// ownership tag values intersects the resource's ownership values.
func hasMatchingOwnership(principalTags map[string]string, resourceValues []string) bool {
	if principalTags == nil {
		return false
	}
	resourceSet := map[string]struct{}{}
	for _, v := range resourceValues {
		resourceSet[v] = struct{}{}
	}
	for _, key := range defaultOwnershipTagKeys {
		if v, ok := principalTags[key]; ok {
			if _, okSet := resourceSet[v]; okSet {
				return true
			}
		}
	}
	return false
}

// readFactPairs parses a TSV .facts file into (subject, object)
// records. Empty / blank lines are skipped. Lines with fewer than
// two tab-separated fields are skipped (no malformed-line failure).
type factPair struct {
	Subject string
	Object  string
}

func readFactPairs(path string) ([]factPair, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		// Missing file is treated as empty — extract.go pre-
		// creates empty .facts for relations the JSONL didn't
		// emit, but G3 may be called before preCreateEmpty.
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []factPair
	for line := range strings.SplitSeq(string(data), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 2 {
			continue
		}
		out = append(out, factPair{Subject: fields[0], Object: fields[1]})
	}
	return out, nil
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// runExportSIR invokes `stave export-sir --format jsonl --controls ... --observations ...`
// and returns the captured stdout. Errors include stderr for triage.
func runExportSIR(opts *options) ([]byte, error) {
	args := []string{
		"export-sir",
		"--format", "jsonl",
		"--controls", opts.controls,
		"--observations", opts.snapshot,
	}
	cmd := exec.Command(opts.staveBinary, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s %v: %w\nstderr: %s",
			opts.staveBinary, args, err, stderr.String())
	}
	return stdout.Bytes(), nil
}

// split reads the JSONL stream and writes one .facts file per
// distinct predicate. Each .facts row is TSV: subject \t object.
// Returns per-predicate row counts for the report.
func split(r io.Reader, outDir string) (map[string]int, error) {
	// Buffer per predicate; flush at end so each .facts file gets
	// one Open+Write cycle rather than one per line.
	buffers := map[string]*bytes.Buffer{}
	counts := map[string]int{}

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var f factLine
		if err := json.Unmarshal(line, &f); err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNo, err)
		}
		if f.Predicate == "" {
			continue
		}
		buf, ok := buffers[f.Predicate]
		if !ok {
			buf = &bytes.Buffer{}
			buffers[f.Predicate] = buf
		}
		// TSV: subject\tobject\n. Sirfacts sanitizes embedded
		// whitespace at emit-time, but TSV is fragile to literal
		// tabs in symbols — replace defensively.
		subj := strings.ReplaceAll(f.Subject, "\t", " ")
		obj := strings.ReplaceAll(f.Object, "\t", " ")
		fmt.Fprintf(buf, "%s\t%s\n", subj, obj)
		counts[f.Predicate]++
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan: %w", err)
	}

	// Determinism: write predicates in sorted order so the report
	// output is stable across runs.
	names := make([]string, 0, len(buffers))
	for p := range buffers {
		names = append(names, p)
	}
	slices.Sort(names)

	for _, pred := range names {
		path := filepath.Join(outDir, pred+".facts")
		if err := os.WriteFile(path, buffers[pred].Bytes(), 0o644); err != nil {
			return nil, fmt.Errorf("write %s: %w", path, err)
		}
	}
	return counts, nil
}

// preCreateEmpty touches one empty .facts file per declared input
// relation that the JSONL stream didn't emit. Matches convert.sh
// behavior — Soufflé warns on missing input files but evaluates
// empty files as the empty relation.
func preCreateEmpty(outDir string) error {
	for _, pred := range declaredInputs {
		path := filepath.Join(outDir, pred+".facts")
		if _, err := os.Stat(path); err == nil {
			continue
		}
		f, err := os.Create(path)
		if err != nil {
			return fmt.Errorf("touch %s: %w", path, err)
		}
		f.Close()
	}
	return nil
}

func report(counts map[string]int, outDir string) {
	total := 0
	for _, n := range counts {
		total += n
	}

	// Sorted iteration for stable output.
	preds := make([]string, 0, len(counts))
	for p := range counts {
		preds = append(preds, p)
	}
	slices.Sort(preds)

	fmt.Printf("Wrote %d .facts files to %s\n", len(counts), outDir)
	fmt.Printf("Total emitted facts: %d\n", total)
	if len(preds) > 0 {
		fmt.Println("Per-predicate counts (emitted only; empties pre-created from declaredInputs):")
		for _, p := range preds {
			fmt.Printf("  %-40s %d\n", p, counts[p])
		}
	}

	// Surface any predicates the JSONL emitted that aren't in the
	// declared-inputs list. This is the drift gate: a new sirfacts
	// predicate appearing in JSONL but not in schema.dl/declaredInputs
	// indicates the schema is stale.
	known := map[string]struct{}{}
	for _, p := range declaredInputs {
		known[p] = struct{}{}
	}
	var undeclared []string
	for _, p := range preds {
		if _, ok := known[p]; !ok {
			undeclared = append(undeclared, p)
		}
	}
	if len(undeclared) > 0 {
		fmt.Println()
		fmt.Println("WARN: predicates emitted by sirfacts but NOT declared in schema.dl/declaredInputs:")
		for _, p := range undeclared {
			fmt.Printf("  %s\n", p)
		}
		fmt.Println("Add these to declaredInputs + schema.dl if downstream programs need them.")
	}
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "extract: "+format+"\n", args...)
	os.Exit(1)
}
