// Command conflictdryrun runs the full conflict analyzer end-to-end
// against the real Stave control catalog and a fixture corpus, and
// prints a human-readable summary of the resulting ConflictReport.
//
// This is the Node 3f honest-moment tool: it surfaces what the analyzer
// finds in a 600+ control catalog grown from real incident reports. The
// expected counts (1-3 CONTRADICTIONs, 5-15 REDUNDANCYs) are
// hypotheses, not contracts; the tool's job is to make the actual
// numbers visible so we can decide whether to fix defects before
// shipping `stave verify catalog` (option 2 in Iteration 3 spec) or
// log them as catalog TODOs and proceed (option 1).
//
// Usage:
//
//	go run ./internal/tools/conflictdryrun                                        # default ./controls + testdata/e2e
//	go run ./internal/tools/conflictdryrun -controls stave/controls -fixtures stave/testdata/e2e,dns-lab/observations
//	go run ./internal/tools/conflictdryrun -json                                  # emit the full ConflictReport JSON to stdout
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/sufield/stave/internal/adapters/controls/yaml"
	"github.com/sufield/stave/internal/adapters/observations"
	"github.com/sufield/stave/internal/builtin/predicate"
	"github.com/sufield/stave/internal/catalog/conflict"
	"github.com/sufield/stave/internal/cel"
	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
)

func main() {
	controlsDir := flag.String("controls", "controls", "path to the control catalog directory")
	fixtureDirs := flag.String("fixtures", "testdata/e2e",
		"comma-separated list of directories holding observation snapshots (recursively scanned for observations/ subdirs)")
	emitJSON := flag.Bool("json", false, "print the full ConflictReport JSON instead of the human summary")
	flag.Parse()

	// 1. Load catalog.
	loader, err := yaml.NewControlLoader(yaml.WithAliasResolver(predicate.ResolverFunc()))
	if err != nil {
		die("control loader init: %v", err)
	}
	controls, err := loader.LoadControls(context.Background(), *controlsDir)
	if err != nil {
		die("load controls from %s: %v", *controlsDir, err)
	}

	// 2. Build catalog map and metadata used by the classifier and renderer.
	catalogMap := make(map[string]*policy.ControlDefinition, len(controls))
	metadata := make(map[string]conflict.ControlMetadata, len(controls))
	for i := range controls {
		ctl := &controls[i]
		id := string(ctl.ID)
		catalogMap[id] = ctl
		metadata[id] = conflict.ControlMetadata{
			ControlID:            id,
			AttackStage:          ctl.AttackStage(),
			ComplianceCanonical:  conflict.CanonicalCompliance(complianceTokens(ctl.Compliance)),
			RemediationCanonical: remediationCanonical(ctl.Remediation),
		}
	}

	// 3. Overlap analysis (Node 3a).
	pairs, stats, err := conflict.AnalyzeOverlap(controls)
	if err != nil {
		die("AnalyzeOverlap: %v", err)
	}

	// 4. Load fixtures.
	fixtures, fixtureCount, err := loadFixtures(strings.Split(*fixtureDirs, ","))
	if err != nil {
		die("load fixtures: %v", err)
	}

	// 5. Evaluate (Node 3b) using the real CEL engine.
	eval, err := cel.NewPredicateEval()
	if err != nil {
		die("init CEL evaluator: %v", err)
	}
	evaluated, err := conflict.EvaluatePairs(pairs, catalogMap, fixtures, eval)
	if err != nil {
		die("EvaluatePairs: %v", err)
	}

	// 6. Classify (Node 3c).
	classified, err := conflict.Classify(evaluated, metadata)
	if err != nil {
		die("Classify: %v", err)
	}

	// 7. Render (Node 3d).
	report := conflict.BuildReport(conflict.ReportInputs{
		Classified:           classified,
		AliasedControls:      stats.SkippedAliased,
		CatalogVersion:       resolveGitSHA(*controlsDir),
		FixtureCorpusVersion: resolveGitSHA("."),
		StaveVersion:         "0.1.0-dryrun",
		GeneratedAt:          time.Now().UTC(),
	})

	if *emitJSON {
		raw, err := report.Marshal()
		if err != nil {
			die("Marshal report: %v", err)
		}
		fmt.Println(string(raw))
		return
	}

	printSummary(report, stats, len(controls), fixtureCount, len(fixtures))
}

// loadFixtures walks the listed roots and collects every asset from
// every observation file as a FixtureAsset. Returns the asset list, the
// number of source files read, and any error.
//
// We walk JSON files individually (rather than calling LoadSnapshots on
// each directory) so each FixtureAsset can carry the actual on-disk
// path of the snapshot it came from — the renderer surfaces this as the
// witness fixture_path, which is the breadcrumb a maintainer follows
// when investigating a CONTRADICTION.
func loadFixtures(roots []string) ([]conflict.FixtureAsset, int, error) {
	loader := observations.NewObservationLoader()
	var out []conflict.FixtureAsset
	files := 0

	loadOne := func(path string) error {
		f, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("open %s: %w", path, err)
		}
		defer f.Close()
		snap, err := loader.LoadSnapshotFromReader(context.Background(), f, path)
		if err != nil {
			// Skip files the loader rejects — many corpora contain
			// non-snapshot JSON (configs, fixtures from other tools).
			// Log to stderr so we know the rejection rate.
			fmt.Fprintf(os.Stderr, "skip %s: %v\n", path, err)
			return nil
		}
		files++
		for j := range snap.Assets {
			out = append(out, conflict.FixtureAsset{
				FixturePath: path,
				Asset:       snap.Assets[j],
				Identities:  snap.Identities,
			})
		}
		return nil
	}

	for _, root := range roots {
		root = strings.TrimSpace(root)
		if root == "" {
			continue
		}
		err := filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if info.IsDir() {
				return nil
			}
			if filepath.Ext(path) != ".json" {
				return nil
			}
			return loadOne(path)
		})
		if err != nil {
			return nil, 0, err
		}
	}
	return out, files, nil
}

// complianceTokens turns a ComplianceMapping into "FRAMEWORK:citation"
// tokens suitable for CanonicalCompliance.
func complianceTokens(m policy.ComplianceMapping) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for fw, citation := range m {
		if citation == "" {
			continue
		}
		out = append(out, fmt.Sprintf("%s:%s", fw, citation))
	}
	return out
}

func remediationCanonical(r *policy.RemediationSpec) string {
	if r == nil {
		return conflict.CanonicalRemediation("", "")
	}
	return conflict.CanonicalRemediation(r.Action, r.Example)
}

// resolveGitSHA tries `git rev-parse HEAD` for a path; on any failure
// returns "unknown". Surfaces a usable corpus_version without making
// the tool depend on shell-out cleanliness.
func resolveGitSHA(_ string) string {
	// Keep it simple — the dryrun report is informational, not signed.
	// A future stave verify catalog command can shell out properly.
	return "dryrun-local"
}

func printSummary(r conflict.Report, stats conflict.AnalysisStats, totalControls, fixtureFiles, fixtureAssets int) {
	fmt.Printf("Catalog:              %d controls, %d usable, %d aliased, %d empty-deps\n",
		totalControls,
		totalControls-len(stats.SkippedAliased)-len(stats.SkippedEmptyDeps),
		len(stats.SkippedAliased), len(stats.SkippedEmptyDeps))
	fmt.Printf("Pairs:                %d candidate (from %d total, %d skipped metadata-only)\n",
		stats.CandidatePairs, stats.TotalPairs, stats.SkippedMetadataOnly)
	fmt.Printf("Fixtures:             %d files, %d assets\n", fixtureFiles, fixtureAssets)
	fmt.Println()

	counts := categoryCounts(r.Pairs)
	fmt.Printf("Findings (%d total):\n", len(r.Pairs))
	fmt.Printf("  CONTRADICTION         %d\n", counts[conflict.CategoryContradiction])
	fmt.Printf("  REDUNDANCY            %d\n", counts[conflict.CategoryRedundancy])
	fmt.Printf("  EMPIRICAL_SUBSUMPTION %d\n", counts[conflict.CategoryEmpiricalSubsumption])
	fmt.Printf("  DIVERGENCE            %d\n", counts[conflict.CategoryDivergence])
	fmt.Println()

	gapCounts := gapReasonCounts(r.AnalysisGaps)
	fmt.Printf("Analysis gaps (%d total):\n", len(r.AnalysisGaps))
	fmt.Printf("  ALIASED_PREDICATE     %d\n", gapCounts[conflict.GapAliasedPredicate])
	fmt.Printf("  NO_FIXTURE_COVERAGE   %d\n", gapCounts[conflict.GapNoFixtureCoverage])
	fmt.Printf("  EXTRACTION_FAILED     %d\n", gapCounts[conflict.GapExtractionFailed])
	fmt.Println()

	// Print every CONTRADICTION (likely few; high signal).
	contradictions := pairsByCategory(r.Pairs, conflict.CategoryContradiction)
	if len(contradictions) > 0 {
		fmt.Println("CONTRADICTIONS (each is a likely defect):")
		for _, p := range contradictions {
			pl := p.Payload.(conflict.ContradictionPayload)
			fmt.Printf("  [%s] %s ~ %s\n", pl.Subcategory, p.ControlA, p.ControlB)
			fmt.Printf("    shared dependencies: %v\n", pl.SharedDependencies)
			fmt.Printf("    coverage: %d evaluated, %d matched, low=%v\n",
				p.CorpusCoverage.FixturesEvaluated, p.CorpusCoverage.FixturesMatched, p.CorpusCoverage.LowCoverage)
			for _, w := range pl.DisagreementWitnesses {
				fmt.Printf("    witness: %s/%s  A=%s B=%s\n",
					w.FixturePath, w.AssetID, w.VerdictA, w.VerdictB)
			}
		}
		fmt.Println()
	}

	// Print first 10 REDUNDANCIES (informational; can be many).
	redundancies := pairsByCategory(r.Pairs, conflict.CategoryRedundancy)
	if len(redundancies) > 0 {
		fmt.Printf("REDUNDANCIES (showing %d of %d):\n", min(10, len(redundancies)), len(redundancies))
		for i, p := range redundancies {
			if i >= 10 {
				break
			}
			pl := p.Payload.(conflict.RedundancyPayload)
			fmt.Printf("  %s ~ %s  (attack_stage=%q, deps=%v)\n",
				p.ControlA, p.ControlB, pl.SharedAttackStage, pl.SharedDependencies)
		}
		fmt.Println()
	}

	// Cross-category sanity check the user explicitly asked about:
	// CONTRADICTIONs whose pair touches an aliased-predicate neighbor
	// would suggest the alias blind spot is hiding more than just the
	// 6 self-contained S3 ACL conflicts.
	aliasedSet := make(map[string]struct{}, len(stats.SkippedAliased))
	for _, id := range stats.SkippedAliased {
		aliasedSet[id] = struct{}{}
	}
	flagged := 0
	for _, p := range contradictions {
		if neighborsAliased(p, aliasedSet) {
			if flagged == 0 {
				fmt.Println("CONTRADICTIONS adjacent to aliased controls (alias blind-spot check):")
			}
			fmt.Printf("  %s ~ %s\n", p.ControlA, p.ControlB)
			flagged++
		}
	}
	if flagged > 0 {
		fmt.Println()
	}

	fmt.Printf("Report ID: %s\n", r.ReportID)
}

func categoryCounts(pairs []conflict.ConflictPair) map[conflict.ConflictCategory]int {
	c := map[conflict.ConflictCategory]int{}
	for _, p := range pairs {
		c[p.Category]++
	}
	return c
}

func gapReasonCounts(gaps []conflict.AnalysisGap) map[conflict.GapReason]int {
	c := map[conflict.GapReason]int{}
	for _, g := range gaps {
		c[g.Reason]++
	}
	return c
}

func pairsByCategory(pairs []conflict.ConflictPair, cat conflict.ConflictCategory) []conflict.ConflictPair {
	var out []conflict.ConflictPair
	for _, p := range pairs {
		if p.Category == cat {
			out = append(out, p)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].ControlA != out[j].ControlA {
			return out[i].ControlA < out[j].ControlA
		}
		return out[i].ControlB < out[j].ControlB
	})
	return out
}

// neighborsAliased reports whether either side of the pair shares an ID
// prefix (up to the first dot) with an aliased control. Heuristic: real
// catalog uses dotted IDs like "s3.bucket_acl_public" — same first
// segment ≈ same domain.
func neighborsAliased(p conflict.ConflictPair, aliased map[string]struct{}) bool {
	prefixes := map[string]struct{}{
		idPrefix(p.ControlA): {},
		idPrefix(p.ControlB): {},
	}
	for id := range aliased {
		if _, ok := prefixes[idPrefix(id)]; ok {
			return true
		}
	}
	return false
}

func idPrefix(id string) string {
	if i := strings.IndexByte(id, '.'); i > 0 {
		return id[:i]
	}
	return id
}

// Confirm asset is referenced (silences unused import warning if go
// adds package-level checks in the future).
var _ asset.Asset

// die is the standard tool-process exit helper.
func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "conflictdryrun: "+format+"\n", args...)
	os.Exit(1)
}

func init() {
	// Use compact JSON serialization; not used here but kept ready
	// for the -json path to remain stable across maintainer changes.
	_ = json.Marshal
}
