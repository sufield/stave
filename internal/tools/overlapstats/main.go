// Command overlapstats runs the conflict-detector's overlap analysis
// pass against the real control catalog and prints summary statistics.
// This is a diagnostic tool — it does not evaluate fixtures, does not
// classify into conflict categories, and produces no ConflictReport.
// Its sole purpose is to surface catalog coherence before deeper
// conflict detection runs: a high candidate-pair ratio signals that
// the catalog's dependency paths are too coarse and downstream
// conflict detection will be noisy.
//
// Usage:
//
//	go run ./internal/tools/overlapstats                   # uses default ./controls
//	go run ./internal/tools/overlapstats -dir stave/controls
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"sort"

	"github.com/sufield/stave/internal/adapters/controls/yaml"
	"github.com/sufield/stave/internal/builtin/predicate"
	"github.com/sufield/stave/internal/catalog/conflict"
)

func main() {
	dir := flag.String("dir", "controls", "path to the control catalog directory")
	verbose := flag.Bool("v", false, "list candidate pairs (noisy on large catalogs)")
	flag.Parse()

	loader, err := yaml.NewControlLoader(yaml.WithAliasResolver(predicate.ResolverFunc()))
	if err != nil {
		die("control loader init: %v", err)
	}
	controls, err := loader.LoadControls(context.Background(), *dir)
	if err != nil {
		die("load controls from %s: %v", *dir, err)
	}

	pairs, stats, err := conflict.AnalyzeOverlap(controls)
	if err != nil {
		die("analyze overlap: %v", err)
	}

	fmt.Printf("Catalog path:         %s\n", *dir)
	fmt.Printf("Total controls:       %d\n", stats.TotalControls)
	fmt.Printf("Usable controls:      %d (aliased skipped: %d, empty-deps skipped: %d)\n",
		stats.TotalControls-len(stats.SkippedAliased)-len(stats.SkippedEmptyDeps),
		len(stats.SkippedAliased), len(stats.SkippedEmptyDeps))
	fmt.Printf("Total pairs:          %d (N*(N-1)/2 over usable)\n", stats.TotalPairs)
	fmt.Printf("Candidate pairs:      %d\n", stats.CandidatePairs)
	fmt.Printf("Candidate ratio:      %.4f (%.2f%%)\n",
		stats.CandidateRatio(), stats.CandidateRatio()*100)

	fmt.Println()
	fmt.Println("By dependency relation:")
	fmt.Printf("  IDENTICAL:    %d\n", stats.ByRelation[conflict.RelationIdentical])
	fmt.Printf("  SUBSET:       %d\n", stats.ByRelation[conflict.RelationSubset])
	fmt.Printf("  OVERLAPPING:  %d\n", stats.ByRelation[conflict.RelationOverlapping])

	if stats.CandidateRatio() > 0.10 {
		fmt.Println()
		fmt.Println("WARNING: candidate ratio exceeds 10%.")
		fmt.Println("Catalog dependency paths may be too coarse-grained.")
		fmt.Println("Downstream conflict detection will be noisy unless predicates")
		fmt.Println("are revised to read more specific paths.")
	}

	if len(stats.SkippedAliased) > 0 {
		fmt.Println()
		fmt.Println("Analysis gap: ALIASED_PREDICATE")
		fmt.Println("These controls are excluded from pair enumeration because the")
		fmt.Println("dependency extractor does not yet expand predicate aliases.")
		fmt.Println("Downstream ConflictReport must surface them in analysis_gaps[].")
		for _, id := range stats.SkippedAliased {
			fmt.Printf("  - %s\n", id)
		}
	}

	if *verbose {
		fmt.Println()
		fmt.Printf("Candidate pairs (%d):\n", len(pairs))
		sort.SliceStable(pairs, func(i, j int) bool {
			if pairs[i].Relation != pairs[j].Relation {
				return pairs[i].Relation < pairs[j].Relation
			}
			if pairs[i].ControlA != pairs[j].ControlA {
				return pairs[i].ControlA < pairs[j].ControlA
			}
			return pairs[i].ControlB < pairs[j].ControlB
		})
		for _, p := range pairs {
			fmt.Printf("  [%-11s] %s ~ %s  (overlap: %d path(s))\n",
				p.Relation, p.ControlA, p.ControlB, len(p.Overlap))
		}
	}
}

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "overlapstats: "+format+"\n", args...)
	os.Exit(1)
}
