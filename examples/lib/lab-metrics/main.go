// Command lab-metrics loads a CloudGoat lab's findings and displays
// detection metrics using only pkg/stave — no CLI, no JSON parsing.
//
// Usage:
//
//	go run ./examples/lib/lab-metrics ./ctf/cloudgoat/lambda_privesc/findings.json
//	go run ./examples/lib/lab-metrics --prev ./prev.json ./current.json
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/sufield/stave/pkg/stave"
)

func main() {
	prevPath := flag.String("prev", "", "previous assessment for diff (optional)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [--prev <prev.json>] <findings.json>\n", os.Args[0])
	}
	flag.Parse()

	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}

	ctx := context.Background()
	assessment, err := stave.LoadAssessment(ctx, flag.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "load: %v\n", err)
		os.Exit(1)
	}

	printHeader(assessment)
	printFindings(assessment)
	printChains(assessment)
	printSeverityBreakdown(assessment)
	printAttackSurface(assessment)

	score, err := stave.Score(ctx, stave.ScoreConfig{Assessment: assessment})
	if err == nil {
		printScore(score)
	}

	if *prevPath != "" {
		prev, err := stave.LoadAssessment(ctx, *prevPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "load prev: %v\n", err)
			os.Exit(1)
		}
		printDiff(prev, assessment)
	}
}

func printHeader(a *stave.Assessment) {
	fmt.Println("╔══════════════════════════════════════════════╗")
	fmt.Println("║           Lab Detection Metrics              ║")
	fmt.Println("╠══════════════════════════════════════════════╣")
	fmt.Printf("║  Status:      %-30s ║\n", a.Status)
	fmt.Printf("║  Findings:    %-30d ║\n", len(a.Findings))
	fmt.Printf("║  Issues:      %-30d ║\n", len(a.Issues))
	fmt.Printf("║  Chains:      %-30d ║\n", len(a.ChainFindings))
	fmt.Println("╚══════════════════════════════════════════════╝")
	fmt.Println()
}

func printFindings(a *stave.Assessment) {
	if len(a.Findings) == 0 {
		return
	}
	fmt.Println("Findings")
	fmt.Println(strings.Repeat("─", 70))
	for i, f := range a.Findings {
		mitre := f.CorpusReference
		if mitre == "" {
			mitre = "—"
		}
		asset := truncate(string(f.AssetID), 30)
		fmt.Printf("  %2d. [%-8s] %-35s %s\n", i+1, f.Severity, f.ControlID, asset)
		if mitre != "—" {
			fmt.Printf("      MITRE: %s\n", mitre)
		}
	}
	fmt.Println()
}

func printChains(a *stave.Assessment) {
	if len(a.ChainFindings) == 0 {
		return
	}
	fmt.Println("Compound Chains")
	fmt.Println(strings.Repeat("─", 70))
	for _, c := range a.ChainFindings {
		fmt.Printf("  [%-8s] %s\n", c.Severity, c.ChainID)
		fmt.Printf("    controls failing:    %v\n", c.ControlsFailing)
		if len(c.MissingSafeguards) > 0 {
			fmt.Printf("    missing safeguards:  %v\n", c.MissingSafeguards)
		}
		if len(c.AttackStages) > 0 {
			fmt.Printf("    attack stages:       %v\n", c.AttackStages)
		}
	}
	fmt.Println()
}

func printSeverityBreakdown(a *stave.Assessment) {
	counts := map[stave.Severity]int{}
	for _, f := range a.Findings {
		counts[f.Severity]++
	}
	fmt.Println("Severity Breakdown")
	fmt.Println(strings.Repeat("─", 40))
	for _, sev := range []stave.Severity{"critical", "high", "medium", "low"} {
		if c := counts[sev]; c > 0 {
			bar := strings.Repeat("█", c)
			fmt.Printf("  %-10s %3d %s\n", sev, c, bar)
		}
	}
	fmt.Println()
}

func printAttackSurface(a *stave.Assessment) {
	assets := map[stave.AssetID]bool{}
	for _, f := range a.Findings {
		assets[f.AssetID] = true
	}
	fmt.Println("Attack Surface")
	fmt.Println(strings.Repeat("─", 40))
	fmt.Printf("  Assets with findings: %d\n", len(assets))
	for id := range assets {
		fmt.Printf("    %s\n", truncate(string(id), 50))
	}
	fmt.Println()
}

func printScore(s *stave.ScoreResult) {
	fmt.Println("Posture Score")
	fmt.Println(strings.Repeat("─", 40))
	fmt.Printf("  Score: %.0f / 100\n", s.Score)
	fmt.Printf("  Band:  %s\n", s.RubricBand)
	fmt.Println()
}

func printDiff(prev, curr *stave.Assessment) {
	diff := stave.DiffAssessments(prev, curr)
	fmt.Println("Assessment Diff")
	fmt.Println(strings.Repeat("─", 40))
	fmt.Printf("  Status:  %s → %s\n", diff.PreviousStatus, diff.CurrentStatus)
	fmt.Printf("  Added:   %d\n", len(diff.Added))
	fmt.Printf("  Removed: %d\n", len(diff.Removed))
	fmt.Printf("  Changed: %d\n", len(diff.SeverityChanged))
	fmt.Printf("  Stable:  %d\n", len(diff.Unchanged))

	if len(diff.Added) > 0 {
		fmt.Println("\n  New findings:")
		for _, f := range diff.Added {
			fmt.Printf("    + [%-8s] %s on %s\n", f.Severity, f.ControlID, truncate(string(f.AssetID), 30))
		}
	}
	if len(diff.Removed) > 0 {
		fmt.Println("\n  Resolved:")
		for _, f := range diff.Removed {
			fmt.Printf("    - [%-8s] %s on %s\n", f.Severity, f.ControlID, truncate(string(f.AssetID), 30))
		}
	}
	fmt.Println()
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
