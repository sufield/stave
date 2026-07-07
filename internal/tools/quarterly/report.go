package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

func writeTextReport(report *AuditReport) {
	line := strings.Repeat("═", 55)
	fmt.Println(line)
	fmt.Printf("STAVE QUARTERLY AUDIT — %s\n", report.Quarter)
	fmt.Println(line)
	fmt.Println()

	fmt.Println("ENGINES:")
	for _, e := range report.Engines {
		if e.Error != "" {
			fmt.Printf("  %-18s  SKIPPED  %s\n", e.Engine, e.Error)
			continue
		}
		fmt.Printf("  %-18s  ran %-6s  checked %5d  %d gaps\n",
			e.Engine, fmtDuration(e.Duration), e.TotalChecked, len(e.GapsFound))
	}
	fmt.Println()

	fmt.Printf("TOTAL: %d unique gaps (after dedup from %d raw)\n\n",
		report.TotalDeduped, report.TotalRaw)

	if len(report.MultiEngine) > 0 {
		fmt.Printf("MULTI-ENGINE GAPS (%d — highest confidence):\n", len(report.MultiEngine))
		for i, g := range report.MultiEngine {
			printGap(i+1, g)
		}
		fmt.Println()
	}

	if len(report.SingleEngine) > 0 {
		n := len(report.MultiEngine)
		fmt.Printf("SINGLE-ENGINE GAPS (%d):\n", len(report.SingleEngine))
		for i, g := range report.SingleEngine {
			printGap(n+i+1, g)
		}
		fmt.Println()
	}

	if report.TotalDeduped == 0 {
		fmt.Println("No coverage gaps found.")
		fmt.Println()
	}

	fmt.Println("QUARTER-OVER-QUARTER:")
	fmt.Print(formatQuarterDiff(report.Diff))
	fmt.Println()
	fmt.Println(line)
}

func printGap(n int, g Gap) {
	fmt.Printf("  %d. %s:%s  [%s]\n", n, g.Service, g.Property, g.Severity)
	fmt.Printf("     %s\n", g.Source)
	if len(g.Taxonomy) > 0 {
		fmt.Printf("     → %s\n", strings.Join(g.Taxonomy, ", "))
	}
}

func fmtDuration(d interface{ Seconds() float64 }) string {
	s := d.Seconds()
	if s < 1 {
		return fmt.Sprintf("%.0fms", s*1000)
	}
	return fmt.Sprintf("%.1fs", s)
}

func writeJSONReport(report *AuditReport) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
