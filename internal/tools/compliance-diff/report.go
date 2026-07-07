package main

import (
	"fmt"
	"strings"
)

func writeTextReport(report DiffReport, gapsOnly bool) {
	s := report.Summary
	fmt.Println(strings.Repeat("═", 55))
	fmt.Printf("COMPLIANCE DIFF: %s\n", report.Framework)
	fmt.Println(strings.Repeat("═", 55))

	fmt.Println()
	fmt.Println("SUMMARY:")
	fmt.Printf("  Total checks:     %d\n", s.Total)
	fmt.Printf("  In scope:         %d\n", s.InScope)
	fmt.Printf("  Out of scope:     %d\n", s.OutOfScope)
	fmt.Println()

	if s.InScope > 0 {
		fmt.Println("IN-SCOPE COVERAGE:")
		fmt.Printf("  Covered:          %d (%d%%)\n", s.Covered, pct(s.Covered, s.InScope))
		fmt.Printf("  Partial:          %d (%d%%)\n", s.Partial, pct(s.Partial, s.InScope))
		fmt.Printf("  Gap:              %d (%d%%)\n", s.Gap, pct(s.Gap, s.InScope))
		fmt.Println()
	}

	if !gapsOnly {
		printSection("COVERED", report, "covered")
		printSection("PARTIAL", report, "partial")
	}
	printSection("GAP", report, "gap")
	if !gapsOnly {
		printSection("OUT OF SCOPE", report, "out_of_scope")
	}
}

func printSection(title string, report DiffReport, status string) {
	var results []MatchResult
	for _, r := range report.Results {
		if r.Status == status {
			results = append(results, r)
		}
	}
	if len(results) == 0 {
		return
	}

	fmt.Printf("%s (%d):\n", title, len(results))
	for _, r := range results {
		line := fmt.Sprintf("  %-14s %-8s %s", r.Check.ID, r.Check.Service, r.Check.Description)
		if len(r.ControlIDs) > 0 {
			ids := r.ControlIDs
			if len(ids) > 3 {
				ids = append(ids[:3], fmt.Sprintf("+%d more", len(ids)-3))
			}
			line += "  → " + strings.Join(ids, ", ")
		}
		fmt.Println(line)
		if r.Notes != "" {
			fmt.Printf("               %s\n", r.Notes)
		}
	}
	fmt.Println()
}

func writeSummaryTable(reports []DiffReport) {
	fmt.Printf("%-45s %6s %6s %12s %6s\n", "FRAMEWORK", "CHECKS", "SCOPE", "COVERED", "GAPS")
	for _, r := range reports {
		s := r.Summary
		covered := fmt.Sprintf("%d (%d%%)", s.Covered+s.Partial, pct(s.Covered+s.Partial, s.InScope))
		fmt.Printf("%-45s %6d %6d %12s %6d\n",
			truncateStr(r.Framework, 45), s.Total, s.InScope, covered, s.Gap)
	}
}

func pct(n, total int) int {
	if total == 0 {
		return 0
	}
	return n * 100 / total
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}
