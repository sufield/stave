package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const auditDir = "tools/quarterly-audit"

func currentQuarter() string {
	now := time.Now()
	q := (now.Month()-1)/3 + 1
	return fmt.Sprintf("%d-Q%d", now.Year(), q)
}

func saveReport(report *AuditReport) error {
	if err := os.MkdirAll(auditDir, 0o755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}

	path := filepath.Join(auditDir, report.Quarter+"-gaps.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return err
	}

	latestPath := filepath.Join(auditDir, "latest-gaps.json")
	os.Remove(latestPath) //nolint:errcheck // best-effort symlink
	if err := os.Symlink(filepath.Base(path), latestPath); err != nil {
		return os.WriteFile(latestPath, data, 0o644)
	}

	fmt.Fprintf(os.Stderr, "Saved to %s\n", path)
	return nil
}

func loadPreviousReport() *AuditReport {
	latestPath := filepath.Join(auditDir, "latest-gaps.json")
	data, err := os.ReadFile(latestPath)
	if err != nil {
		return nil
	}

	var report AuditReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil
	}
	return &report
}

func computeDiff(current *AuditReport, previous *AuditReport) *QuarterDiff {
	if previous == nil {
		return nil
	}

	prevKeys := make(map[string]Gap)
	allPrev := append(previous.MultiEngine, previous.SingleEngine...)
	for _, g := range allPrev {
		prevKeys[gapKey(g)] = g
	}

	currKeys := make(map[string]Gap)
	allCurr := append(current.MultiEngine, current.SingleEngine...)
	for _, g := range allCurr {
		currKeys[gapKey(g)] = g
	}

	diff := &QuarterDiff{
		PreviousQuarter: previous.Quarter,
	}

	for key, g := range currKeys {
		if _, found := prevKeys[key]; !found {
			diff.NewGaps = append(diff.NewGaps, g)
		} else {
			diff.PersistentGaps = append(diff.PersistentGaps, g)
		}
	}

	for key, g := range prevKeys {
		if _, found := currKeys[key]; !found {
			diff.FixedGaps = append(diff.FixedGaps, g)
		}
	}

	sortGaps(diff.NewGaps)
	sortGaps(diff.FixedGaps)
	sortGaps(diff.PersistentGaps)

	return diff
}

func formatQuarterDiff(diff *QuarterDiff) string {
	if diff == nil {
		return "  No previous quarter data for comparison.\n"
	}

	var b strings.Builder
	fmt.Fprintf(&b, "  Previous quarter: %s\n", diff.PreviousQuarter)
	fmt.Fprintf(&b, "  New gaps this quarter:      %d\n", len(diff.NewGaps))
	fmt.Fprintf(&b, "  Fixed since last quarter:   %d\n", len(diff.FixedGaps))
	fmt.Fprintf(&b, "  Persistent (still open):    %d\n", len(diff.PersistentGaps))
	return b.String()
}
