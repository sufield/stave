package text

import (
	"fmt"
	"slices"
	"strings"

	"github.com/sufield/stave/internal/core/evaluation/coverage"
)

// notCoveredDisplayCap caps the per-tool/domain "Not covered" list in
// text output. Long lists are truncated with an ellipsis so the section
// stays scannable; full lists remain available in JSON output.
const notCoveredDisplayCap = 5

// writeCoveragePosture renders the per-tool, per-domain coverage
// posture section. Silent when no inventories are loaded — Stave keeps
// its existing output shape unless coverage data is available.
func (w *FindingWriter) writeCoveragePosture(d *drawer, idx *coverage.CoverageIndex) {
	if idx == nil || len(idx.ByTool) == 0 {
		return
	}

	d.ln("")
	d.ln("Coverage posture")
	d.ln("----------------")

	for _, tool := range sortedKeys(idx.ByTool) {
		domains := idx.ByTool[tool]
		for _, domain := range sortedKeys(domains) {
			dc := domains[domain]
			d.f("  %s / %s: %s\n", tool, domain, summarizeCoverage(dc))
		}
	}

	wrote := false
	for _, tool := range sortedKeys(idx.ByTool) {
		domains := idx.ByTool[tool]
		for _, domain := range sortedKeys(domains) {
			dc := domains[domain]
			if len(dc.NotCoveredChecks) == 0 {
				continue
			}
			if !wrote {
				d.ln("")
				wrote = true
			}
			d.f("  Not covered (%s %s): %s\n", tool, domain, formatNotCovered(dc.NotCoveredChecks))
		}
	}
}

func summarizeCoverage(dc coverage.DomainCoverage) string {
	if dc.Total == 0 {
		noun := "checks"
		if dc.Covered == 1 {
			noun = "check"
		}
		return fmt.Sprintf("%d %s covered (no inventory)", dc.Covered, noun)
	}
	return fmt.Sprintf("%d of %d checks covered", dc.Covered, dc.Total)
}

func formatNotCovered(checks []string) string {
	if len(checks) <= notCoveredDisplayCap {
		return strings.Join(checks, ", ")
	}
	return strings.Join(checks[:notCoveredDisplayCap], ", ") + ", ..."
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
