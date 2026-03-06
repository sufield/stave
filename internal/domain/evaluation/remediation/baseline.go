package remediation

import "github.com/sufield/stave/internal/domain/evaluation"

// BaselineEntriesFromFindings converts findings to deduplicated, sorted baseline entries.
func BaselineEntriesFromFindings(findings []Finding) []evaluation.BaselineEntry {
	byKey := make(map[evaluation.BaselineEntryKey]evaluation.BaselineEntry, len(findings))
	for _, f := range findings {
		entry := evaluation.BaselineEntryFromFinding(f.Finding)
		byKey[entry.Key()] = entry
	}
	out := make([]evaluation.BaselineEntry, 0, len(byKey))
	for _, e := range byKey {
		out = append(out, e)
	}
	evaluation.SortBaselineEntries(out)
	return out
}
