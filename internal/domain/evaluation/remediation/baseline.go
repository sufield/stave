package remediation

import "github.com/sufield/stave/internal/domain/evaluation"

// BaselineEntriesFromFindings converts findings to deduplicated, sorted baseline entries.
func BaselineEntriesFromFindings(findings []Finding) []evaluation.BaselineEntry {
	if len(findings) == 0 {
		return nil
	}

	unique := make(map[evaluation.BaselineEntryKey]evaluation.BaselineEntry, len(findings))
	for _, f := range findings {
		entry := evaluation.BaselineEntryFromFinding(f.Finding)
		unique[entry.Key()] = entry
	}

	entries := make([]evaluation.BaselineEntry, 0, len(unique))
	for _, e := range unique {
		entries = append(entries, e)
	}

	evaluation.SortBaselineEntries(entries)
	return entries
}
