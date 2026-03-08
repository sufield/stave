package shared

import (
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/safetyenvelope"
)

// FindingsToVerificationEntries maps findings to verification entries.
func FindingsToVerificationEntries(findings []evaluation.Finding) []safetyenvelope.VerificationEntry {
	entries := make([]safetyenvelope.VerificationEntry, 0, len(findings))
	for _, f := range findings {
		entries = append(entries, safetyenvelope.VerificationEntry{
			ControlID:   f.ControlID,
			ControlName: f.ControlName,
			AssetID:     f.AssetID,
			AssetType:   f.AssetType,
		})
	}
	return entries
}
