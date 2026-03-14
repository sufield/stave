package shared

import (
	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/safetyenvelope"
)

// FindingsToVerificationEntries transforms domain findings into safety envelope
// verification entries.
//
// If a sanitizer is provided, it is applied to the AssetID of each finding
// to ensure that the resulting verification entries respect the configured
// anonymization settings.
func FindingsToVerificationEntries(san kernel.Sanitizer, findings []evaluation.Finding) []safetyenvelope.VerificationEntry {
	if len(findings) == 0 {
		return nil
	}

	entries := make([]safetyenvelope.VerificationEntry, 0, len(findings))
	for _, f := range findings {
		assetID := f.AssetID
		if san != nil {
			assetID = asset.ID(san.ID(string(assetID)))
		}

		entries = append(entries, safetyenvelope.VerificationEntry{
			ControlID:   f.ControlID,
			ControlName: f.ControlName,
			AssetID:     assetID,
			AssetType:   f.AssetType,
		})
	}
	return entries
}
