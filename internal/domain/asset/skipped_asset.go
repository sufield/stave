package asset

import "github.com/sufield/stave/internal/domain/kernel"

// SkippedAsset represents an asset that was skipped due to exemption rules.
type SkippedAsset struct {
	ID      ID     `json:"asset_id"`
	Pattern string `json:"matched_pattern"`
	Reason  string `json:"reason"`
}

// Sanitized returns a copy with the asset ID replaced by a deterministic token.
func (s SkippedAsset) Sanitized(r kernel.IDSanitizer) SkippedAsset {
	out := s
	out.ID = ID(r.ID(string(s.ID)))
	return out
}
