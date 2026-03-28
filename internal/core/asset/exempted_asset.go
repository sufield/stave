package asset

import "github.com/sufield/stave/internal/core/kernel"

// ExemptedAsset represents an asset that was skipped due to exemption rules.
type ExemptedAsset struct {
	ID      ID     `json:"asset_id"`
	Pattern string `json:"matched_pattern"`
	Reason  string `json:"reason"`
}

// Sanitized returns a copy with the asset ID replaced by a deterministic token.
func (s ExemptedAsset) Sanitized(r kernel.IDSanitizer) ExemptedAsset {
	out := s
	out.ID = ID(r.ID(string(s.ID)))
	return out
}
