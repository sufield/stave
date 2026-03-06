package asset

// IDSanitizer replaces identifiers with deterministic tokens.
type IDSanitizer interface {
	ID(string) string
}

// SkippedAsset represents a resource that was skipped due to exemption rules.
type SkippedAsset struct {
	ID      ID     `json:"asset_id"`
	Pattern string `json:"matched_pattern"`
	Reason  string `json:"reason"`
}

// Sanitized returns a copy with the asset ID replaced by a deterministic token.
func (s SkippedAsset) Sanitized(r IDSanitizer) SkippedAsset {
	out := s
	out.ID = ID(r.ID(string(s.ID)))
	return out
}
