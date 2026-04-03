package asset

// ExemptedAsset represents an asset that was skipped due to exemption rules.
type ExemptedAsset struct {
	ID      ID     `json:"asset_id"`
	Pattern string `json:"matched_pattern"`
	Reason  string `json:"reason"`
}
