// exemption.go provides asset-level exemption/allowlist functionality.
package policy

import (
	"strings"

	"github.com/sufield/stave/internal/domain/asset"
)

// ExemptionConfig defines assets that should be skipped during evaluation.
type ExemptionConfig struct {
	// Version is the config schema version.
	Version string `yaml:"version"`

	// Assets lists asset IDs or patterns to exempt.
	// Supports exact matches and glob patterns (e.g., "k8s:ClusterRoleBinding/*").
	Assets []ExemptionRule `yaml:"assets"`
}

// ExemptionRule defines a single exemption rule.
type ExemptionRule struct {
	// Pattern is the asset ID pattern to match.
	// Supports exact matches and glob patterns with "*".
	Pattern string `yaml:"pattern"`

	// Reason explains why this asset is being exempted.
	Reason string `yaml:"reason"`
}

// SkippedAsset represents an asset that was skipped due to exemption rules.
type SkippedAsset struct {
	AssetID asset.ID `json:"asset_id"`
	Pattern string   `json:"matched_pattern"`
	Reason  string   `json:"reason"`
}

// ShouldExempt checks if an asset should be exempted based on the configuration.
// Returns the matched exemption rule, or nil if no exemption applies.
func (c *ExemptionConfig) ShouldExempt(assetID string) *ExemptionRule {
	// Nil-safe guard remains for safety
	if c == nil {
		return nil
	}

	for i := range c.Assets {
		// Rule is returned by reference to the slice element
		if matchPattern(c.Assets[i].Pattern, assetID) {
			return &c.Assets[i]
		}
	}

	return nil
}

// matchPattern checks if an asset ID matches a pattern.
// Supports exact matches and simple glob patterns with "*".
func matchPattern(pattern, assetID string) bool {
	if pattern == assetID {
		return true
	}
	if strings.Contains(pattern, "*") {
		return globMatch(pattern, assetID)
	}
	return false
}

// globMatch performs simple glob matching where "*" matches any sequence of characters.
func globMatch(pattern, s string) bool {
	segments := strings.Split(pattern, "*")
	if !strings.HasPrefix(s, segments[0]) {
		return false
	}
	s = s[len(segments[0]):]
	for _, seg := range segments[1 : len(segments)-1] {
		idx := strings.Index(s, seg)
		if idx < 0 {
			return false
		}
		s = s[idx+len(seg):]
	}
	return strings.HasSuffix(s, segments[len(segments)-1])
}
