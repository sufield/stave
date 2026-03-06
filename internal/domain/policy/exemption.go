// exemption.go provides resource-level exemption/allowlist functionality.
package policy

import (
	"strings"

	"github.com/sufield/stave/internal/domain/asset"
)

// ExemptionConfig defines resources that should be skipped during evaluation.
type ExemptionConfig struct {
	// Version is the config schema version.
	Version string `yaml:"version"`

	// Resources lists resource IDs or patterns to exempt.
	// Supports exact matches and glob patterns (e.g., "k8s:ClusterRoleBinding/*").
	Resources []ExemptionRule `yaml:"resources"`
}

// ExemptionRule defines a single exemption rule.
type ExemptionRule struct {
	// Pattern is the resource ID pattern to match.
	// Supports exact matches and glob patterns with "*".
	Pattern string `yaml:"pattern"`

	// Reason explains why this resource is being exempted.
	Reason string `yaml:"reason"`
}

// SkippedAsset represents a resource that was skipped due to exemption rules.
type SkippedAsset struct {
	AssetID asset.ID `json:"asset_id"`
	Pattern string   `json:"matched_pattern"`
	Reason  string   `json:"reason"`
}

// ShouldExempt checks if a resource should be exempted based on the configuration.
// Returns the matched exemption rule, or nil if no exemption applies.
func (c *ExemptionConfig) ShouldExempt(assetID string) *ExemptionRule {
	// Nil-safe guard remains for safety
	if c == nil {
		return nil
	}

	for i := range c.Resources {
		// Rule is returned by reference to the slice element
		if matchPattern(c.Resources[i].Pattern, assetID) {
			return &c.Resources[i]
		}
	}

	return nil
}

// matchPattern checks if a resource ID matches a pattern.
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
