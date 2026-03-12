package policy

import (
	"strings"
)

// ExemptionConfig defines a set of rules used to exclude specific assets
// from policy evaluation.
type ExemptionConfig struct {
	Version string          `yaml:"version"`
	Assets  []ExemptionRule `yaml:"assets"`

	// Prepared state for performance optimization
	exactMatches map[string]*ExemptionRule
	globMatches  []*ExemptionRule
	ready        bool
}

// ExemptionRule defines the criteria for skipping an asset.
type ExemptionRule struct {
	// Pattern supports exact asset IDs or simple globs (e.g. "aws_s3_bucket:*")
	Pattern string `yaml:"pattern"`
	Reason  string `yaml:"reason"`
}

// Prepare indexes the rules to optimize lookup performance.
// This should be called once after the configuration is loaded.
func (c *ExemptionConfig) Prepare() {
	if c == nil || c.ready {
		return
	}

	c.exactMatches = make(map[string]*ExemptionRule)
	c.globMatches = make([]*ExemptionRule, 0)

	for i := range c.Assets {
		rule := &c.Assets[i]
		if strings.Contains(rule.Pattern, "*") {
			c.globMatches = append(c.globMatches, rule)
		} else {
			c.exactMatches[rule.Pattern] = rule
		}
	}
	c.ready = true
}

// ShouldExempt determines if a specific asset ID is covered by an exemption rule.
// It returns the matching rule or nil if the asset should be evaluated.
func (c *ExemptionConfig) ShouldExempt(assetID string) *ExemptionRule {
	if c == nil {
		return nil
	}

	// Auto-prepare if the caller forgot, though loaders should handle this.
	if !c.ready {
		c.Prepare()
	}

	// 1. Fast path: O(1) exact match lookup
	if rule, ok := c.exactMatches[assetID]; ok {
		return rule
	}

	// 2. Slow path: Iterate through glob patterns
	for _, rule := range c.globMatches {
		if globMatch(rule.Pattern, assetID) {
			return rule
		}
	}

	return nil
}

// matchPattern checks if a string matches a pattern supporting exact and glob matches.
// Shared by ExemptionConfig and SuppressionRule.
func matchPattern(pattern, s string) bool {
	if pattern == s {
		return true
	}
	if strings.Contains(pattern, "*") {
		return globMatch(pattern, s)
	}
	return false
}

// globMatch performs simple glob matching where "*" matches any character sequence.
func globMatch(pattern, s string) bool {
	segments := strings.Split(pattern, "*")
	if len(segments) == 1 {
		return pattern == s
	}

	// Must match the start of the pattern
	if !strings.HasPrefix(s, segments[0]) {
		return false
	}
	s = s[len(segments[0]):]

	// Match intermediate segments in order
	for i := 1; i < len(segments)-1; i++ {
		idx := strings.Index(s, segments[i])
		if idx < 0 {
			return false
		}
		s = s[idx+len(segments[i]):]
	}

	// Must match the end of the pattern
	return strings.HasSuffix(s, segments[len(segments)-1])
}
