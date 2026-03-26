package policy

import (
	"strings"
	"sync"

	"github.com/sufield/stave/pkg/alpha/domain/asset"
)

// ExemptionRule defines the criteria for completely skipping an asset's evaluation.
type ExemptionRule struct {
	// Pattern supports exact asset IDs or simple globs (e.g., "aws_s3_bucket:*").
	Pattern string `json:"pattern" yaml:"pattern"`
	Reason  string `json:"reason"  yaml:"reason"`
}

// ExemptionConfig manages asset-level exemptions with an optimized lookup index.
// Always used as a pointer — sync.Once is safe for thread-safe init.
type ExemptionConfig struct {
	Version string
	Assets  []ExemptionRule

	exactMatches map[string]*ExemptionRule
	globMatches  []*ExemptionRule
	once         sync.Once
}

// NewExemptionConfig creates a prepared ExemptionConfig with indexed rules.
func NewExemptionConfig(version string, assets []ExemptionRule) *ExemptionConfig {
	c := &ExemptionConfig{Version: version, Assets: assets}
	c.Prepare()
	return c
}

// ShouldExempt determines if a specific asset ID should be skipped.
// Returns the matching rule if an exemption applies; otherwise nil.
// Thread-safe via sync.Once.
func (c *ExemptionConfig) ShouldExempt(assetID asset.ID) *ExemptionRule {
	if c == nil || len(c.Assets) == 0 {
		return nil
	}
	c.Prepare()

	id := string(assetID)

	// Fast path: O(1) exact match lookup.
	if rule, ok := c.exactMatches[id]; ok {
		return rule
	}

	// Slow path: iterate through glob patterns.
	for _, rule := range c.globMatches {
		if globMatch(rule.Pattern, id) {
			return rule
		}
	}
	return nil
}

// Prepare indexes the rules for efficient lookup.
// Thread-safe and idempotent via sync.Once.
func (c *ExemptionConfig) Prepare() {
	if c == nil {
		return
	}
	c.once.Do(func() {
		c.exactMatches = make(map[string]*ExemptionRule)
		c.globMatches = make([]*ExemptionRule, 0)
		for i := range c.Assets {
			r := &c.Assets[i]
			if strings.Contains(r.Pattern, "*") {
				c.globMatches = append(c.globMatches, r)
			} else {
				c.exactMatches[r.Pattern] = r
			}
		}
	})
}

// matchPattern checks if a string matches a pattern (exact or glob).
// Shared by ExemptionConfig and ExceptionRule.
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
	if pattern == "*" {
		return true
	}

	segments := strings.Split(pattern, "*")
	if len(segments) == 1 {
		return pattern == s
	}

	if !strings.HasPrefix(s, segments[0]) {
		return false
	}
	s = s[len(segments[0]):]

	for i := 1; i < len(segments)-1; i++ {
		idx := strings.Index(s, segments[i])
		if idx < 0 {
			return false
		}
		s = s[idx+len(segments[i]):]
	}

	return strings.HasSuffix(s, segments[len(segments)-1])
}
