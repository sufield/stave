// suppression.go provides finding-level suppression functionality.
// Unlike exemptions (which skip entire assets), suppressions silence
// specific control+asset pairs with an audit trail and expiry date.
// Suppressed findings are still evaluated but partitioned into a separate
// output array - nothing is silently dropped.
package policy

import (
	"fmt"
	"time"

	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/kernel"
)

const suppressionDateLayout = "2006-01-02"

// ExpiryDate is a date-only value object used for suppression expiry.
// Zero value means "no expiry".
type ExpiryDate struct {
	value time.Time
	set   bool
}

// ParseExpiryDate parses YYYY-MM-DD into an ExpiryDate.
// Empty string returns zero ExpiryDate (no expiry).
func ParseExpiryDate(s string) (ExpiryDate, error) {
	if s == "" {
		return ExpiryDate{}, nil
	}
	v, err := time.Parse(suppressionDateLayout, s)
	if err != nil {
		return ExpiryDate{}, fmt.Errorf("invalid suppression expiry %q: %w", s, err)
	}
	return ExpiryDate{value: v, set: true}, nil
}

func (d ExpiryDate) IsZero() bool {
	return !d.set
}

func (d ExpiryDate) String() string {
	if !d.set {
		return ""
	}
	return d.value.Format(suppressionDateLayout)
}

func (d ExpiryDate) IsExpired(now time.Time) bool {
	if !d.set {
		return false
	}
	return now.After(d.value) || now.Equal(d.value)
}

// SuppressionRule defines a single suppression entry from stave.yaml.
type SuppressionRule struct {
	ControlID kernel.ControlID `yaml:"control_id" json:"control_id"`
	AssetID   asset.ID         `yaml:"asset_id" json:"asset_id"`
	Reason    string           `yaml:"reason" json:"reason"`
	Expires   ExpiryDate       `yaml:"expires,omitempty" json:"expires"` // YYYY-MM-DD
}

func (r SuppressionRule) matchesResource(assetID asset.ID) bool {
	return matchPattern(r.AssetID.String(), assetID.String())
}

// SuppressionConfig holds all suppression rules.
type SuppressionConfig struct {
	Rules []SuppressionRule

	indexedRules map[kernel.ControlID][]*SuppressionRule
	prepared     bool
}

// NewSuppressionConfig creates a prepared SuppressionConfig with indexed rules.
func NewSuppressionConfig(rules []SuppressionRule) *SuppressionConfig {
	c := &SuppressionConfig{Rules: rules}
	c.Prepare()
	return c
}

// SuppressedFinding records a finding that was suppressed, with audit trail.
type SuppressedFinding struct {
	ControlID kernel.ControlID `json:"control_id"`
	AssetID   asset.ID         `json:"asset_id"`
	Reason    string           `json:"reason"`
	Expires   string           `json:"expires,omitempty"`
}

// ShouldSuppress checks if a specific control+asset pair should be suppressed.
// Returns the matched rule when suppression applies; otherwise nil.
func (c *SuppressionConfig) ShouldSuppress(controlID kernel.ControlID, assetID asset.ID, now time.Time) *SuppressionRule {
	if c == nil {
		return nil
	}
	if !c.prepared {
		panic("precondition failed: ShouldSuppress requires Prepare()")
	}

	for _, rule := range c.indexedRules[controlID] {
		if !rule.matchesResource(assetID) {
			continue
		}
		if rule.Expires.IsExpired(now) {
			continue
		}
		return rule
	}

	return nil
}

// Prepare validates and indexes suppression rules for efficient lookups.
// It is safe to call multiple times.
func (c *SuppressionConfig) Prepare() {
	if c == nil || c.prepared {
		return
	}

	c.indexedRules = make(map[kernel.ControlID][]*SuppressionRule, len(c.Rules))
	for i := range c.Rules {
		rule := &c.Rules[i]
		c.indexedRules[rule.ControlID] = append(c.indexedRules[rule.ControlID], rule)
	}
	c.prepared = true
}
