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

// ExpiryDate represents a date-only value for suppression lifecycles.
// Zero value (time.Time.IsZero()) means "no expiry".
type ExpiryDate time.Time

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
	return ExpiryDate(v), nil
}

// UnmarshalText implements encoding.TextUnmarshaler for automatic YAML/JSON parsing.
func (d *ExpiryDate) UnmarshalText(text []byte) error {
	s := string(text)
	if s == "" || s == "null" {
		return nil
	}
	parsed, err := ParseExpiryDate(s)
	if err != nil {
		return err
	}
	*d = parsed
	return nil
}

func (d ExpiryDate) IsZero() bool {
	return time.Time(d).IsZero()
}

func (d ExpiryDate) String() string {
	if d.IsZero() {
		return ""
	}
	return time.Time(d).Format(suppressionDateLayout)
}

// IsExpired reports whether the current time has passed the expiry date.
// A date of 2026-01-01 expires at the start of 2026-01-02, so the
// suppression remains active for the entire specified day.
func (d ExpiryDate) IsExpired(now time.Time) bool {
	if d.IsZero() {
		return false
	}
	endOfDay := time.Time(d).Add(24 * time.Hour)
	return now.After(endOfDay) || now.Equal(endOfDay)
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

// SuppressionConfig holds all suppression rules with an indexed lookup.
type SuppressionConfig struct {
	Rules []SuppressionRule

	index map[kernel.ControlID][]*SuppressionRule
	ready bool
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
	if !c.ready {
		c.Prepare()
	}

	for _, rule := range c.index[controlID] {
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

// Prepare indexes the rules for efficient O(1) control ID lookups.
// Safe to call multiple times.
func (c *SuppressionConfig) Prepare() {
	if c == nil || c.ready {
		return
	}

	c.index = make(map[kernel.ControlID][]*SuppressionRule, len(c.Rules))
	for i := range c.Rules {
		rule := &c.Rules[i]
		c.index[rule.ControlID] = append(c.index[rule.ControlID], rule)
	}
	c.ready = true
}
