// exception.go provides finding-level exception functionality.
// Unlike exemptions (which skip entire assets), exceptions silence
// specific control+asset pairs with an audit trail and expiry date.
// Excepted findings are still evaluated but partitioned into a separate
// output array - nothing is silently dropped.
package policy

import (
	"fmt"
	"time"

	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/kernel"
)

const exceptionDateLayout = "2006-01-02"

// ExpiryDate represents a date-only value for exception lifecycles.
// Zero value (time.Time.IsZero()) means "no expiry".
type ExpiryDate time.Time

// ParseExpiryDate parses YYYY-MM-DD into an ExpiryDate.
// Empty string returns zero ExpiryDate (no expiry).
func ParseExpiryDate(s string) (ExpiryDate, error) {
	if s == "" {
		return ExpiryDate{}, nil
	}
	v, err := time.Parse(exceptionDateLayout, s)
	if err != nil {
		return ExpiryDate{}, fmt.Errorf("invalid exception expiry %q: %w", s, err)
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
	return time.Time(d).Format(exceptionDateLayout)
}

// IsExpired reports whether the current time has passed the expiry date.
// A date of 2026-01-01 expires at the start of 2026-01-02, so the
// exception remains active for the entire specified day.
func (d ExpiryDate) IsExpired(now time.Time) bool {
	if d.IsZero() {
		return false
	}
	endOfDay := time.Time(d).Add(24 * time.Hour)
	return now.After(endOfDay) || now.Equal(endOfDay)
}

// ExceptionRule defines a single exception entry from stave.yaml.
type ExceptionRule struct {
	ControlID kernel.ControlID `json:"control_id"`
	AssetID   asset.ID         `json:"asset_id"`
	Reason    string           `json:"reason"`
	Expires   ExpiryDate       `json:"expires"` // YYYY-MM-DD
}

func (r ExceptionRule) matchesResource(assetID asset.ID) bool {
	return matchPattern(r.AssetID.String(), assetID.String())
}

// ExceptionConfig holds all exception rules with an indexed lookup.
type ExceptionConfig struct {
	Rules []ExceptionRule

	index map[kernel.ControlID][]*ExceptionRule
	ready bool
}

// NewExceptionConfig creates a prepared ExceptionConfig with indexed rules.
func NewExceptionConfig(rules []ExceptionRule) *ExceptionConfig {
	c := &ExceptionConfig{Rules: rules}
	c.Prepare()
	return c
}

// ShouldExcept checks if a specific control+asset pair should be excepted.
// Returns the matched rule when exception applies; otherwise nil.
func (c *ExceptionConfig) ShouldExcept(controlID kernel.ControlID, assetID asset.ID, now time.Time) *ExceptionRule {
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
func (c *ExceptionConfig) Prepare() {
	if c == nil || c.ready {
		return
	}

	c.index = make(map[kernel.ControlID][]*ExceptionRule, len(c.Rules))
	for i := range c.Rules {
		rule := &c.Rules[i]
		c.index[rule.ControlID] = append(c.index[rule.ControlID], rule)
	}
	c.ready = true
}
