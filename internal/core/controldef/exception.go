// exception.go provides finding-level exception functionality.
// Unlike exemptions (which skip entire assets), exceptions silence
// specific control+asset pairs with an audit trail and expiry date.
// Excepted findings are still evaluated but partitioned into a separate
// output array — nothing is silently dropped.
package controldef

import (
	"fmt"
	"sync"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/kernel"
)

const dateLayout = "2006-01-02"

// ExpiryDate represents a date-only value for exception lifecycles.
// Zero value means "no expiry".
type ExpiryDate time.Time

// ParseExpiryDate parses YYYY-MM-DD into an ExpiryDate.
// Empty string returns zero ExpiryDate (no expiry).
func ParseExpiryDate(s string) (ExpiryDate, error) {
	if s == "" {
		return ExpiryDate{}, nil
	}
	v, err := time.Parse(dateLayout, s)
	if err != nil {
		return ExpiryDate{}, fmt.Errorf("policy: invalid expiry date %q: %w", s, err)
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

// IsZero reports whether the date is unset.
func (d ExpiryDate) IsZero() bool {
	return time.Time(d).IsZero()
}

// String returns YYYY-MM-DD or "never" for the zero value.
func (d ExpiryDate) String() string {
	if d.IsZero() {
		return "never"
	}
	return time.Time(d).Format(dateLayout)
}

// IsExpired reports whether the current time has passed the expiry date.
// A date of 2026-01-01 expires at the start of 2026-01-02 UTC, so the
// exception remains active for the entire specified day.
func (d ExpiryDate) IsExpired(now time.Time) bool {
	if d.IsZero() {
		return false
	}
	expiryBoundary := time.Time(d).AddDate(0, 0, 1)
	return !now.Before(expiryBoundary)
}

// ExceptionRule defines a single exception entry from stave.yaml.
type ExceptionRule struct {
	ControlID kernel.ControlID `json:"control_id" yaml:"control_id"`
	AssetID   asset.ID         `json:"asset_id"   yaml:"asset_id"`
	Reason    string           `json:"reason"     yaml:"reason"`
	Expires   ExpiryDate       `json:"expires"    yaml:"expires"`
}

// Validate ensures the rule has the required identifiers.
func (r ExceptionRule) Validate() error {
	if r.ControlID == "" {
		return fmt.Errorf("exception rule: control_id is required")
	}
	if r.AssetID == "" {
		return fmt.Errorf("exception rule: asset_id is required")
	}
	return nil
}

func (r ExceptionRule) matches(assetID asset.ID) bool {
	return matchPattern(r.AssetID.String(), assetID.String())
}

// ExceptionConfig holds all exception rules with an indexed lookup.
// Always used as a pointer — sync.Once is safe for thread-safe init.
type ExceptionConfig struct {
	Rules []ExceptionRule

	index map[kernel.ControlID][]*ExceptionRule
	once  sync.Once
}

// NewExceptionConfig creates a prepared ExceptionConfig with indexed rules.
func NewExceptionConfig(rules []ExceptionRule) *ExceptionConfig {
	c := &ExceptionConfig{Rules: rules}
	c.Prepare()
	return c
}

// ShouldExcept checks if a specific control+asset pair should be excepted.
// Returns the matched rule when exception applies; otherwise nil.
// Thread-safe via sync.Once.
func (c *ExceptionConfig) ShouldExcept(controlID kernel.ControlID, assetID asset.ID, now time.Time) *ExceptionRule {
	if c == nil || len(c.Rules) == 0 {
		return nil
	}
	c.Prepare()

	for _, rule := range c.index[controlID] {
		if !rule.matches(assetID) {
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
// Thread-safe and idempotent via sync.Once.
func (c *ExceptionConfig) Prepare() {
	if c == nil {
		return
	}
	c.once.Do(func() {
		c.index = make(map[kernel.ControlID][]*ExceptionRule, len(c.Rules))
		for i := range c.Rules {
			rule := &c.Rules[i]
			c.index[rule.ControlID] = append(c.index[rule.ControlID], rule)
		}
	})
}
