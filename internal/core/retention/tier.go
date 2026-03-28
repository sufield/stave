// Package retention defines canonical retention-tier types shared across
// configuration, pruning, and config-service packages.
package retention

import (
	"fmt"
	"time"

	"github.com/sufield/stave/internal/core/kernel"
)

// DefaultKeepMin is the fallback value for minimum items to retain if not specified.
const DefaultKeepMin = 2

// Tier defines the retention settings for a specific category of data.
type Tier struct {
	OlderThan string `yaml:"older_than" json:"older_than"`
	KeepMin   int    `yaml:"keep_min"   json:"keep_min"`
}

// Validate checks if the tier configuration is semantically correct.
func (t Tier) Validate() error {
	if t.OlderThan == "" {
		return fmt.Errorf("retention: older_than must not be empty")
	}
	_, err := t.Duration()
	return err
}

// Duration parses the OlderThan string into a time.Duration.
func (t Tier) Duration() (time.Duration, error) {
	if t.OlderThan == "" {
		return 0, nil
	}
	d, err := kernel.ParseDuration(t.OlderThan)
	if err != nil {
		return 0, fmt.Errorf("retention: invalid duration %q: %w", t.OlderThan, err)
	}
	return d, nil
}

// MinRetained returns the effective number of items to keep.
// Defaults to DefaultKeepMin if the configured value is 0 or less.
func (t Tier) MinRetained() int {
	if t.KeepMin <= 0 {
		return DefaultKeepMin
	}
	return t.KeepMin
}

// Rule maps a resource pattern (glob) to a specific retention tier name.
type Rule struct {
	Pattern string `yaml:"pattern" json:"pattern"`
	Tier    string `yaml:"tier"    json:"tier"`
}

// Validate ensures the rule has both a pattern and a target tier.
func (r Rule) Validate() error {
	if r.Pattern == "" {
		return fmt.Errorf("retention rule: pattern is required")
	}
	if r.Tier == "" {
		return fmt.Errorf("retention rule: tier name is required")
	}
	return nil
}

// --- Backward-compatibility aliases (remove once all callers migrate) ---

// TierConfig is an alias for Tier.
type TierConfig = Tier

// MappingRule is an alias for Rule.
type MappingRule = Rule

// ParseDuration returns the OlderThan string as a time.Duration.
// Unlike Duration(), it returns an error when OlderThan is empty.
func (t Tier) ParseDuration() (time.Duration, error) {
	if t.OlderThan == "" {
		return 0, fmt.Errorf("older_than is empty")
	}
	return kernel.ParseDuration(t.OlderThan)
}

// EffectiveKeepMin is an alias for MinRetained on Tier.
func (t Tier) EffectiveKeepMin() int { return t.MinRetained() }
