// Package retention defines canonical retention-tier types shared across
// configuration, pruning, and config-service packages.
package retention

import (
	"fmt"
	"time"

	"github.com/sufield/stave/internal/pkg/timeutil"
)

// DefaultKeepMin is the fallback keep_min value when none is configured.
const DefaultKeepMin = 2

// TierConfig holds a tier's retention settings.
type TierConfig struct {
	OlderThan string `yaml:"older_than" json:"older_than"`
	KeepMin   int    `yaml:"keep_min"   json:"keep_min"`
}

// ParseDuration returns the OlderThan string as a time.Duration.
func (c TierConfig) ParseDuration() (time.Duration, error) {
	if c.OlderThan == "" {
		return 0, fmt.Errorf("older_than is empty")
	}
	return timeutil.ParseDuration(c.OlderThan)
}

// EffectiveKeepMin returns the keep_min value, using DefaultKeepMin as fallback.
func (c TierConfig) EffectiveKeepMin() int {
	if c.KeepMin <= 0 {
		return DefaultKeepMin
	}
	return c.KeepMin
}

// MappingRule maps a glob pattern to a retention tier.
type MappingRule struct {
	Pattern string `yaml:"pattern" json:"pattern"`
	Tier    string `yaml:"tier"    json:"tier"`
}
