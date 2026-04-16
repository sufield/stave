// Package overlay provides environment-specific severity adjustments
// for the control catalog without modifying canonical control YAML.
package overlay

import (
	"fmt"
	"os"
	"strings"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
	"gopkg.in/yaml.v3"
)

// Config is the on-disk overlay format.
type Config struct {
	SchemaVersion string        `yaml:"schema_version"`
	Name          string        `yaml:"name"`
	Description   string        `yaml:"description"`
	AssetFilter   *AssetFilter  `yaml:"asset_filter,omitempty"`
	Overrides     []Override    `yaml:"overrides"`
	SLAOverrides  *SLAOverrides `yaml:"sla_overrides,omitempty"`
}

// AssetFilter restricts which assets the overlay applies to.
type AssetFilter struct {
	Tags map[string]string `yaml:"tags"`
}

// Override adjusts a control's severity or threshold.
type Override struct {
	ControlID string `yaml:"control_id,omitempty"`
	Domain    string `yaml:"domain,omitempty"`
	Severity  string `yaml:"severity"`
	Rationale string `yaml:"rationale"`
}

// SLAOverrides adjusts SLA deadlines for the overlay environment.
type SLAOverrides struct {
	Critical string `yaml:"critical"`
	High     string `yaml:"high"`
	Medium   string `yaml:"medium"`
	Low      string `yaml:"low"`
}

// LoadFromFile reads an overlay configuration.
func LoadFromFile(path string) (*Config, error) {
	data, err := os.ReadFile(path) //nolint:gosec // user path
	if err != nil {
		return nil, fmt.Errorf("read overlay %s: %w", path, err)
	}
	var cfg Config
	if unmarshalErr := yaml.Unmarshal(data, &cfg); unmarshalErr != nil {
		return nil, fmt.Errorf("parse overlay %s: %w", path, unmarshalErr)
	}
	return &cfg, nil
}

// ApplyResult describes what the overlay changed on a control.
type ApplyResult struct {
	OriginalSeverity policy.Severity
	Suppressed       bool
	OverlayName      string
	Rationale        string
}

// Apply modifies controls in-place based on the overlay rules.
// Returns a map of control ID → ApplyResult for controls that were changed.
func Apply(controls []policy.ControlDefinition, cfg *Config) map[kernel.ControlID]ApplyResult {
	if cfg == nil || len(cfg.Overrides) == 0 {
		return nil
	}

	// Build lookup indexes.
	controlOverrides := make(map[string]*Override)
	domainOverrides := make(map[string]*Override)
	for i := range cfg.Overrides {
		o := &cfg.Overrides[i]
		if o.ControlID != "" {
			controlOverrides[o.ControlID] = o
		} else if o.Domain != "" {
			domainOverrides[o.Domain] = o
		}
	}

	results := make(map[kernel.ControlID]ApplyResult)

	for i := range controls {
		ctl := &controls[i]

		// Control-level override takes priority.
		if o, ok := controlOverrides[string(ctl.ID)]; ok {
			results[ctl.ID] = applyOverride(ctl, o, cfg.Name)
			continue
		}

		// Domain-level override.
		if o, ok := domainOverrides[string(ctl.Domain)]; ok {
			results[ctl.ID] = applyOverride(ctl, o, cfg.Name)
		}
	}

	return results
}

func applyOverride(ctl *policy.ControlDefinition, o *Override, overlayName string) ApplyResult {
	result := ApplyResult{
		OriginalSeverity: ctl.Severity,
		OverlayName:      overlayName,
		Rationale:        o.Rationale,
	}

	sev := strings.ToLower(o.Severity)
	switch sev {
	case "suppressed":
		result.Suppressed = true
		ctl.Severity = 0 // zero severity marks as suppressed
	case "critical":
		ctl.Severity = policy.SeverityCritical
	case "high":
		ctl.Severity = policy.SeverityHigh
	case "medium":
		ctl.Severity = policy.SeverityMedium
	case "low":
		ctl.Severity = policy.SeverityLow
	case "info":
		ctl.Severity = policy.SeverityInfo
	}

	return result
}

// MatchesFilter checks if an asset matches the overlay's asset filter.
func MatchesFilter(cfg *Config, tags map[string]string) bool {
	if cfg == nil || cfg.AssetFilter == nil || len(cfg.AssetFilter.Tags) == 0 {
		return true // no filter = apply to all
	}
	for k, v := range cfg.AssetFilter.Tags {
		if tags[k] != v {
			return false
		}
	}
	return true
}
