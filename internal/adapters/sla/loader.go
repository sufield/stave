// Package sla provides SLA policy loading from embedded YAML files.
package sla

import (
	"embed"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"strings"

	"github.com/sufield/stave/internal/core/kernel"
	"gopkg.in/yaml.v3"
)

//go:embed embedded/*.yaml
var policiesFS embed.FS

// Policy defines remediation deadlines per severity tier.
type Policy struct {
	ID               string        `yaml:"id"          json:"id"`
	Name             string        `yaml:"name"        json:"name"`
	Description      string        `yaml:"description" json:"description,omitempty"`
	Deadlines        DeadlineTiers `yaml:"deadlines"   json:"deadlines"`
	EscalationFactor float64       `yaml:"escalation_factor" json:"escalation_factor"`
}

// DeadlineTiers maps severity levels to deadline durations (as strings).
type DeadlineTiers struct {
	Critical string `yaml:"critical" json:"critical"`
	High     string `yaml:"high"     json:"high"`
	Medium   string `yaml:"medium"   json:"medium"`
	Low      string `yaml:"low"      json:"low"`
}

// DeadlineHoursFor returns the deadline in hours for a given severity.
// Returns 0 if severity is unrecognized or has no deadline.
func (p *Policy) DeadlineHoursFor(severity string) float64 {
	var raw string
	switch strings.ToLower(severity) {
	case "critical":
		raw = p.Deadlines.Critical
	case "high":
		raw = p.Deadlines.High
	case "medium":
		raw = p.Deadlines.Medium
	case "low":
		raw = p.Deadlines.Low
	default:
		return 0
	}
	if raw == "" {
		return 0
	}
	d, err := kernel.ParseDuration(raw)
	if err != nil {
		return 0
	}
	return d.Hours()
}

// LoadFromFile reads an SLA policy from a local YAML file.
func LoadFromFile(path string) (*Policy, error) {
	data, err := os.ReadFile(path) //nolint:gosec // user-specified path
	if err != nil {
		return nil, fmt.Errorf("read sla policy %q: %w", path, err)
	}
	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parse sla policy %q: %w", path, err)
	}
	if valErr := p.Validate(); valErr != nil {
		return nil, fmt.Errorf("invalid sla policy %q: %w", path, valErr)
	}
	return &p, nil
}

// Validate checks that all required fields are present and valid.
func (p *Policy) Validate() error {
	var errs []string
	if p.Deadlines.Critical == "" {
		errs = append(errs, "deadlines.critical is required")
	} else if _, err := kernel.ParseDuration(p.Deadlines.Critical); err != nil {
		errs = append(errs, "deadlines.critical: "+err.Error())
	}
	if p.Deadlines.High == "" {
		errs = append(errs, "deadlines.high is required")
	} else if _, err := kernel.ParseDuration(p.Deadlines.High); err != nil {
		errs = append(errs, "deadlines.high: "+err.Error())
	}
	if p.Deadlines.Medium == "" {
		errs = append(errs, "deadlines.medium is required")
	} else if _, err := kernel.ParseDuration(p.Deadlines.Medium); err != nil {
		errs = append(errs, "deadlines.medium: "+err.Error())
	}
	if p.Deadlines.Low == "" {
		errs = append(errs, "deadlines.low is required")
	} else if _, err := kernel.ParseDuration(p.Deadlines.Low); err != nil {
		errs = append(errs, "deadlines.low: "+err.Error())
	}
	if p.EscalationFactor < 1.0 || p.EscalationFactor > 3.0 {
		errs = append(errs, fmt.Sprintf("escalation_factor %.1f must be between 1.0 and 3.0", p.EscalationFactor))
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

// LoadEmbedded loads an SLA policy by ID from embedded files.
func LoadEmbedded(id string) (*Policy, error) {
	data, err := policiesFS.ReadFile("embedded/" + id + ".yaml")
	if err != nil {
		return nil, fmt.Errorf("sla policy %q not found", id)
	}
	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parse sla policy %q: %w", id, err)
	}
	return &p, nil
}

// AvailableProfiles returns the IDs of all embedded SLA policies.
//
// The embedded filesystem is built into the binary, so a walk error
// here is structural — likely a missing build-time embed directive.
// It cannot be returned to the caller without a signature change,
// so log a warning instead. The earlier shape silently swallowed
// the error, leaving operators without any signal when a build
// shipped without the embedded SLA catalog.
func AvailableProfiles() []string {
	var ids []string
	walkErr := fs.WalkDir(policiesFS, "embedded", func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if name, ok := strings.CutSuffix(d.Name(), ".yaml"); ok {
			ids = append(ids, name)
		}
		return nil
	})
	if walkErr != nil {
		slog.Warn("sla: failed to walk embedded SLA profile catalog",
			"error", walkErr)
	}
	return ids
}
