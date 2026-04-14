// Package sla provides SLA policy loading from embedded YAML files.
package sla

import (
	"embed"
	"fmt"
	"io/fs"
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
func AvailableProfiles() []string {
	var ids []string
	_ = fs.WalkDir(policiesFS, "embedded", func(_ string, d fs.DirEntry, err error) error {
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
	return ids
}
