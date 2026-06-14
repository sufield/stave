// Package sla provides SLA policy loading from embedded YAML files.
package sla

import (
	"embed"
	"errors"
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

// KnownSeverities returns the canonical severity vocabulary the
// SLA policy supports. Centralised so callers iterating "all
// severities to deadline" stop reproducing the slice.
func (p *Policy) KnownSeverities() []string {
	return []string{"critical", "high", "medium", "low"}
}

// AllDeadlines returns a (severity → hours) map covering every
// known severity tier. Centralises the four-call DeadlineHoursFor
// table cmd/monitor used to build inline so a future tier addition
// (e.g. info) lands as one edit on this method plus KnownSeverities.
func (p *Policy) AllDeadlines() map[string]float64 {
	if p == nil {
		return nil
	}
	deadlines := make(map[string]float64, 4)
	for _, sev := range p.KnownSeverities() {
		deadlines[sev] = p.DeadlineHoursFor(sev)
	}
	return deadlines
}

// DeadlineHoursFor returns the deadline in hours for a given severity.
// Returns 0 if severity is unrecognized or has no deadline.
func (p *Policy) DeadlineHoursFor(severity string) float64 {
	var raw string
	if strings.EqualFold(severity, "critical") {
		raw = p.Deadlines.Critical
	} else if strings.EqualFold(severity, "high") {
		raw = p.Deadlines.High
	} else if strings.EqualFold(severity, "medium") {
		raw = p.Deadlines.Medium
	} else if strings.EqualFold(severity, "low") {
		raw = p.Deadlines.Low
	} else {
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
// Tier-level checks live on DeadlineTiers itself; Policy.Validate
// only owns the Policy-scoped invariants (escalation_factor range).
func (p *Policy) Validate() error {
	var errs []error
	if err := p.Deadlines.Validate(); err != nil {
		errs = append(errs, err)
	}
	if p.EscalationFactor < 1.0 || p.EscalationFactor > 3.0 {
		errs = append(errs, fmt.Errorf("escalation_factor %.1f must be between 1.0 and 3.0", p.EscalationFactor))
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

// Validate checks that all four severity tiers carry a non-empty,
// kernel.ParseDuration-parseable string. Returns a single
// joined error so the caller can surface every missing /
// malformed tier in one pass instead of failing on the first.
//
// Owns the per-tier "required and parseable" rule so Policy.Validate
// stops reproducing the same four-field walk; future additions to the
// tier set are one edit on DeadlineTiers.
func (d *DeadlineTiers) Validate() error {
	if d == nil {
		return errors.New("deadlines: tier set is nil")
	}
	tiers := []struct {
		name  string
		value string
	}{
		{"critical", d.Critical},
		{"high", d.High},
		{"medium", d.Medium},
		{"low", d.Low},
	}
	var errs []error
	for _, t := range tiers {
		if t.value == "" {
			errs = append(errs, fmt.Errorf("deadlines.%s is required: %w", t.name, kernel.ErrEmptyDuration))
		} else if _, err := kernel.ParseDuration(t.value); err != nil {
			errs = append(errs, fmt.Errorf("deadlines.%s: %w", t.name, err))
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

// LoadEmbedded loads an SLA policy by ID from embedded files.
func LoadEmbedded(id string) (*Policy, error) {
	data, err := policiesFS.ReadFile("embedded/" + id + ".yaml")
	if err != nil {
		return nil, fmt.Errorf("sla policy %q not found: %w", id, err)
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
