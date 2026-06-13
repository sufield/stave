package sla

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/sufield/stave/internal/core/kernel"
)

func TestLoadEmbedded_Default(t *testing.T) {
	p, err := LoadEmbedded("default")
	if err != nil {
		t.Fatal(err)
	}
	if p.ID != "default" {
		t.Errorf("ID = %q, want default", p.ID)
	}
	if p.DeadlineHoursFor("critical") != 72 {
		t.Errorf("critical = %f, want 72", p.DeadlineHoursFor("critical"))
	}
	if p.DeadlineHoursFor("high") != 336 {
		t.Errorf("high = %f, want 336", p.DeadlineHoursFor("high"))
	}
	if p.EscalationFactor != 1.5 {
		t.Errorf("escalation = %f, want 1.5", p.EscalationFactor)
	}
}

func TestLoadEmbedded_PCI(t *testing.T) {
	p, err := LoadEmbedded("pci_dss_v4")
	if err != nil {
		t.Fatal(err)
	}
	if p.DeadlineHoursFor("critical") != 24 {
		t.Errorf("critical = %f, want 24", p.DeadlineHoursFor("critical"))
	}
}

func TestLoadEmbedded_HIPAA(t *testing.T) {
	p, err := LoadEmbedded("hipaa")
	if err != nil {
		t.Fatal(err)
	}
	if p.DeadlineHoursFor("critical") != 72 {
		t.Errorf("critical = %f, want 72", p.DeadlineHoursFor("critical"))
	}
	if p.EscalationFactor != 1.3 {
		t.Errorf("escalation = %f, want 1.3", p.EscalationFactor)
	}
}

func TestLoadEmbedded_NotFound(t *testing.T) {
	_, err := LoadEmbedded("nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent profile")
	}
}

func TestLoadFromFile_Valid(t *testing.T) {
	yaml := `
id: custom_test
name: "Custom Test SLA"
deadlines:
  critical: 4h
  high: 24h
  medium: 168h
  low: 720h
escalation_factor: 2.0
`
	path := filepath.Join(t.TempDir(), "custom-sla.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := LoadFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if p.ID != "custom_test" {
		t.Errorf("ID = %q, want custom_test", p.ID)
	}
	if p.DeadlineHoursFor("critical") != 4 {
		t.Errorf("critical = %f, want 4", p.DeadlineHoursFor("critical"))
	}
	if p.EscalationFactor != 2.0 {
		t.Errorf("escalation = %f, want 2.0", p.EscalationFactor)
	}
}

func TestLoadFromFile_InvalidDuration(t *testing.T) {
	yaml := `
id: bad
deadlines:
  critical: "2 hours"
  high: 24h
  medium: 168h
  low: 720h
escalation_factor: 1.5
`
	path := filepath.Join(t.TempDir(), "bad-sla.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadFromFile(path)
	if err == nil {
		t.Error("expected error for invalid duration")
	}
}

func TestLoadFromFile_MissingSeverity(t *testing.T) {
	yaml := `
id: incomplete
deadlines:
  critical: 4h
escalation_factor: 1.5
`
	path := filepath.Join(t.TempDir(), "incomplete-sla.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadFromFile(path)
	if err == nil {
		t.Error("expected error for missing severity tiers")
	}
}

func TestLoadFromFile_NotFound(t *testing.T) {
	_, err := LoadFromFile("/nonexistent/sla.yaml")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestValidate_EscalationOutOfRange(t *testing.T) {
	p := &Policy{
		Deadlines:        DeadlineTiers{Critical: "4h", High: "24h", Medium: "168h", Low: "720h"},
		EscalationFactor: 5.0,
	}
	if err := p.Validate(); err == nil {
		t.Error("expected error for escalation_factor > 3.0")
	}
}

func TestAvailableProfiles(t *testing.T) {
	profiles := AvailableProfiles()
	if len(profiles) < 5 {
		t.Errorf("expected at least 5 profiles, got %d: %v", len(profiles), profiles)
	}
	want := map[string]struct{}{
		"default": {}, "pci_dss_v4": {}, "hipaa": {},
		"soc2": {}, "fedramp_moderate": {},
	}
	for _, p := range profiles {
		delete(want, p)
	}
	for missing := range want {
		t.Errorf("missing profile: %s", missing)
	}
}

func TestDeadlineHoursFor_UnknownSeverity(t *testing.T) {
	p, _ := LoadEmbedded("default")
	if p.DeadlineHoursFor("info") != 0 {
		t.Errorf("info severity should return 0, got %f", p.DeadlineHoursFor("info"))
	}
}

func TestValidate_ErrorIdentityPreserved(t *testing.T) {
	p := &Policy{
		Deadlines:        DeadlineTiers{Critical: "", High: "24h", Medium: "168h", Low: "720h"},
		EscalationFactor: 2.0,
	}
	err := p.Validate()
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !errors.Is(err, kernel.ErrEmptyDuration) {
		t.Errorf("expected error to wrap kernel.ErrEmptyDuration, but it did not: %v", err)
	}
}
