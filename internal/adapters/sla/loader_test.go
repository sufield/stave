package sla

import (
	"testing"
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

func TestAvailableProfiles(t *testing.T) {
	profiles := AvailableProfiles()
	if len(profiles) < 5 {
		t.Errorf("expected at least 5 profiles, got %d: %v", len(profiles), profiles)
	}
	want := map[string]bool{
		"default": true, "pci_dss_v4": true, "hipaa": true,
		"soc2": true, "fedramp_moderate": true,
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
