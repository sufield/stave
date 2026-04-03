package compliance

import (
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
)

// ---------------------------------------------------------------------------
// Definition getters
// ---------------------------------------------------------------------------

func TestDefinition_Description(t *testing.T) {
	d := Definition{description: "test description"}
	if d.Description() != "test description" {
		t.Fatalf("Description = %q", d.Description())
	}
}

func TestDefinition_ProfileRationale(t *testing.T) {
	d := Definition{
		profileRationales: map[string]string{
			"hipaa": "Required for HIPAA compliance",
		},
	}
	if got := d.ProfileRationale("hipaa"); got != "Required for HIPAA compliance" {
		t.Fatalf("ProfileRationale(hipaa) = %q", got)
	}
	if got := d.ProfileRationale("nonexistent"); got != "" {
		t.Fatalf("ProfileRationale(nonexistent) = %q", got)
	}
}

func TestDefinition_ProfileSeverityOverride(t *testing.T) {
	d := Definition{
		profileSeverities: map[string]policy.Severity{
			"hipaa": policy.SeverityCritical,
		},
	}
	sev, ok := d.ProfileSeverityOverride("hipaa")
	if !ok || sev != policy.SeverityCritical {
		t.Fatalf("ProfileSeverityOverride(hipaa) = %v, %v", sev, ok)
	}
	_, ok = d.ProfileSeverityOverride("nonexistent")
	if ok {
		t.Fatal("expected false for nonexistent profile")
	}
}

// ---------------------------------------------------------------------------
// Registry.ByProfile
// ---------------------------------------------------------------------------

func TestRegistry_ByProfile(t *testing.T) {
	// The global ControlRegistry should have controls for "hipaa"
	controls := ControlRegistry.ByProfile("hipaa")
	if len(controls) == 0 {
		t.Fatal("expected HIPAA controls in registry")
	}
}

func TestRegistry_ByProfile_Unknown(t *testing.T) {
	controls := ControlRegistry.ByProfile("nonexistent_profile")
	if len(controls) != 0 {
		t.Fatalf("expected 0 controls for unknown profile, got %d", len(controls))
	}
}

// ---------------------------------------------------------------------------
// ParseSeverity — additional edge cases (delegated to policy.ParseSeverity)
// ---------------------------------------------------------------------------

func TestParseSeverity_AllValid(t *testing.T) {
	tests := []struct {
		in   string
		want policy.Severity
	}{
		{"critical", policy.SeverityCritical},
		{"high", policy.SeverityHigh},
		{"medium", policy.SeverityMedium},
		{"low", policy.SeverityLow},
	}
	for _, tt := range tests {
		got, err := policy.ParseSeverity(tt.in)
		if err != nil {
			t.Fatalf("ParseSeverity(%q) error: %v", tt.in, err)
		}
		if got != tt.want {
			t.Fatalf("ParseSeverity(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestParseSeverity_Invalid(t *testing.T) {
	_, err := policy.ParseSeverity("invalid")
	if err == nil {
		t.Fatal("expected error for invalid severity")
	}
}

func TestParseSeverity_CaseInsensitive(t *testing.T) {
	// policy.ParseSeverity is case-insensitive
	s, err := policy.ParseSeverity("CRITICAL")
	if err != nil {
		t.Fatalf("ParseSeverity(CRITICAL) error: %v", err)
	}
	if s != policy.SeverityCritical {
		t.Fatalf("ParseSeverity(CRITICAL) = %v, want %v", s, policy.SeverityCritical)
	}
}
