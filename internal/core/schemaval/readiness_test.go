package schemaval

import (
	"testing"

	"github.com/sufield/stave/internal/core/outcome"
)

func TestStatus_String(t *testing.T) {
	tests := []struct {
		s    outcome.Status
		want string
	}{
		{outcome.Pass, "PASS"},
		{outcome.Warn, "WARN"},
		{outcome.Fail, "FAIL"},
	}
	for _, tt := range tests {
		t.Run(tt.s.String(), func(t *testing.T) {
			if got := tt.s.String(); got != tt.want {
				t.Fatalf("String()=%q, want %q", got, tt.want)
			}
		})
	}
}

func TestNewReadinessAssessment(t *testing.T) {
	r := NewReadinessAssessment("/controls", "/observations")
	if r == nil {
		t.Fatal("NewReadinessAssessment returned nil")
	}
	if !r.IsSafe {
		t.Fatal("new assessment should default to IsSafe=true")
	}
	if r.ControlSource != "/controls" {
		t.Fatalf("ControlSource=%q", r.ControlSource)
	}
	if r.ObservationSource != "/observations" {
		t.Fatalf("ObservationSource=%q", r.ObservationSource)
	}
	if r.Summary.Errors != 0 {
		t.Fatalf("Errors=%d, want 0", r.Summary.Errors)
	}
	if r.Summary.Warnings != 0 {
		t.Fatalf("Warnings=%d, want 0", r.Summary.Warnings)
	}
}

func TestReadinessAssessment_Findings_Empty(t *testing.T) {
	r := NewReadinessAssessment("", "")
	findings := r.Findings()
	if len(findings) != 0 {
		t.Fatalf("len=%d, want 0", len(findings))
	}
}

func TestReadinessAssessment_RecordFinding_Fail(t *testing.T) {
	r := NewReadinessAssessment("", "")
	r.RecordFinding(ValidationFinding{
		Name:        "schema check",
		Status:      outcome.Fail,
		Message:     "schema invalid",
		Remediation: "fix the schema",
	})

	if r.IsSafe {
		t.Fatal("IsSafe should be false after recording a fail finding")
	}
	if r.Summary.Errors != 1 {
		t.Fatalf("Errors=%d, want 1", r.Summary.Errors)
	}
	if r.Summary.Warnings != 0 {
		t.Fatalf("Warnings=%d, want 0", r.Summary.Warnings)
	}
	findings := r.Findings()
	if len(findings) != 1 {
		t.Fatalf("Findings len=%d, want 1", len(findings))
	}
	if findings[0].Name != "schema check" {
		t.Fatalf("Name=%q", findings[0].Name)
	}
}

func TestReadinessAssessment_RecordFinding_Warn(t *testing.T) {
	r := NewReadinessAssessment("", "")
	r.RecordFinding(ValidationFinding{
		Name:   "minor warning",
		Status: outcome.Warn,
	})

	if !r.IsSafe {
		t.Fatal("IsSafe should remain true after recording a warning")
	}
	if r.Summary.Warnings != 1 {
		t.Fatalf("Warnings=%d, want 1", r.Summary.Warnings)
	}
	if r.Summary.Errors != 0 {
		t.Fatalf("Errors=%d, want 0", r.Summary.Errors)
	}
}

func TestReadinessAssessment_RecordFinding_Pass(t *testing.T) {
	r := NewReadinessAssessment("", "")
	r.RecordFinding(ValidationFinding{
		Name:   "all good",
		Status: outcome.Pass,
	})

	if !r.IsSafe {
		t.Fatal("IsSafe should remain true after pass")
	}
	if r.Summary.Errors != 0 || r.Summary.Warnings != 0 {
		t.Fatalf("unexpected counters: errors=%d warnings=%d", r.Summary.Errors, r.Summary.Warnings)
	}
	if len(r.Findings()) != 1 {
		t.Fatalf("Findings len=%d, want 1", len(r.Findings()))
	}
}

func TestReadinessAssessment_Findings_ReturnsDefensiveCopy(t *testing.T) {
	r := NewReadinessAssessment("", "")
	r.RecordFinding(ValidationFinding{Name: "original", Status: outcome.Pass})

	findings := r.Findings()
	findings[0].Name = "mutated"

	fresh := r.Findings()
	if fresh[0].Name != "original" {
		t.Fatal("Findings() should return a defensive copy")
	}
}

func TestReadinessAssessment_MultipleFindings(t *testing.T) {
	r := NewReadinessAssessment("/c", "/o")
	r.RecordFinding(ValidationFinding{Name: "fail1", Status: outcome.Fail})
	r.RecordFinding(ValidationFinding{Name: "warn1", Status: outcome.Warn})
	r.RecordFinding(ValidationFinding{Name: "fail2", Status: outcome.Fail})
	r.RecordFinding(ValidationFinding{Name: "pass1", Status: outcome.Pass})

	if r.IsSafe {
		t.Fatal("should not be safe with fail findings")
	}
	if r.Summary.Errors != 2 {
		t.Fatalf("Errors=%d, want 2", r.Summary.Errors)
	}
	if r.Summary.Warnings != 1 {
		t.Fatalf("Warnings=%d, want 1", r.Summary.Warnings)
	}
	if len(r.Findings()) != 4 {
		t.Fatalf("Findings len=%d, want 4", len(r.Findings()))
	}
}
