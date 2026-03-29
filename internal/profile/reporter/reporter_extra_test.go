package reporter

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sufield/stave/internal/core/hipaa"
	"github.com/sufield/stave/internal/core/hipaa/compound"
	"github.com/sufield/stave/internal/profile"
)

// ---------------------------------------------------------------------------
// TextReporter.String
// ---------------------------------------------------------------------------

func TestTextReporter_String(t *testing.T) {
	r := TextReporter{}
	out := r.String(fixtureReport(), fixtureMeta())
	if out == "" {
		t.Fatal("expected non-empty string")
	}
	if !strings.Contains(out, "FAIL") {
		t.Fatal("expected FAIL in output")
	}
}

// ---------------------------------------------------------------------------
// passLabel
// ---------------------------------------------------------------------------

func TestPassLabel(t *testing.T) {
	if passLabel(true) != "PASS" {
		t.Fatal("expected PASS")
	}
	if passLabel(false) != "FAIL" {
		t.Fatal("expected FAIL")
	}
}

// ---------------------------------------------------------------------------
// filterBySeverity
// ---------------------------------------------------------------------------

func TestFilterBySeverity(t *testing.T) {
	results := fixtureReport().Results
	critical := filterBySeverity(results, hipaa.Critical)
	if len(critical) != 2 {
		t.Fatalf("expected 2 critical, got %d", len(critical))
	}
	low := filterBySeverity(results, hipaa.Low)
	if len(low) != 0 {
		t.Fatalf("expected 0 low, got %d", len(low))
	}
}

// ---------------------------------------------------------------------------
// TextReporter with passing report
// ---------------------------------------------------------------------------

func TestTextReporter_PassingReport(t *testing.T) {
	report := profile.ProfileReport{
		ProfileName: "HIPAA Security Rule",
		Pass:        true,
		Results:     []profile.ProfileResult{},
		Counts:      map[hipaa.Severity]int{},
		FailCounts:  map[hipaa.Severity]int{},
	}
	var buf bytes.Buffer
	err := TextReporter{}.Write(&buf, report, fixtureMeta())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "PASS") {
		t.Fatal("expected PASS in output")
	}
}

// ---------------------------------------------------------------------------
// TextReporter with compound findings
// ---------------------------------------------------------------------------

func TestTextReporter_CompoundFindings(t *testing.T) {
	report := profile.ProfileReport{
		ProfileName: "HIPAA Security Rule",
		Pass:        false,
		CompoundFindings: []compound.CompoundFinding{
			{
				ID:         "COMPOUND.001",
				Severity:   hipaa.Critical,
				TriggerIDs: []string{"CONTROLS.001", "AUDIT.001"},
				Message:    "Multiple critical failures compound risk",
			},
		},
		Results:    []profile.ProfileResult{},
		Counts:     map[hipaa.Severity]int{},
		FailCounts: map[hipaa.Severity]int{},
	}
	var buf bytes.Buffer
	err := TextReporter{}.Write(&buf, report, fixtureMeta())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "COMPOUND RISKS") {
		t.Fatal("expected COMPOUND RISKS section")
	}
}

// ---------------------------------------------------------------------------
// TextReporter with acknowledged exceptions
// ---------------------------------------------------------------------------

func TestTextReporter_Acknowledged(t *testing.T) {
	report := profile.ProfileReport{
		ProfileName: "HIPAA Security Rule",
		Pass:        true,
		Acknowledged: []profile.AcknowledgedEntry{
			{
				ControlID:      "CONTROLS.001",
				Bucket:         "test-bucket",
				Rationale:      "accepted risk",
				AcknowledgedBy: "admin",
				Valid:          true,
			},
			{
				ControlID:      "CONTROLS.002",
				Bucket:         "test-bucket-2",
				Rationale:      "expired",
				AcknowledgedBy: "admin",
				Valid:          false,
				InvalidReason:  "exception expired",
			},
		},
		Results:    []profile.ProfileResult{},
		Counts:     map[hipaa.Severity]int{},
		FailCounts: map[hipaa.Severity]int{},
	}
	var buf bytes.Buffer
	err := TextReporter{}.Write(&buf, report, fixtureMeta())
	if err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "Acknowledged Exceptions") {
		t.Fatal("expected Acknowledged Exceptions section")
	}
	if !strings.Contains(out, "INVALID") {
		t.Fatal("expected INVALID status for expired exception")
	}
}
