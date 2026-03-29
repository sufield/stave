package schemaval

import "testing"

func TestStatus_String(t *testing.T) {
	tests := []struct {
		s    Status
		want string
	}{
		{StatusPass, "PASS"},
		{StatusWarn, "WARN"},
		{StatusFail, "FAIL"},
	}
	for _, tt := range tests {
		t.Run(string(tt.s), func(t *testing.T) {
			if got := tt.s.String(); got != tt.want {
				t.Fatalf("String()=%q, want %q", got, tt.want)
			}
		})
	}
}

func TestNewReport(t *testing.T) {
	r := NewReport("/controls", "/observations")
	if r == nil {
		t.Fatal("NewReport returned nil")
	}
	if !r.Ready {
		t.Fatal("new report should default to Ready=true")
	}
	if r.ControlsDir != "/controls" {
		t.Fatalf("ControlsDir=%q", r.ControlsDir)
	}
	if r.ObservationsDir != "/observations" {
		t.Fatalf("ObservationsDir=%q", r.ObservationsDir)
	}
	if r.Summary.Errors != 0 {
		t.Fatalf("Errors=%d, want 0", r.Summary.Errors)
	}
	if r.Summary.Warnings != 0 {
		t.Fatalf("Warnings=%d, want 0", r.Summary.Warnings)
	}
}

func TestReport_Issues_Empty(t *testing.T) {
	r := NewReport("", "")
	issues := r.Issues()
	if len(issues) != 0 {
		t.Fatalf("len=%d, want 0", len(issues))
	}
}

func TestReport_RecordIssue_Fail(t *testing.T) {
	r := NewReport("", "")
	r.RecordIssue(Issue{
		Name:    "schema check",
		Status:  StatusFail,
		Message: "schema invalid",
		Fix:     "fix the schema",
	})

	if r.Ready {
		t.Fatal("Ready should be false after recording a fail issue")
	}
	if r.Summary.Errors != 1 {
		t.Fatalf("Errors=%d, want 1", r.Summary.Errors)
	}
	if r.Summary.Warnings != 0 {
		t.Fatalf("Warnings=%d, want 0", r.Summary.Warnings)
	}
	issues := r.Issues()
	if len(issues) != 1 {
		t.Fatalf("Issues len=%d, want 1", len(issues))
	}
	if issues[0].Name != "schema check" {
		t.Fatalf("Name=%q", issues[0].Name)
	}
}

func TestReport_RecordIssue_Warn(t *testing.T) {
	r := NewReport("", "")
	r.RecordIssue(Issue{
		Name:   "minor warning",
		Status: StatusWarn,
	})

	if !r.Ready {
		t.Fatal("Ready should remain true after recording a warning")
	}
	if r.Summary.Warnings != 1 {
		t.Fatalf("Warnings=%d, want 1", r.Summary.Warnings)
	}
	if r.Summary.Errors != 0 {
		t.Fatalf("Errors=%d, want 0", r.Summary.Errors)
	}
}

func TestReport_RecordIssue_Pass(t *testing.T) {
	r := NewReport("", "")
	r.RecordIssue(Issue{
		Name:   "all good",
		Status: StatusPass,
	})

	if !r.Ready {
		t.Fatal("Ready should remain true after pass")
	}
	if r.Summary.Errors != 0 || r.Summary.Warnings != 0 {
		t.Fatalf("unexpected counters: errors=%d warnings=%d", r.Summary.Errors, r.Summary.Warnings)
	}
	if len(r.Issues()) != 1 {
		t.Fatalf("Issues len=%d, want 1", len(r.Issues()))
	}
}

func TestReport_Issues_ReturnsDefensiveCopy(t *testing.T) {
	r := NewReport("", "")
	r.RecordIssue(Issue{Name: "original", Status: StatusPass})

	issues := r.Issues()
	issues[0].Name = "mutated"

	fresh := r.Issues()
	if fresh[0].Name != "original" {
		t.Fatal("Issues() should return a defensive copy")
	}
}

func TestReport_MultipleIssues(t *testing.T) {
	r := NewReport("/c", "/o")
	r.RecordIssue(Issue{Name: "fail1", Status: StatusFail})
	r.RecordIssue(Issue{Name: "warn1", Status: StatusWarn})
	r.RecordIssue(Issue{Name: "fail2", Status: StatusFail})
	r.RecordIssue(Issue{Name: "pass1", Status: StatusPass})

	if r.Ready {
		t.Fatal("should not be ready with fail issues")
	}
	if r.Summary.Errors != 2 {
		t.Fatalf("Errors=%d, want 2", r.Summary.Errors)
	}
	if r.Summary.Warnings != 1 {
		t.Fatalf("Warnings=%d, want 1", r.Summary.Warnings)
	}
	if len(r.Issues()) != 4 {
		t.Fatalf("Issues len=%d, want 4", len(r.Issues()))
	}
}
