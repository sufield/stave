package diag

import "testing"

func TestNewAssessment_Empty(t *testing.T) {
	a := NewAssessment()
	if a == nil {
		t.Fatal("NewAssessment returned nil")
	}
	if len(a.Findings) != 0 {
		t.Fatalf("new assessment has %d findings, want 0", len(a.Findings))
	}
}

func TestAssessment_Record(t *testing.T) {
	a := NewAssessment()
	a.Record(NewFinding(RuleSchemaViolation).Error().Message("bad schema").Build())
	if len(a.Findings) != 1 {
		t.Fatalf("after Record: len=%d, want 1", len(a.Findings))
	}
}

func TestAssessment_Record_NilReceiver(_ *testing.T) {
	var a *Assessment
	// Should not panic.
	a.Record(NewFinding(RuleSchemaViolation).Build())
}

func TestAssessment_RecordAll(t *testing.T) {
	a := NewAssessment()
	findings := []Finding{
		NewFinding(RuleSchemaViolation).Error().Build(),
		NewFinding(RuleNoControls).Warning().Build(),
	}
	a.RecordAll(findings)
	if len(a.Findings) != 2 {
		t.Fatalf("after RecordAll: len=%d, want 2", len(a.Findings))
	}
}

func TestAssessment_RecordAll_NilReceiver(_ *testing.T) {
	var a *Assessment
	a.RecordAll([]Finding{NewFinding(RuleSchemaViolation).Build()})
}

func TestAssessment_RecordAll_EmptySlice(t *testing.T) {
	a := NewAssessment()
	a.RecordAll(nil)
	if len(a.Findings) != 0 {
		t.Fatalf("after RecordAll(nil): len=%d, want 0", len(a.Findings))
	}
}

func TestAssessment_Merge(t *testing.T) {
	a1 := NewAssessment()
	a1.Record(NewFinding(RuleSchemaViolation).Error().Build())
	a2 := NewAssessment()
	a2.Record(NewFinding(RuleNoControls).Warning().Build())
	a2.Record(NewFinding(RuleNoSnapshots).Warning().Build())

	a1.Merge(a2)
	if len(a1.Findings) != 3 {
		t.Fatalf("after Merge: len=%d, want 3", len(a1.Findings))
	}
}

func TestAssessment_Merge_NilReceiver(_ *testing.T) {
	var a *Assessment
	other := NewAssessment()
	other.Record(NewFinding(RuleSchemaViolation).Build())
	a.Merge(other) // Should not panic.
}

func TestAssessment_Merge_NilOther(t *testing.T) {
	a := NewAssessment()
	a.Record(NewFinding(RuleSchemaViolation).Build())
	a.Merge(nil)
	if len(a.Findings) != 1 {
		t.Fatalf("after Merge(nil): len=%d, want 1", len(a.Findings))
	}
}

func TestAssessment_Merge_EmptyOther(t *testing.T) {
	a := NewAssessment()
	a.Record(NewFinding(RuleSchemaViolation).Build())
	a.Merge(NewAssessment())
	if len(a.Findings) != 1 {
		t.Fatalf("after Merge(empty): len=%d, want 1", len(a.Findings))
	}
}

func TestAssessment_Failed(t *testing.T) {
	tests := []struct {
		name     string
		findings []Finding
		want     bool
	}{
		{"no findings", nil, false},
		{"warning only", []Finding{NewFinding(RuleNoControls).Warning().Build()}, false},
		{"error present", []Finding{NewFinding(RuleSchemaViolation).Error().Build()}, true},
		{"mixed", []Finding{
			NewFinding(RuleNoControls).Warning().Build(),
			NewFinding(RuleSchemaViolation).Error().Build(),
		}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := NewAssessment()
			a.RecordAll(tt.findings)
			if got := a.Failed(); got != tt.want {
				t.Fatalf("Failed()=%v, want %v", got, tt.want)
			}
		})
	}
}

func TestAssessment_Failed_NilReceiver(t *testing.T) {
	var a *Assessment
	if a.Failed() {
		t.Fatal("nil receiver Failed should return false")
	}
}

func TestAssessment_HasWarnings(t *testing.T) {
	tests := []struct {
		name     string
		findings []Finding
		want     bool
	}{
		{"no findings", nil, false},
		{"error only", []Finding{NewFinding(RuleSchemaViolation).Error().Build()}, false},
		{"warning present", []Finding{NewFinding(RuleNoControls).Warning().Build()}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := NewAssessment()
			a.RecordAll(tt.findings)
			if got := a.HasWarnings(); got != tt.want {
				t.Fatalf("HasWarnings()=%v, want %v", got, tt.want)
			}
		})
	}
}

func TestAssessment_HasWarnings_NilReceiver(t *testing.T) {
	var a *Assessment
	if a.HasWarnings() {
		t.Fatal("nil receiver HasWarnings should return false")
	}
}

func TestAssessment_Errors(t *testing.T) {
	a := NewAssessment()
	a.Record(NewFinding(RuleSchemaViolation).Error().Build())
	a.Record(NewFinding(RuleNoControls).Warning().Build())
	a.Record(NewFinding(RuleControlLoadFailed).Error().Build())

	errs := a.Errors()
	if len(errs) != 2 {
		t.Fatalf("Errors() len=%d, want 2", len(errs))
	}
	for _, e := range errs {
		if e.Severity != SeverityError {
			t.Fatalf("Errors() returned severity=%q", e.Severity)
		}
	}
}

func TestAssessment_Warnings(t *testing.T) {
	a := NewAssessment()
	a.Record(NewFinding(RuleSchemaViolation).Error().Build())
	a.Record(NewFinding(RuleNoControls).Warning().Build())

	warns := a.Warnings()
	if len(warns) != 1 {
		t.Fatalf("Warnings() len=%d, want 1", len(warns))
	}
	if warns[0].Severity != SeverityWarn {
		t.Fatalf("Warnings() returned severity=%q", warns[0].Severity)
	}
}

func TestAssessment_Filter_NilReceiver(t *testing.T) {
	var a *Assessment
	if errs := a.Errors(); errs != nil {
		t.Fatalf("nil receiver Errors() should return nil, got %v", errs)
	}
	if warns := a.Warnings(); warns != nil {
		t.Fatalf("nil receiver Warnings() should return nil, got %v", warns)
	}
}

func TestAssessment_Error_NoFindings(t *testing.T) {
	a := NewAssessment()
	got := a.Error()
	want := "security assessment passed: no issues identified"
	if got != want {
		t.Fatalf("Error()=%q, want %q", got, want)
	}
}

func TestAssessment_Error_NilReceiver(t *testing.T) {
	var a *Assessment
	got := a.Error()
	want := "security assessment passed: no issues identified"
	if got != want {
		t.Fatalf("Error()=%q, want %q", got, want)
	}
}

func TestAssessment_Error_WithFindings(t *testing.T) {
	a := NewAssessment()
	a.Record(NewFinding(RuleSchemaViolation).Error().Message("bad field").Attribute("path", "/dsl_version").Build())
	a.Record(NewFinding(RuleNoControls).Warning().Build())

	got := a.Error()
	// Should contain counts and first finding summary.
	if got == "" {
		t.Fatal("Error() should not be empty")
	}
	// Check counts.
	wantPrefix := "security assessment failed: 1 errors, 1 warnings"
	if len(got) < len(wantPrefix) || got[:len(wantPrefix)] != wantPrefix {
		t.Fatalf("Error()=%q, want prefix %q", got, wantPrefix)
	}
}

func TestAssessment_Error_FirstFindingSummary_MessageAndPath(t *testing.T) {
	a := NewAssessment()
	a.Record(NewFinding(RuleSchemaViolation).Error().Message("missing field").Attribute("path", "/version").Build())
	got := a.Error()
	// Should contain "missing field (/version)"
	if got == "" {
		t.Fatal("empty")
	}
	want := "security assessment failed: 1 errors, 0 warnings | First Finding: missing field (/version)"
	if got != want {
		t.Fatalf("Error()=%q, want %q", got, want)
	}
}

func TestAssessment_Error_FirstFindingSummary_MessageOnly(t *testing.T) {
	a := NewAssessment()
	a.Record(NewFinding(RuleSchemaViolation).Error().Message("something wrong").Build())
	got := a.Error()
	want := "security assessment failed: 1 errors, 0 warnings | First Finding: something wrong"
	if got != want {
		t.Fatalf("Error()=%q, want %q", got, want)
	}
}

func TestAssessment_Error_FirstFindingSummary_PathOnly(t *testing.T) {
	a := NewAssessment()
	a.Record(NewFinding(RuleSchemaViolation).Error().Attribute("path", "/foo").Build())
	got := a.Error()
	want := "security assessment failed: 1 errors, 0 warnings | First Finding: /foo"
	if got != want {
		t.Fatalf("Error()=%q, want %q", got, want)
	}
}

func TestAssessment_Error_FirstFindingSummary_RuleIDOnly(t *testing.T) {
	a := NewAssessment()
	a.Record(NewFinding(RuleSchemaViolation).Error().Build())
	got := a.Error()
	want := "security assessment failed: 1 errors, 0 warnings | First Finding: SCHEMA_VIOLATION"
	if got != want {
		t.Fatalf("Error()=%q, want %q", got, want)
	}
}
