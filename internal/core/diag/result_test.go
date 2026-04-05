package diag

import "testing"

func TestNewResult_Empty(t *testing.T) {
	r := NewResult()
	if r == nil {
		t.Fatal("NewResult returned nil")
	}
	if len(r.Issues) != 0 {
		t.Fatalf("new result has %d issues, want 0", len(r.Issues))
	}
}

func TestResult_Add(t *testing.T) {
	r := NewResult()
	r.Add(New(CodeSchemaViolation).Error().Msg("bad schema").Build())
	if len(r.Issues) != 1 {
		t.Fatalf("after Add: len=%d, want 1", len(r.Issues))
	}
}

func TestResult_Add_NilReceiver(t *testing.T) {
	var r *Report
	// Should not panic.
	r.Add(New(CodeSchemaViolation).Build())
}

func TestResult_AddAll(t *testing.T) {
	r := NewResult()
	issues := []Diagnostic{
		New(CodeSchemaViolation).Error().Build(),
		New(CodeNoControls).Warning().Build(),
	}
	r.AddAll(issues)
	if len(r.Issues) != 2 {
		t.Fatalf("after AddAll: len=%d, want 2", len(r.Issues))
	}
}

func TestResult_AddAll_NilReceiver(t *testing.T) {
	var r *Report
	r.AddAll([]Diagnostic{New(CodeSchemaViolation).Build()})
}

func TestResult_AddAll_EmptySlice(t *testing.T) {
	r := NewResult()
	r.AddAll(nil)
	if len(r.Issues) != 0 {
		t.Fatalf("after AddAll(nil): len=%d, want 0", len(r.Issues))
	}
}

func TestResult_Merge(t *testing.T) {
	r1 := NewResult()
	r1.Add(New(CodeSchemaViolation).Error().Build())
	r2 := NewResult()
	r2.Add(New(CodeNoControls).Warning().Build())
	r2.Add(New(CodeNoSnapshots).Warning().Build())

	r1.Merge(r2)
	if len(r1.Issues) != 3 {
		t.Fatalf("after Merge: len=%d, want 3", len(r1.Issues))
	}
}

func TestResult_Merge_NilReceiver(t *testing.T) {
	var r *Report
	other := NewResult()
	other.Add(New(CodeSchemaViolation).Build())
	r.Merge(other) // Should not panic.
}

func TestResult_Merge_NilOther(t *testing.T) {
	r := NewResult()
	r.Add(New(CodeSchemaViolation).Build())
	r.Merge(nil)
	if len(r.Issues) != 1 {
		t.Fatalf("after Merge(nil): len=%d, want 1", len(r.Issues))
	}
}

func TestResult_Merge_EmptyOther(t *testing.T) {
	r := NewResult()
	r.Add(New(CodeSchemaViolation).Build())
	r.Merge(NewResult())
	if len(r.Issues) != 1 {
		t.Fatalf("after Merge(empty): len=%d, want 1", len(r.Issues))
	}
}

func TestResult_HasErrors(t *testing.T) {
	tests := []struct {
		name   string
		issues []Diagnostic
		want   bool
	}{
		{"no issues", nil, false},
		{"warning only", []Diagnostic{New(CodeNoControls).Warning().Build()}, false},
		{"error present", []Diagnostic{New(CodeSchemaViolation).Error().Build()}, true},
		{"mixed", []Diagnostic{
			New(CodeNoControls).Warning().Build(),
			New(CodeSchemaViolation).Error().Build(),
		}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewResult()
			r.AddAll(tt.issues)
			if got := r.HasErrors(); got != tt.want {
				t.Fatalf("HasErrors()=%v, want %v", got, tt.want)
			}
		})
	}
}

func TestResult_HasErrors_NilReceiver(t *testing.T) {
	var r *Report
	if r.HasErrors() {
		t.Fatal("nil receiver HasErrors should return false")
	}
}

func TestResult_HasWarnings(t *testing.T) {
	tests := []struct {
		name   string
		issues []Diagnostic
		want   bool
	}{
		{"no issues", nil, false},
		{"error only", []Diagnostic{New(CodeSchemaViolation).Error().Build()}, false},
		{"warning present", []Diagnostic{New(CodeNoControls).Warning().Build()}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewResult()
			r.AddAll(tt.issues)
			if got := r.HasWarnings(); got != tt.want {
				t.Fatalf("HasWarnings()=%v, want %v", got, tt.want)
			}
		})
	}
}

func TestResult_HasWarnings_NilReceiver(t *testing.T) {
	var r *Report
	if r.HasWarnings() {
		t.Fatal("nil receiver HasWarnings should return false")
	}
}

func TestResult_Errors(t *testing.T) {
	r := NewResult()
	r.Add(New(CodeSchemaViolation).Error().Build())
	r.Add(New(CodeNoControls).Warning().Build())
	r.Add(New(CodeControlLoadFailed).Error().Build())

	errs := r.Errors()
	if len(errs) != 2 {
		t.Fatalf("Errors() len=%d, want 2", len(errs))
	}
	for _, e := range errs {
		if e.Signal != SignalError {
			t.Fatalf("Errors() returned signal=%q", e.Signal)
		}
	}
}

func TestResult_Warnings(t *testing.T) {
	r := NewResult()
	r.Add(New(CodeSchemaViolation).Error().Build())
	r.Add(New(CodeNoControls).Warning().Build())

	warns := r.Warnings()
	if len(warns) != 1 {
		t.Fatalf("Warnings() len=%d, want 1", len(warns))
	}
	if warns[0].Signal != SignalWarn {
		t.Fatalf("Warnings() returned signal=%q", warns[0].Signal)
	}
}

func TestResult_Filter_NilReceiver(t *testing.T) {
	var r *Report
	if errs := r.Errors(); errs != nil {
		t.Fatalf("nil receiver Errors() should return nil, got %v", errs)
	}
	if warns := r.Warnings(); warns != nil {
		t.Fatalf("nil receiver Warnings() should return nil, got %v", warns)
	}
}

func TestResult_Error_NoIssues(t *testing.T) {
	r := NewResult()
	got := r.Error()
	want := "validation failed: 0 errors, 0 warnings"
	if got != want {
		t.Fatalf("Error()=%q, want %q", got, want)
	}
}

func TestResult_Error_NilReceiver(t *testing.T) {
	var r *Report
	got := r.Error()
	want := "validation failed: 0 errors, 0 warnings"
	if got != want {
		t.Fatalf("Error()=%q, want %q", got, want)
	}
}

func TestResult_Error_WithIssues(t *testing.T) {
	r := NewResult()
	r.Add(New(CodeSchemaViolation).Error().Msg("bad field").With("path", "/dsl_version").Build())
	r.Add(New(CodeNoControls).Warning().Build())

	got := r.Error()
	// Should contain counts and first issue summary.
	if got == "" {
		t.Fatal("Error() should not be empty")
	}
	// Check counts.
	wantPrefix := "validation failed: 1 errors, 1 warnings"
	if len(got) < len(wantPrefix) || got[:len(wantPrefix)] != wantPrefix {
		t.Fatalf("Error()=%q, want prefix %q", got, wantPrefix)
	}
}

func TestResult_Error_FirstIssueSummary_MessageAndPath(t *testing.T) {
	r := NewResult()
	r.Add(New(CodeSchemaViolation).Error().Msg("missing field").With("path", "/version").Build())
	got := r.Error()
	// Should contain "missing field (/version)"
	if got == "" {
		t.Fatal("empty")
	}
	want := "validation failed: 1 errors, 0 warnings: missing field (/version)"
	if got != want {
		t.Fatalf("Error()=%q, want %q", got, want)
	}
}

func TestResult_Error_FirstIssueSummary_MessageOnly(t *testing.T) {
	r := NewResult()
	r.Add(New(CodeSchemaViolation).Error().Msg("something wrong").Build())
	got := r.Error()
	want := "validation failed: 1 errors, 0 warnings: something wrong"
	if got != want {
		t.Fatalf("Error()=%q, want %q", got, want)
	}
}

func TestResult_Error_FirstIssueSummary_PathOnly(t *testing.T) {
	r := NewResult()
	r.Add(New(CodeSchemaViolation).Error().With("path", "/foo").Build())
	got := r.Error()
	want := "validation failed: 1 errors, 0 warnings: /foo"
	if got != want {
		t.Fatalf("Error()=%q, want %q", got, want)
	}
}

func TestResult_Error_FirstIssueSummary_CodeOnly(t *testing.T) {
	r := NewResult()
	r.Add(New(CodeSchemaViolation).Error().Build())
	got := r.Error()
	want := "validation failed: 1 errors, 0 warnings: SCHEMA_VIOLATION"
	if got != want {
		t.Fatalf("Error()=%q, want %q", got, want)
	}
}
