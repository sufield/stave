package doctor

import (
	"testing"

	"github.com/sufield/stave/internal/core/outcome"
)

func TestCheck_IsFail(t *testing.T) {
	tests := []struct {
		status outcome.Status
		want   bool
	}{
		{outcome.Pass, false},
		{outcome.Warn, false},
		{outcome.Fail, true},
	}
	for _, tt := range tests {
		c := Diagnostic{Status: tt.status}
		if c.IsFailure() != tt.want {
			t.Errorf("Diagnostic{Status: %q}.IsFailure() = %v, want %v", tt.status, c.IsFailure(), tt.want)
		}
	}
}

func TestCheck_String(t *testing.T) {
	c := Diagnostic{Name: "test", Status: outcome.Pass, Message: "ok"}
	got := c.String()
	want := "[PASS] test: ok"
	if got != want {
		t.Errorf("Diagnostic.String() = %q, want %q", got, want)
	}
}

func TestRegistry_Run_NilRegistry(t *testing.T) {
	var r *DiagnosticSuite
	checks, ok := r.Execute(nil)
	if !ok {
		t.Error("nil registry should return success=true")
	}
	if len(checks) != 0 {
		t.Errorf("nil registry should return 0 checks, got %d", len(checks))
	}
}

func TestRegistry_Run_EmptyRegistry(t *testing.T) {
	r := NewSuite()
	checks, ok := r.Execute(nil)
	if !ok {
		t.Error("empty registry should return success=true")
	}
	if len(checks) != 0 {
		t.Errorf("empty registry should return 0 checks, got %d", len(checks))
	}
}

func TestRegistry_Run_AllPass(t *testing.T) {
	r := NewSuite(
		func(*SystemEnvironment) Diagnostic { return Diagnostic{Name: "a", Status: outcome.Pass, Message: "ok"} },
		func(*SystemEnvironment) Diagnostic {
			return Diagnostic{Name: "b", Status: outcome.Warn, Message: "warning"}
		},
	)
	checks, ok := r.Execute(nil)
	if !ok {
		t.Error("no FAIL checks should return success=true")
	}
	if len(checks) != 2 {
		t.Errorf("expected 2 checks, got %d", len(checks))
	}
}

func TestRegistry_Run_SkipsEmptyName(t *testing.T) {
	r := NewSuite(
		func(*SystemEnvironment) Diagnostic { return Diagnostic{} }, // empty name, should be skipped
		func(*SystemEnvironment) Diagnostic { return Diagnostic{Name: "a", Status: outcome.Pass} },
	)
	checks, _ := r.Execute(nil)
	if len(checks) != 1 {
		t.Errorf("expected 1 check (skipping empty), got %d", len(checks))
	}
}

func TestFillDefaults_Nil(_ *testing.T) {
	var ctx *SystemEnvironment
	ctx.FillDefaults() // should not panic
}

func TestFillDefaults_SetsFields(t *testing.T) {
	ctx := &SystemEnvironment{}
	ctx.FillDefaults()
	if ctx.PathLookupFn == nil {
		t.Error("expected LookPathFn to be set")
	}
	if ctx.EnvVarFn == nil {
		t.Error("expected GetenvFn to be set")
	}
	if ctx.OS == "" {
		t.Error("expected Goos to be set")
	}
	if ctx.Arch == "" {
		t.Error("expected Goarch to be set")
	}
	if ctx.Runtime == "" {
		t.Error("expected GoVersion to be set")
	}
}

func TestFillDefaults_PreservesExistingValues(t *testing.T) {
	ctx := &SystemEnvironment{
		OS:   "custom",
		Arch: "arm",
	}
	ctx.FillDefaults()
	if ctx.OS != "custom" {
		t.Errorf("Goos = %q, want custom", ctx.OS)
	}
	if ctx.Arch != "arm" {
		t.Errorf("Goarch = %q, want arm", ctx.Arch)
	}
}

func TestStandardChecks_Length(t *testing.T) {
	checks := StandardChecks()
	if len(checks) == 0 {
		t.Fatal("StandardChecks should return at least one check")
	}
	// Verify it has a reasonable number of checks
	if len(checks) < 10 {
		t.Errorf("StandardChecks returned %d, expected >= 10", len(checks))
	}
}

func TestExtractXMLTag(t *testing.T) {
	val, ok := extractXMLTag("<string>1.2.3</string>", "string")
	if !ok || val != "1.2.3" {
		t.Errorf("extractXMLTag() = (%q, %v)", val, ok)
	}

	_, ok = extractXMLTag("no tags here", "string")
	if ok {
		t.Error("expected false for missing tag")
	}

	_, ok = extractXMLTag("<string>unclosed", "string")
	if ok {
		t.Error("expected false for unclosed tag")
	}
}
