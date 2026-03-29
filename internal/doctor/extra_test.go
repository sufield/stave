package doctor

import (
	"testing"
)

func TestCheck_IsFail(t *testing.T) {
	tests := []struct {
		status Status
		want   bool
	}{
		{StatusPass, false},
		{StatusWarn, false},
		{StatusFail, true},
	}
	for _, tt := range tests {
		c := Check{Status: tt.status}
		if c.IsFail() != tt.want {
			t.Errorf("Check{Status: %q}.IsFail() = %v, want %v", tt.status, c.IsFail(), tt.want)
		}
	}
}

func TestCheck_String(t *testing.T) {
	c := Check{Name: "test", Status: StatusPass, Message: "ok"}
	got := c.String()
	want := "[PASS] test: ok"
	if got != want {
		t.Errorf("Check.String() = %q, want %q", got, want)
	}
}

func TestRegistry_Run_NilRegistry(t *testing.T) {
	var r *Registry
	checks, ok := r.Run(nil)
	if !ok {
		t.Error("nil registry should return success=true")
	}
	if len(checks) != 0 {
		t.Errorf("nil registry should return 0 checks, got %d", len(checks))
	}
}

func TestRegistry_Run_EmptyRegistry(t *testing.T) {
	r := NewRegistry()
	checks, ok := r.Run(nil)
	if !ok {
		t.Error("empty registry should return success=true")
	}
	if len(checks) != 0 {
		t.Errorf("empty registry should return 0 checks, got %d", len(checks))
	}
}

func TestRegistry_Run_AllPass(t *testing.T) {
	r := NewRegistry(
		func(*Context) Check { return Check{Name: "a", Status: StatusPass, Message: "ok"} },
		func(*Context) Check { return Check{Name: "b", Status: StatusWarn, Message: "warning"} },
	)
	checks, ok := r.Run(nil)
	if !ok {
		t.Error("no FAIL checks should return success=true")
	}
	if len(checks) != 2 {
		t.Errorf("expected 2 checks, got %d", len(checks))
	}
}

func TestRegistry_Run_SkipsEmptyName(t *testing.T) {
	r := NewRegistry(
		func(*Context) Check { return Check{} }, // empty name, should be skipped
		func(*Context) Check { return Check{Name: "a", Status: StatusPass} },
	)
	checks, _ := r.Run(nil)
	if len(checks) != 1 {
		t.Errorf("expected 1 check (skipping empty), got %d", len(checks))
	}
}

func TestFillDefaults_Nil(t *testing.T) {
	var ctx *Context
	ctx.FillDefaults() // should not panic
}

func TestFillDefaults_SetsFields(t *testing.T) {
	ctx := &Context{}
	ctx.FillDefaults()
	if ctx.LookPathFn == nil {
		t.Error("expected LookPathFn to be set")
	}
	if ctx.GetenvFn == nil {
		t.Error("expected GetenvFn to be set")
	}
	if ctx.Goos == "" {
		t.Error("expected Goos to be set")
	}
	if ctx.Goarch == "" {
		t.Error("expected Goarch to be set")
	}
	if ctx.GoVersion == "" {
		t.Error("expected GoVersion to be set")
	}
}

func TestFillDefaults_PreservesExistingValues(t *testing.T) {
	ctx := &Context{
		Goos:   "custom",
		Goarch: "arm",
	}
	ctx.FillDefaults()
	if ctx.Goos != "custom" {
		t.Errorf("Goos = %q, want custom", ctx.Goos)
	}
	if ctx.Goarch != "arm" {
		t.Errorf("Goarch = %q, want arm", ctx.Goarch)
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
