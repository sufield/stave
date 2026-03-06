package sanitize

import "testing"

func TestParsePathMode(t *testing.T) {
	tests := []struct {
		input string
		want  PathMode
	}{
		{"base", PathModeBase},
		{"full", PathModeFull},
		{" FULL ", PathModeFull},
		{"", PathModeBase},
		{"other", PathModeBase},
	}
	for _, tt := range tests {
		got := ParsePathMode(tt.input)
		if got != tt.want {
			t.Errorf("ParsePathMode(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestOutputSanitizationPolicy_Sanitizer(t *testing.T) {
	p := OutputSanitizationPolicy{SanitizeIDs: true}
	if p.Sanitizer() == nil {
		t.Error("Sanitizer() should return non-nil when SanitizeIDs is true")
	}

	p2 := OutputSanitizationPolicy{SanitizeIDs: false}
	r := p2.Sanitizer()
	if r == nil {
		t.Error("Sanitizer() should return non-nil no-op sanitizer when SanitizeIDs is false")
	}
	if got := r.Asset("my-bucket"); got != "my-bucket" {
		t.Errorf("no-op sanitizer should preserve resource ID, got %q", got)
	}
}

func TestOutputSanitizationPolicy_ShouldSanitizePaths(t *testing.T) {
	base := OutputSanitizationPolicy{PathMode: PathModeBase}
	if !base.ShouldSanitizePaths() {
		t.Error("ShouldSanitizePaths() should be true for PathModeBase")
	}

	full := OutputSanitizationPolicy{PathMode: PathModeFull}
	if full.ShouldSanitizePaths() {
		t.Error("ShouldSanitizePaths() should be false for PathModeFull")
	}
}
