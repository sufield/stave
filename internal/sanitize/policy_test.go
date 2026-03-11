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

func TestSanitizer_PathRespectsMode(t *testing.T) {
	baseSan := OutputSanitizationPolicy{SanitizeIDs: true, PathMode: PathModeBase}.Sanitizer()
	if got := baseSan.Path("/home/user/data/obs.json"); got != "obs.json" {
		t.Errorf("Path() with PathModeBase = %q, want obs.json", got)
	}

	fullSan := OutputSanitizationPolicy{SanitizeIDs: true, PathMode: PathModeFull}.Sanitizer()
	if got := fullSan.Path("/home/user/data/obs.json"); got != "/home/user/data/obs.json" {
		t.Errorf("Path() with PathModeFull = %q, want full path", got)
	}
}

func TestSanitizer_ScrubMessage(t *testing.T) {
	baseSan := OutputSanitizationPolicy{SanitizeIDs: true, PathMode: PathModeBase}.Sanitizer()
	got := baseSan.ScrubMessage("cannot read /home/user/data/obs.json: no such file")
	if got != "cannot read obs.json: no such file" {
		t.Errorf("ScrubMessage() with PathModeBase = %q", got)
	}

	fullSan := OutputSanitizationPolicy{SanitizeIDs: true, PathMode: PathModeFull}.Sanitizer()
	msg := "cannot read /home/user/data/obs.json: no such file"
	if got := fullSan.ScrubMessage(msg); got != msg {
		t.Errorf("ScrubMessage() with PathModeFull should be no-op, got %q", got)
	}
}
