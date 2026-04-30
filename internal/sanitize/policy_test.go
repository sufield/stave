package sanitize

import "testing"

func TestPolicy_NewSanitizer(t *testing.T) {
	p := Policy{SanitizeIDs: true}
	if p.NewSanitizer() == nil {
		t.Error("NewSanitizer() should return non-nil when SanitizeIDs is true")
	}

	p2 := Policy{SanitizeIDs: false}
	r := p2.NewSanitizer()
	if r == nil {
		t.Error("NewSanitizer() should return non-nil no-op sanitizer when SanitizeIDs is false")
	}
	if got := r.Asset("my-bucket"); got != "my-bucket" {
		t.Errorf("no-op sanitizer should preserve resource ID, got %q", got)
	}
}

func TestSanitizer_PathRespectsMode(t *testing.T) {
	baseSan := Policy{SanitizeIDs: true, PathMode: PathBase}.NewSanitizer()
	if got := baseSan.Path("/home/user/data/obs.json"); got != "obs.json" {
		t.Errorf("Path() with PathBase = %q, want obs.json", got)
	}

	fullSan := Policy{SanitizeIDs: true, PathMode: PathFull}.NewSanitizer()
	if got := fullSan.Path("/home/user/data/obs.json"); got != "/home/user/data/obs.json" {
		t.Errorf("Path() with PathFull = %q, want full path", got)
	}
}

func TestSanitizer_ScrubMessage(t *testing.T) {
	baseSan := Policy{SanitizeIDs: true, PathMode: PathBase}.NewSanitizer()
	got := baseSan.ScrubMessage("cannot read /home/user/data/obs.json: no such file")
	if got != "cannot read obs.json: no such file" {
		t.Errorf("ScrubMessage() with PathBase = %q", got)
	}

	// Per Phase 13 P13.4.1: PathMode no longer gates message
	// scrubbing. PathFull is about output path rendering; it does
	// not control whether credential-style paths in error messages
	// get reduced to their basename. The previous coupling let
	// secrets like `/secret/token` slip through whenever
	// `--path-mode=full` was set for unrelated reasons.
	fullSan := Policy{SanitizeIDs: true, PathMode: PathFull}.NewSanitizer()
	if got := fullSan.ScrubMessage("cannot read /home/user/data/obs.json: no such file"); got != "cannot read obs.json: no such file" {
		t.Errorf("ScrubMessage() should always scrub credential paths regardless of PathMode; got %q", got)
	}
}

func TestSanitizer_ScrubMessage_SingleComponentPath(t *testing.T) {
	// Single-component absolute paths (e.g. `/secret`) used to slip
	// through because the regex required at least one intermediate
	// directory. CI runners that mount secret-token files at the
	// root surface them in error messages exactly this way.
	baseSan := Policy{SanitizeIDs: true, PathMode: PathBase}.NewSanitizer()
	cases := []struct {
		in   string
		want string
	}{
		{"cannot read /secret: permission denied", "cannot read secret: permission denied"},
		{"open /token failed", "open token failed"},
		{"existing /home/user/data/obs.json untouched", "existing obs.json untouched"},
		{"empty path / not collapsed", "empty path / not collapsed"}, // bare slash, no basename
	}
	for _, tc := range cases {
		got := baseSan.ScrubMessage(tc.in)
		if got != tc.want {
			t.Errorf("ScrubMessage(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
