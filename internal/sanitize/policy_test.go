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

	fullSan := Policy{SanitizeIDs: true, PathMode: PathFull}.NewSanitizer()
	msg := "cannot read /home/user/data/obs.json: no such file"
	if got := fullSan.ScrubMessage(msg); got != msg {
		t.Errorf("ScrubMessage() with PathFull should be no-op, got %q", got)
	}
}
