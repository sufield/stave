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
	// Output preserves the leading "/" so the scrubbed message
	// reads grammatically: "cannot read /[BASENAME]:" rather than
	// "cannot read [BASENAME]:" which loses the absolute-path
	// signal.
	baseSan := Policy{SanitizeIDs: true, PathMode: PathBase}.NewSanitizer()
	got := baseSan.ScrubMessage("cannot read /home/user/data/obs.json: no such file")
	if got != "cannot read /obs.json: no such file" {
		t.Errorf("ScrubMessage() with PathBase = %q", got)
	}

	// Per Phase 13 P13.4.1: PathMode no longer gates message
	// scrubbing. PathFull is about output path rendering; it does
	// not control whether credential-style paths in error messages
	// get reduced to their basename. The previous coupling let
	// secrets like `/secret/token` slip through whenever
	// `--path-mode=full` was set for unrelated reasons.
	fullSan := Policy{SanitizeIDs: true, PathMode: PathFull}.NewSanitizer()
	if got := fullSan.ScrubMessage("cannot read /home/user/data/obs.json: no such file"); got != "cannot read /obs.json: no such file" {
		t.Errorf("ScrubMessage() should always scrub credential paths regardless of PathMode; got %q", got)
	}
}

// TestSanitizer_ScrubMessage_PreservesURLs pins that URL paths are
// not eaten by the path-scrubbing regex. The earlier shape collapsed
// `http://example.com/secret` to `http://example.comsecret` because
// the leading-slash rule matched the URL's first path slash and
// consumed it during basename replacement.
func TestSanitizer_ScrubMessage_PreservesURLs(t *testing.T) {
	s := Policy{SanitizeIDs: true, PathMode: PathBase}.NewSanitizer()
	cases := []struct {
		in   string
		want string
	}{
		{"failed to fetch http://example.com/secret",
			"failed to fetch http://example.com/secret"},
		{"upload to https://bucket.s3.amazonaws.com/data/x.json",
			"upload to https://bucket.s3.amazonaws.com/data/x.json"},
		// Path-and-URL mixed: URL preserved, file path scrubbed
		// (leading "/" preserved on the basename to keep the
		// absolute-path signal in the error string).
		{"cannot reach http://example.com/x: open /home/u/data: denied",
			"cannot reach http://example.com/x: open /data: denied"},
	}
	for _, tc := range cases {
		got := s.ScrubMessage(tc.in)
		if got != tc.want {
			t.Errorf("ScrubMessage(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestSanitizer_ScrubMessage_SingleComponentPath(t *testing.T) {
	// Single-component absolute paths (e.g. `/secret`) reach the
	// basename branch but `/`+basename equals the original — so the
	// substitution would round-trip the leaked filename verbatim.
	// The branch detects that and emits `/<redacted>` instead. CI
	// runners that mount secret-token files at the root surface
	// them in error messages exactly this way.
	baseSan := Policy{SanitizeIDs: true, PathMode: PathBase}.NewSanitizer()
	cases := []struct {
		in   string
		want string
	}{
		{"cannot read /secret: permission denied", "cannot read /<redacted>: permission denied"},
		{"open /token failed", "open /<redacted> failed"},
		{"existing /home/user/data/obs.json untouched", "existing /obs.json untouched"},
		{"empty path / not collapsed", "empty path / not collapsed"}, // bare slash, no basename
	}
	for _, tc := range cases {
		got := baseSan.ScrubMessage(tc.in)
		if got != tc.want {
			t.Errorf("ScrubMessage(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestSanitizer_ScrubMessage_TrailingSlashPath pins the trailing-slash
// alternation. Mount-point and container-volume paths surface in error
// messages with a trailing `/` (`/run/secrets/`, `/var/run/keys/`) and
// the earlier regex left them untouched because the non-slash-terminal
// branch was leftmost-first and consumed the prefix without the
// trailing slash.
func TestSanitizer_ScrubMessage_TrailingSlashPath(t *testing.T) {
	s := Policy{SanitizeIDs: true, PathMode: PathBase}.NewSanitizer()
	cases := []struct {
		in   string
		want string
	}{
		{"failed to read /run/secrets/", "failed to read /secrets/"},
		{"mount: /var/run/keys/ is read-only", "mount: /keys/ is read-only"},
		// Confirm the non-trailing-slash variant still matches via
		// the basename branch.
		{"open /run/secrets/token", "open /token"},
	}
	for _, tc := range cases {
		got := s.ScrubMessage(tc.in)
		if got != tc.want {
			t.Errorf("ScrubMessage(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
