package sanitize

import (
	"testing"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/platform/crypto"
)

func TestToken_Deterministic(t *testing.T) {
	a := crypto.ShortToken("my-bucket")
	b := crypto.ShortToken("my-bucket")
	if a != b {
		t.Errorf("token not deterministic: %q != %q", a, b)
	}
	if len(a) != 16 {
		t.Errorf("token length = %d, want 16", len(a))
	}
}

func TestToken_DifferentInputs(t *testing.T) {
	a := crypto.ShortToken("bucket-a")
	b := crypto.ShortToken("bucket-b")
	if a == b {
		t.Errorf("different inputs produced same token: %q", a)
	}
}

func TestResourceID_Plain(t *testing.T) {
	r := New(WithIDSanitization(true))
	got := r.Asset("my-bucket")
	want := asset.ID("SANITIZED_" + crypto.ShortToken("my-bucket"))
	if got != want {
		t.Errorf("AssetID(%q) = %q, want %q", "my-bucket", got, want)
	}
}

func TestResourceID_ARN(t *testing.T) {
	r := New(WithIDSanitization(true))
	got := r.Asset("arn:aws:s3:::my-bucket")
	want := asset.ID("arn:aws:s3:::SANITIZED_" + crypto.ShortToken("my-bucket"))
	if got != want {
		t.Errorf("AssetID(ARN) = %q, want %q", got, want)
	}
}

func TestResourceID_ARN_WithPath(t *testing.T) {
	r := New(WithIDSanitization(true))
	got := r.Asset("arn:aws:s3:::my-bucket/some/key")
	want := asset.ID("arn:aws:s3:::SANITIZED_" + crypto.ShortToken("my-bucket") + "/some/key")
	if got != want {
		t.Errorf("AssetID(ARN with path) = %q, want %q", got, want)
	}
}

func TestValue(t *testing.T) {
	r := New(WithIDSanitization(true))
	got := r.Value("sensitive-data")
	want := "SANITIZED_" + crypto.ShortToken("sensitive-data")
	if got != want {
		t.Errorf("Value() = %q, want %q", got, want)
	}
	// Distinct inputs must produce distinct redacted tokens.
	if r.Value("a") == r.Value("b") {
		t.Error("Value() collapsed distinct inputs to the same token")
	}
}

func TestPath(t *testing.T) {
	r := New(WithIDSanitization(true))
	if got := r.Path("/home/user/data/obs.json"); got != "obs.json" {
		t.Errorf("Path() = %q, want obs.json", got)
	}
}

// Compile-time check that Sanitizer implements kernel.Sanitizer.
var _ kernel.Sanitizer = (*Sanitizer)(nil)

// TestScrubMap_NestedRemoveBeneathSanitize pins that nested Remove
// rules apply even when reached through a Sanitize-flagged parent.
// Earlier shape called s.scrubValue (empty profile) for Sanitize
// keys, dropping the profile context, so a Remove key inside the
// flagged subtree leaked through.
func TestScrubMap_NestedRemoveBeneathSanitize(t *testing.T) {
	prof := NewProfile(
		map[string]struct{}{"tags": {}},      // remove "tags" anywhere
		map[string]struct{}{"bucket_meta": {}}, // sanitize the parent
	)
	s := New(WithIDSanitization(true))
	in := map[string]any{
		"bucket_meta": map[string]any{
			"name": "shared-bucket",
			"tags": map[string]any{"owner": "alice"},
		},
	}
	out := s.ScrubMap(in, prof)
	meta, ok := out["bucket_meta"].(map[string]any)
	if !ok {
		t.Fatalf("bucket_meta missing or wrong shape: %#v", out["bucket_meta"])
	}
	if _, present := meta["tags"]; present {
		t.Errorf("tags key must be removed under a sanitize-flagged parent; got %#v", meta)
	}
}
