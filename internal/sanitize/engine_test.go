package sanitize

import (
	"testing"

	"github.com/sufield/stave/internal/platform/crypto"
	"github.com/sufield/stave/pkg/alpha/domain/asset"
	"github.com/sufield/stave/pkg/alpha/domain/kernel"
)

func TestToken_Deterministic(t *testing.T) {
	a := crypto.ShortToken("my-bucket")
	b := crypto.ShortToken("my-bucket")
	if a != b {
		t.Errorf("token not deterministic: %q != %q", a, b)
	}
	if len(a) != 8 {
		t.Errorf("token length = %d, want 8", len(a))
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
	if got := r.Value("sensitive-data"); got != "[SANITIZED]" {
		t.Errorf("Value() = %q, want [SANITIZED]", got)
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
