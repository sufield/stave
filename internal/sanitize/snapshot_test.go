package sanitize

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/platform/crypto"
)

// --- Profile tests ---

func TestProfile_ShouldRemove(t *testing.T) {
	p := Profile{
		Remove: map[string]struct{}{"tags": {}, "policy": {}},
	}
	if !p.ShouldRemove("tags") {
		t.Error("ShouldRemove(tags) should return true")
	}
	if !p.ShouldRemove("policy") {
		t.Error("ShouldRemove(policy) should return true")
	}
	if p.ShouldRemove("bucket_name") {
		t.Error("ShouldRemove(bucket_name) should return false")
	}
}

func TestProfile_ShouldRemove_NilMap(t *testing.T) {
	p := Profile{Remove: nil}
	if p.ShouldRemove("tags") {
		t.Error("nil Remove map should return false")
	}
}

func TestProfile_ShouldSanitize(t *testing.T) {
	p := Profile{
		Sanitize: map[string]struct{}{"bucket_name": {}},
	}
	if !p.ShouldSanitize("bucket_name") {
		t.Error("ShouldSanitize(bucket_name) should return true")
	}
	if p.ShouldSanitize("tags") {
		t.Error("ShouldSanitize(tags) should return false")
	}
}

func TestProfile_ShouldSanitize_NilMap(t *testing.T) {
	p := Profile{Sanitize: nil}
	if p.ShouldSanitize("bucket_name") {
		t.Error("nil Sanitize map should return false")
	}
}

func TestAssetProfile_Keys(t *testing.T) {
	p := AssetProfile()
	removeKeys := []string{"tags", "policy", "policy_json", "policy_public_statements", "acl_grants", "acl_public_grantees"}
	for _, k := range removeKeys {
		if !p.ShouldRemove(k) {
			t.Errorf("AssetProfile should remove key %q", k)
		}
	}
	sanitizeKeys := []string{"bucket_name", "external_id"}
	for _, k := range sanitizeKeys {
		if !p.ShouldSanitize(k) {
			t.Errorf("AssetProfile should sanitize key %q", k)
		}
	}
}

func TestAssetProfile_ReturnsCopy(t *testing.T) {
	p1 := AssetProfile()
	p2 := AssetProfile()
	// Mutating one should not affect the other.
	p1.Remove["injected"] = struct{}{}
	if p2.ShouldRemove("injected") {
		t.Error("AssetProfile should return independent copies")
	}
}

func TestIdentityProfile_Keys(t *testing.T) {
	p := IdentityProfile()
	if !p.ShouldRemove("owner") {
		t.Error("IdentityProfile should remove 'owner'")
	}
	if !p.ShouldRemove("purpose") {
		t.Error("IdentityProfile should remove 'purpose'")
	}
	if p.ShouldRemove("bucket_name") {
		t.Error("IdentityProfile should not remove 'bucket_name'")
	}
}

// --- ScrubMap tests ---

func TestScrubMap_NilProps(t *testing.T) {
	s := New(WithIDSanitization(true))
	result := s.ScrubMap(nil, AssetProfile())
	if result != nil {
		t.Error("ScrubMap(nil) should return nil")
	}
}

func TestScrubMap_RemovesKeys(t *testing.T) {
	s := New(WithIDSanitization(true))
	props := map[string]any{
		"tags":        []string{"env:prod"},
		"policy":      `{"Version":"2012"}`,
		"bucket_name": "my-secret-bucket",
		"versioning":  true,
	}
	result := s.ScrubMap(props, AssetProfile())
	if _, ok := result["tags"]; ok {
		t.Error("tags should be removed")
	}
	if _, ok := result["policy"]; ok {
		t.Error("policy should be removed")
	}
	if _, ok := result["versioning"]; !ok {
		t.Error("versioning should be kept")
	}
}

func TestScrubMap_SanitizesKeys(t *testing.T) {
	s := New(WithIDSanitization(true))
	props := map[string]any{
		"bucket_name": "my-secret-bucket",
	}
	result := s.ScrubMap(props, AssetProfile())
	got, ok := result["bucket_name"]
	if !ok {
		t.Fatal("bucket_name should still be present after sanitize")
	}
	// Should be sanitized, not the original value.
	if got == "my-secret-bucket" {
		t.Error("bucket_name should have been sanitized")
	}
}

func TestScrubMap_SanitizesNonStringValue(t *testing.T) {
	s := New(WithIDSanitization(true))
	// A non-string value that needs sanitizing becomes "[SANITIZED]".
	props := map[string]any{
		"bucket_name": 12345, // non-string
	}
	result := s.ScrubMap(props, AssetProfile())
	if got, ok := result["bucket_name"]; !ok || got != "[SANITIZED]" {
		t.Errorf("non-string sanitize value = %v, want [SANITIZED]", got)
	}
}

func TestScrubMap_RecursesNestedMap(t *testing.T) {
	s := New(WithIDSanitization(true))
	p := Profile{
		Remove: map[string]struct{}{"secret": {}},
	}
	props := map[string]any{
		"nested": map[string]any{
			"secret":  "should-be-gone",
			"visible": "keep-me",
		},
	}
	result := s.ScrubMap(props, p)
	nested, ok := result["nested"].(map[string]any)
	if !ok {
		t.Fatal("nested map should be preserved")
	}
	if _, ok := nested["secret"]; ok {
		t.Error("nested secret should be removed")
	}
	if _, ok := nested["visible"]; !ok {
		t.Error("nested visible key should be kept")
	}
}

// --- Snapshot tests ---

func TestSanitizer_Snapshot_NilSanitizer(t *testing.T) {
	var s *Sanitizer
	snap := asset.Snapshot{
		SchemaVersion: kernel.Schema("obs.v1"),
		CapturedAt:    time.Now(),
		Assets: []asset.Asset{
			{ID: "my-bucket", Type: "s3_bucket"},
		},
	}
	result := s.Snapshot(snap)
	// Nil sanitizer should return the snapshot unchanged.
	if len(result.Assets) != 1 {
		t.Fatalf("expected 1 asset, got %d", len(result.Assets))
	}
	if result.Assets[0].ID != "my-bucket" {
		t.Errorf("Asset ID should be unchanged for nil sanitizer")
	}
}

func TestSanitizer_Snapshot_SanitizesAssets(t *testing.T) {
	s := New(WithIDSanitization(true))
	snap := asset.Snapshot{
		SchemaVersion: kernel.Schema("obs.v1"),
		CapturedAt:    time.Now(),
		Assets: []asset.Asset{
			{
				ID:     "my-phi-bucket",
				Type:   "s3_bucket",
				Vendor: "aws",
				Properties: map[string]any{
					"tags":        []string{"env:prod"},
					"bucket_name": "my-phi-bucket",
					"versioning":  true,
				},
				Source: &asset.SourceRef{File: "/home/user/obs.json", Line: 5},
			},
		},
	}
	result := s.Snapshot(snap)

	if result.SchemaVersion != snap.SchemaVersion {
		t.Error("SchemaVersion should be preserved")
	}
	if len(result.Assets) != 1 {
		t.Fatalf("expected 1 asset, got %d", len(result.Assets))
	}
	a := result.Assets[0]
	if string(a.ID) == "my-phi-bucket" {
		t.Error("Asset ID should be sanitized")
	}
	if _, ok := a.Properties["tags"]; ok {
		t.Error("tags should be removed")
	}
	if a.Source == nil {
		t.Fatal("Source should not be nil")
	}
	if a.Source.File == "/home/user/obs.json" {
		t.Error("Source.File should be scrubbed to basename")
	}
	if a.Source.File != "obs.json" {
		t.Errorf("Source.File = %q, want obs.json", a.Source.File)
	}
}

func TestSanitizer_Snapshot_SanitizesIdentities(t *testing.T) {
	s := New(WithIDSanitization(true))
	snap := asset.Snapshot{
		SchemaVersion: kernel.Schema("obs.v1"),
		CapturedAt:    time.Now(),
		Assets:        []asset.Asset{},
		Identities: []asset.CloudIdentity{
			{
				ID:     "arn:aws:iam::123:role/admin",
				Type:   "iam_role",
				Vendor: "aws",
				Properties: map[string]any{
					"owner":   "team-security",
					"purpose": "admin access",
					"active":  true,
				},
				Source: &asset.SourceRef{File: "/data/identities.json", Line: 1},
			},
		},
	}
	result := s.Snapshot(snap)

	if len(result.Identities) != 1 {
		t.Fatalf("expected 1 identity, got %d", len(result.Identities))
	}
	id := result.Identities[0]
	if string(id.ID) == "arn:aws:iam::123:role/admin" {
		t.Error("Identity ID should be sanitized")
	}
	if _, ok := id.Properties["owner"]; ok {
		t.Error("owner should be removed by IdentityProfile")
	}
	if _, ok := id.Properties["purpose"]; ok {
		t.Error("purpose should be removed by IdentityProfile")
	}
	if _, ok := id.Properties["active"]; !ok {
		t.Error("active should be preserved")
	}
	if id.Source != nil && id.Source.File == "/data/identities.json" {
		t.Error("Source.File should be scrubbed to basename")
	}
}

func TestSanitizer_Snapshot_NoIdentities(t *testing.T) {
	s := New(WithIDSanitization(true))
	snap := asset.Snapshot{
		SchemaVersion: kernel.Schema("obs.v1"),
		Assets: []asset.Asset{
			{ID: "bucket-a"},
		},
		// No identities.
	}
	result := s.Snapshot(snap)
	if result.Identities != nil {
		t.Error("Identities should remain nil when source has no identities")
	}
}

func TestSanitizer_Snapshot_NilSource(t *testing.T) {
	s := New(WithIDSanitization(true))
	snap := asset.Snapshot{
		Assets: []asset.Asset{
			{ID: "bucket-no-source", Source: nil},
		},
	}
	result := s.Snapshot(snap)
	if result.Assets[0].Source != nil {
		t.Error("nil Source should remain nil after scrubbing")
	}
}

func TestSanitizer_Snapshot_ARNBucketName(t *testing.T) {
	s := New(WithIDSanitization(true))
	snap := asset.Snapshot{
		Assets: []asset.Asset{
			{
				ID:     "arn:aws:s3:::my-phi-bucket",
				Type:   "s3_bucket",
				Vendor: "aws",
				Properties: map[string]any{
					"bucket_name": "my-phi-bucket",
				},
			},
		},
	}
	result := s.Snapshot(snap)
	a := result.Assets[0]
	// ARN prefix should be preserved, bucket name part sanitized.
	if !hasPrefix(string(a.ID), "arn:aws:s3:::SANITIZED_") {
		t.Errorf("ARN sanitization malformed: %q", a.ID)
	}
	tok := crypto.ShortToken("my-phi-bucket")
	if string(a.ID) != "arn:aws:s3:::SANITIZED_"+tok {
		t.Errorf("unexpected sanitized ARN: %q", a.ID)
	}
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}
