package sanitize

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
)

func TestSanitize_HashDeterministic(t *testing.T) {
	s1 := []asset.Snapshot{{
		CapturedAt: time.Now(),
		Assets: []asset.Asset{
			{ID: "arn:aws:s3:::my-bucket", Properties: map[string]any{}},
		},
	}}
	s2 := []asset.Snapshot{{
		CapturedAt: time.Now(),
		Assets: []asset.Asset{
			{ID: "arn:aws:s3:::my-bucket", Properties: map[string]any{}},
		},
	}}

	cfg := DefaultConfig()
	Sanitize(s1, cfg)
	Sanitize(s2, cfg)

	if s1[0].Assets[0].ID != s2[0].Assets[0].ID {
		t.Errorf("hash not deterministic: %s != %s", s1[0].Assets[0].ID, s2[0].Assets[0].ID)
	}
	if s1[0].Assets[0].ID == "arn:aws:s3:::my-bucket" {
		t.Error("asset ID was not sanitized")
	}
}

func TestSanitize_StillEvaluable(t *testing.T) {
	snaps := []asset.Snapshot{{
		CapturedAt: time.Now(),
		Assets: []asset.Asset{
			{
				ID:   "arn:aws:s3:::test-bucket",
				Type: "s3_bucket",
				Properties: map[string]any{
					"versioning": true,
					"region":     "us-east-1",
				},
			},
		},
	}}

	Sanitize(snaps, DefaultConfig())

	// Properties should still be present (evaluable).
	a := snaps[0].Assets[0]
	if a.Properties["versioning"] != true {
		t.Error("versioning property was removed")
	}
	if a.Properties["region"] == nil {
		t.Error("region property was removed")
	}
}

func TestSanitize_PlaceholderMethod(t *testing.T) {
	snaps := []asset.Snapshot{{
		Assets: []asset.Asset{
			{
				ID: "test",
				Properties: map[string]any{
					"tags": map[string]any{
						"Name": "production-server",
					},
				},
			},
		},
	}}

	cfg := Config{
		Rules: []Rule{
			{Field: "tags.Name", Method: MethodPlaceholder, Placeholder: "[REDACTED]"},
		},
	}
	Sanitize(snaps, cfg)

	tags := snaps[0].Assets[0].Properties["tags"].(map[string]any)
	if tags["Name"] != "[REDACTED]" {
		t.Errorf("Name = %v, want [REDACTED]", tags["Name"])
	}
}

func TestSanitize_RemoveMethod(t *testing.T) {
	snaps := []asset.Snapshot{{
		Assets: []asset.Asset{
			{
				ID: "test",
				Properties: map[string]any{
					"tags": map[string]any{
						"CostCenter": "CC-1234",
						"Name":       "keep-this",
					},
				},
			},
		},
	}}

	cfg := Config{
		Rules: []Rule{
			{Field: "tags.CostCenter", Method: MethodRemove},
		},
	}
	Sanitize(snaps, cfg)

	tags := snaps[0].Assets[0].Properties["tags"].(map[string]any)
	if _, exists := tags["CostCenter"]; exists {
		t.Error("CostCenter should be removed")
	}
	if tags["Name"] != "keep-this" {
		t.Error("Name should be preserved")
	}
}

func TestSanitize_AccountIDsHashed(t *testing.T) {
	snaps := []asset.Snapshot{{
		Assets: []asset.Asset{
			{
				ID: "test",
				Properties: map[string]any{
					"arn": "arn:aws:s3:::bucket-123456789012",
				},
			},
		},
	}}

	Sanitize(snaps, DefaultConfig())

	arn := snaps[0].Assets[0].Properties["arn"].(string)
	if arn == "arn:aws:s3:::bucket-123456789012" {
		t.Error("account ID was not sanitized from ARN property")
	}
}

func TestSanitizeAccountIDs_Array(t *testing.T) {
	// Array values containing account IDs (typical for
	// `allowed_principals` / ARN lists). Previously slipped
	// through because the list branch did not exist.
	props := map[string]any{
		"principals": []any{
			"arn:aws:iam::111122223333:role/admin",
			"arn:aws:iam::444455556666:user/bob",
			"not-an-arn",
		},
	}
	sanitizeAccountIDs(props)
	got := props["principals"].([]any)
	if got[0] == "arn:aws:iam::111122223333:role/admin" {
		t.Errorf("array element 0 was not sanitized: %v", got[0])
	}
	if got[1] == "arn:aws:iam::444455556666:user/bob" {
		t.Errorf("array element 1 was not sanitized: %v", got[1])
	}
	if got[2] != "not-an-arn" {
		t.Errorf("non-account-id string changed: %v", got[2])
	}
}

func TestSanitizeAccountIDs_NestedArrayInMap(t *testing.T) {
	// Array nested inside a map that's nested in another map —
	// exercises the recursion path through both branches.
	props := map[string]any{
		"policy": map[string]any{
			"statements": []any{
				map[string]any{
					"Principal": []any{"arn:aws:iam::111122223333:root"},
				},
			},
		},
	}
	sanitizeAccountIDs(props)
	stmts := props["policy"].(map[string]any)["statements"].([]any)
	principals := stmts[0].(map[string]any)["Principal"].([]any)
	if principals[0] == "arn:aws:iam::111122223333:root" {
		t.Errorf("deeply nested account ID was not sanitized: %v", principals[0])
	}
}
