package forgecmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTestBundle(t *testing.T, assets []map[string]any) string {
	t.Helper()
	snapshots := []map[string]any{{
		"schema_version": "obs.v0.1",
		"source":         "deployed",
		"captured_at":    "2026-01-15T00:00:00Z",
		"assets":         assets,
	}}
	bundle := map[string]any{
		"schema_version": "obs.v0.1",
		"snapshots":      snapshots,
	}
	data, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	path := filepath.Join(t.TempDir(), "snapshot.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func TestPaths_ListsPaths(t *testing.T) {
	path := writeTestBundle(t, []map[string]any{{
		"id":     "bucket-1",
		"type":   "aws_s3_bucket",
		"vendor": "aws",
		"properties": map[string]any{
			"storage": map[string]any{
				"name":   "bucket-1",
				"region": "us-east-1",
				"tags": map[string]any{
					"environment": "production",
					"team":        "platform",
				},
				"encryption": map[string]any{
					"enabled": true,
				},
			},
		},
	}})

	out, err := Paths(path, "aws_s3_bucket", "")
	if err != nil {
		t.Fatalf("Paths: %v", err)
	}
	s := string(out)
	if !strings.Contains(s, "properties.storage.name") {
		t.Error("missing storage.name path")
	}
	if !strings.Contains(s, "properties.storage.tags") {
		t.Error("missing storage.tags path")
	}
	if !strings.Contains(s, `properties.storage.tags[environment]`) {
		t.Error("missing expanded tag key")
	}
	if !strings.Contains(s, "bool") {
		t.Error("missing bool type for encryption.enabled")
	}
}

func TestPaths_FilterWorks(t *testing.T) {
	path := writeTestBundle(t, []map[string]any{{
		"id": "bucket-1", "type": "aws_s3_bucket", "vendor": "aws",
		"properties": map[string]any{
			"storage": map[string]any{
				"name":       "b",
				"encryption": map[string]any{"enabled": true},
			},
		},
	}})

	out, err := Paths(path, "aws_s3_bucket", "encryption")
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, "encryption") {
		t.Error("filter should show encryption paths")
	}
	if strings.Contains(s, "properties.storage.name") {
		t.Error("filter should exclude non-matching paths")
	}
}

func TestPreview_DetectsUnsafe(t *testing.T) {
	path := writeTestBundle(t, []map[string]any{
		{
			"id": "public-bucket", "type": "aws_s3_bucket", "vendor": "aws",
			"properties": map[string]any{
				"storage": map[string]any{
					"access": map[string]any{"public_read": true},
				},
			},
		},
		{
			"id": "private-bucket", "type": "aws_s3_bucket", "vendor": "aws",
			"properties": map[string]any{
				"storage": map[string]any{
					"access": map[string]any{"public_read": false},
				},
			},
		},
	})

	out, err := Preview(path, "aws_s3_bucket",
		"properties.storage.access.public_read", "eq", "true", "")
	if err != nil {
		t.Fatalf("Preview: %v", err)
	}
	s := string(out)
	if !strings.Contains(s, "FAIL") {
		t.Error("expected at least one FAIL")
	}
	if !strings.Contains(s, "PASS") {
		t.Error("expected at least one PASS")
	}
	if !strings.Contains(s, "1 FAIL") {
		t.Error("expected exactly 1 FAIL")
	}
}

func TestSnapshotAssetTypes_FromSnapshot(t *testing.T) {
	path := writeTestBundle(t, []map[string]any{
		{"id": "a", "type": "aws_s3_bucket", "vendor": "aws", "properties": map[string]any{}},
		{"id": "b", "type": "aws_iam_role", "vendor": "aws", "properties": map[string]any{}},
	})

	types, err := SnapshotAssetTypes(path)
	if err != nil {
		t.Fatalf("SnapshotAssetTypes: %v", err)
	}
	if len(types) != 2 {
		t.Errorf("expected 2 types, got %d", len(types))
	}
}
