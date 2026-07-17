package expand

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBugHunt_ScanSnapshots_NoFalsePositives(t *testing.T) {
	tmp := t.TempDir()

	// Write a snapshot JSON file where the string "aws_s3" appears as part of a tag value
	// or description, but the actual asset type is something else (e.g., aws_iam_role).
	// Under buggy code, strings.Contains will match "aws_s3" and flag "s3" as Found.
	content := `{
		"schema_version": "obs.v0.1",
		"captured_at": "2026-07-15T12:00:00Z",
		"assets": [
			{
				"id": "arn:aws:iam::123:role/aws_s3_readonly_role",
				"type": "aws_iam_role",
				"properties": {
					"description": "Role allowing aws_s3 read access"
				}
			}
		]
	}`

	err := os.WriteFile(filepath.Join(tmp, "iam.json"), []byte(content), 0o600)
	if err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	status := ScanSnapshots(tmp, []string{"s3", "iam"})
	if status == nil {
		t.Fatal("expected status, got nil")
	}

	// s3 should be Missing because there are no aws_s3 assets in the snapshot
	foundS3 := false
	for _, f := range status.Found {
		if f == "s3" {
			foundS3 = true
		}
	}

	if foundS3 {
		t.Error("expected 's3' service to be Missing, but it was reported as Found (false positive)")
	}

	foundIAM := false
	for _, f := range status.Found {
		if f == "iam" {
			foundIAM = true
		}
	}
	if !foundIAM {
		t.Error("expected 'iam' service to be Found, but it was Missing")
	}
}
