package expand

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanSnapshots_ScansSubdirectoriesRecursively(t *testing.T) {
	dir := t.TempDir()
	subDir := filepath.Join(dir, "aws")
	if err := os.MkdirAll(subDir, 0755); err != nil {
		t.Fatal(err)
	}

	snapJSON := `{
		"assets": [
			{"type": "aws_s3_bucket"}
		]
	}`

	filePath := filepath.Join(subDir, "obs.json")
	if err := os.WriteFile(filePath, []byte(snapJSON), 0644); err != nil {
		t.Fatal(err)
	}

	status := ScanSnapshots(dir, []string{"s3"})
	if status == nil {
		t.Fatalf("expected non-nil SnapshotStatus")
	}

	if len(status.Found) != 1 || status.Found[0] != "s3" {
		t.Fatalf("expected 's3' in Found status for nested observation file, got found: %v, missing: %v", status.Found, status.Missing)
	}
}
