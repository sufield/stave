package expand

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBugHunt_ScanSnapshots_GCPProvider(t *testing.T) {
	// Create a temp directory for fake snapshots.
	tmpDir, err := os.MkdirTemp("", "stave-test-snapshots")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Write a mock snapshot containing a GCP resource type (e.g. "gcp_storage_bucket").
	mockData := `{"assets": [{"type": "gcp_storage_bucket", "properties": {}}]}`
	err = os.WriteFile(filepath.Join(tmpDir, "gcp_snapshot.json"), []byte(mockData), 0644)
	if err != nil {
		t.Fatal(err)
	}

	// Scan the snapshot directory for the service "storage".
	status := ScanSnapshots(tmpDir, []string{"storage"})

	if len(status.Found) != 1 || status.Found[0] != "storage" {
		t.Errorf("expected 'storage' service to be found, got status: %+v", status)
	}
}
