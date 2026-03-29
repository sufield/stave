package cleanup

import (
	"testing"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
)

func TestRunnerToDeleteFiles(t *testing.T) {
	r := &runner{
		plan: &executionPlan{
			candidateFiles: []appcontracts.SnapshotFile{
				{Path: "/obs/snap1.json"},
				{Path: "/obs/snap2.json"},
			},
		},
	}
	files := r.toDeleteFiles()
	if len(files) != 2 {
		t.Fatalf("expected 2 delete files, got %d", len(files))
	}
	if files[0].Path != "/obs/snap1.json" {
		t.Fatalf("Path = %q", files[0].Path)
	}
}

func TestCleanupOptions_Prepare(t *testing.T) {
	opts := &options{
		ObsDir: "observations",
	}
	if err := opts.Prepare(nil); err != nil {
		t.Fatalf("Prepare error: %v", err)
	}
	if opts.ObsDir == "" {
		t.Fatal("ObsDir should not be empty after Prepare")
	}
}
