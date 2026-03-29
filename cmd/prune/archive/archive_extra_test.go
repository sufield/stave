package archive

import (
	"testing"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
)

func TestResolveArchivePaths_Valid(t *testing.T) {
	obs, arch, err := resolveArchivePaths("observations", "archive")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if obs == "" {
		t.Fatal("obs should not be empty")
	}
	if arch == "" {
		t.Fatal("arch should not be empty")
	}
}

func TestResolveArchivePaths_EmptyObs(t *testing.T) {
	_, _, err := resolveArchivePaths("", "archive")
	if err == nil {
		t.Fatal("expected error for empty observations")
	}
}

func TestResolveArchivePaths_EmptyArchive(t *testing.T) {
	_, _, err := resolveArchivePaths("observations", "")
	if err == nil {
		t.Fatal("expected error for empty archive dir")
	}
}

func TestRunnerToArchiveMoves(t *testing.T) {
	r := &runner{
		plan: &executionPlan{
			archiveDir: "/archive",
			candidateFiles: []appcontracts.SnapshotFile{
				{Name: "snap1.json", Path: "/obs/snap1.json"},
				{Name: "snap2.json", Path: "/obs/snap2.json"},
			},
		},
	}
	moves := r.toArchiveMoves()
	if len(moves) != 2 {
		t.Fatalf("expected 2 moves, got %d", len(moves))
	}
	if moves[0].Src != "/obs/snap1.json" {
		t.Fatalf("Src = %q", moves[0].Src)
	}
}

func TestArchiveOptions_Prepare(t *testing.T) {
	opts := &options{
		ObsDir:     "observations",
		ArchiveDir: "archive",
	}
	if err := opts.Prepare(nil); err != nil {
		t.Fatalf("Prepare error: %v", err)
	}
	if opts.ObsDir == "" {
		t.Fatal("ObsDir should not be empty after Prepare")
	}
	if opts.ArchiveDir == "" {
		t.Fatal("ArchiveDir should not be empty after Prepare")
	}
}
