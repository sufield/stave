package report

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/adapters/pruner"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/core/kernel"
)

// ---------------------------------------------------------------------------
// buildCleanupOutput
// ---------------------------------------------------------------------------

func TestBuildCleanupOutput_DryRun(t *testing.T) {
	now := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	input := CleanupInput{
		Now:             now,
		Action:          pruner.ActionDelete,
		DryRun:          true,
		ObservationsDir: "/observations",
		Tier:            "day",
		OlderThan:       7 * 24 * time.Hour,
		KeepMin:         2,
		AllFiles: []appcontracts.SnapshotFile{
			{Name: "a.json", CapturedAt: now.Add(-48 * time.Hour)},
			{Name: "b.json", CapturedAt: now.Add(-24 * time.Hour)},
		},
		CandidateFiles: []appcontracts.SnapshotFile{
			{Name: "a.json", CapturedAt: now.Add(-48 * time.Hour)},
		},
	}

	out := buildCleanupOutput(kernel.SchemaSnapshotPrune, kernel.KindSnapshotPrune, input)
	if out.Applied {
		t.Fatal("dry run should not be applied")
	}
	if out.TotalSnapshots != 2 {
		t.Fatalf("TotalSnapshots = %d", out.TotalSnapshots)
	}
	if out.Candidates != 1 {
		t.Fatalf("Candidates = %d", out.Candidates)
	}
	if len(out.Files) != 1 {
		t.Fatalf("Files = %d", len(out.Files))
	}
}

func TestBuildCleanupOutput_Apply(t *testing.T) {
	now := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	input := CleanupInput{
		Now:    now,
		Action: pruner.ActionDelete,
		DryRun: false,
		CandidateFiles: []appcontracts.SnapshotFile{
			{Name: "a.json", CapturedAt: now},
		},
	}
	out := buildCleanupOutput(kernel.SchemaSnapshotPrune, kernel.KindSnapshotPrune, input)
	if !out.Applied {
		t.Fatal("should be applied")
	}
}

func TestBuildCleanupOutput_NoCandidates(t *testing.T) {
	input := CleanupInput{
		Now:    time.Now(),
		Action: pruner.ActionDelete,
		DryRun: false,
	}
	out := buildCleanupOutput(kernel.SchemaSnapshotPrune, kernel.KindSnapshotPrune, input)
	if out.Applied {
		t.Fatal("no candidates should not be applied")
	}
}

// ---------------------------------------------------------------------------
// BuildArchiveOutput
// ---------------------------------------------------------------------------

func TestBuildArchiveOutput(t *testing.T) {
	now := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	input := ArchiveOutputInput{
		CleanupInput: CleanupInput{
			Now:    now,
			Action: pruner.ActionMove,
			DryRun: false,
			CandidateFiles: []appcontracts.SnapshotFile{
				{Name: "a.json", CapturedAt: now},
			},
		},
		ArchiveDir: "/archive",
	}
	out := BuildArchiveOutput(input)
	if out.ArchiveDir != "/archive" {
		t.Fatalf("ArchiveDir = %q", out.ArchiveDir)
	}
	if !out.Applied {
		t.Fatal("should be applied")
	}
}

// ---------------------------------------------------------------------------
// toCleanupFiles
// ---------------------------------------------------------------------------

func TestToCleanupFiles_Empty(t *testing.T) {
	out := toCleanupFiles(nil)
	if len(out) != 0 {
		t.Fatalf("expected empty, got %d", len(out))
	}
}

func TestToCleanupFiles_NonEmpty(t *testing.T) {
	now := time.Date(2026, 1, 15, 12, 30, 0, 0, time.UTC)
	files := []appcontracts.SnapshotFile{
		{Name: "obs-1.json", CapturedAt: now},
		{Name: "obs-2.json", CapturedAt: now.Add(-time.Hour)},
	}
	out := toCleanupFiles(files)
	if len(out) != 2 {
		t.Fatalf("len = %d", len(out))
	}
	if out[0].Name != "obs-1.json" {
		t.Fatalf("Name = %q", out[0].Name)
	}
}
