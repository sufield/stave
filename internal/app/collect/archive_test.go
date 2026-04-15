package collect

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteRunAndManifest(t *testing.T) {
	dir := t.TempDir()
	archive, err := NewArchive(dir)
	if err != nil {
		t.Fatal(err)
	}

	// Write two runs.
	files := map[string][]byte{
		"evidence.json": []byte(`{"test": true}`),
	}
	meta := RunMetadata{
		RunID:       "run-001",
		CollectedAt: "2025-11-15T02:00:00Z",
		Frameworks:  []string{"hipaa"},
	}
	if writeErr := archive.WriteRun("run-001", files, meta); writeErr != nil {
		t.Fatal(writeErr)
	}

	meta2 := RunMetadata{
		RunID:       "run-002",
		CollectedAt: "2025-11-16T02:00:00Z",
		Frameworks:  []string{"hipaa"},
	}
	if writeErr := archive.WriteRun("run-002", files, meta2); writeErr != nil {
		t.Fatal(writeErr)
	}

	// Build and save manifest.
	manifest, loadErr := archive.LoadManifest()
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	manifest.ArchiveID = "test-archive"
	manifest.AppendRun(ManifestRun{
		RunID: "run-001", CollectedAt: "2025-11-15T02:00:00Z",
		Frameworks: []string{"hipaa"}, FindingCount: 5,
	}, 24)
	manifest.AppendRun(ManifestRun{
		RunID: "run-002", CollectedAt: "2025-11-16T02:00:00Z",
		Frameworks: []string{"hipaa"}, FindingCount: 4,
	}, 24)

	if saveErr := archive.SaveManifest(manifest); saveErr != nil {
		t.Fatal(saveErr)
	}

	// Verify manifest was written.
	if _, statErr := os.Stat(filepath.Join(dir, "manifest.json")); statErr != nil {
		t.Error("manifest.json not written")
	}
	if _, statErr := os.Stat(filepath.Join(dir, "manifest.json.sha256")); statErr != nil {
		t.Error("manifest.json.sha256 not written")
	}

	// Reload and check.
	loaded, reloadErr := archive.LoadManifest()
	if reloadErr != nil {
		t.Fatal(reloadErr)
	}
	if len(loaded.Runs) != 2 {
		t.Errorf("runs = %d, want 2", len(loaded.Runs))
	}
}

func TestGapDetection(t *testing.T) {
	manifest := &Manifest{SchemaVersion: "1"}

	manifest.AppendRun(ManifestRun{
		RunID: "run-001", CollectedAt: "2025-11-15T02:00:00Z",
	}, 24)

	// 48h gap — should trigger gap detection (> 24h * 1.5 = 36h).
	manifest.AppendRun(ManifestRun{
		RunID: "run-002", CollectedAt: "2025-11-17T02:00:00Z",
	}, 24)

	if len(manifest.Gaps) != 1 {
		t.Fatalf("gaps = %d, want 1", len(manifest.Gaps))
	}
	if manifest.Gaps[0].GapHours != 48 {
		t.Errorf("gap hours = %f, want 48", manifest.Gaps[0].GapHours)
	}
}

func TestGapDetection_NoGap(t *testing.T) {
	manifest := &Manifest{SchemaVersion: "1"}

	manifest.AppendRun(ManifestRun{
		RunID: "run-001", CollectedAt: "2025-11-15T02:00:00Z",
	}, 24)
	manifest.AppendRun(ManifestRun{
		RunID: "run-002", CollectedAt: "2025-11-16T02:00:00Z",
	}, 24)

	if len(manifest.Gaps) != 0 {
		t.Errorf("gaps = %d, want 0 (24h interval within 1.5x threshold)", len(manifest.Gaps))
	}
}

func TestVerify_IntactArchive(t *testing.T) {
	dir := t.TempDir()
	archive, _ := NewArchive(dir)

	manifest := &Manifest{
		SchemaVersion: "1",
		ArchiveID:     "test",
		Runs: []ManifestRun{
			{RunID: "run-001"},
		},
	}
	_ = archive.WriteRun("run-001", map[string][]byte{"test.json": []byte("{}")}, RunMetadata{RunID: "run-001"})
	_ = archive.SaveManifest(manifest)

	errs, _ := archive.Verify()
	if len(errs) != 0 {
		t.Errorf("expected no errors, got: %v", errs)
	}
}

func TestVerify_ModifiedManifest(t *testing.T) {
	dir := t.TempDir()
	archive, _ := NewArchive(dir)

	manifest := &Manifest{SchemaVersion: "1"}
	_ = archive.SaveManifest(manifest)

	// Tamper with manifest.
	manifestPath := filepath.Join(dir, "manifest.json")
	_ = os.WriteFile(manifestPath, []byte(`{"schema_version":"1","tampered":true}`), 0o644)

	errs, _ := archive.Verify()
	if len(errs) == 0 {
		t.Error("expected integrity error for modified manifest")
	}
}

func TestSHA256(t *testing.T) {
	a := sha256Hex([]byte("hello"))
	b := sha256Hex([]byte("hello"))
	if a != b {
		t.Error("SHA-256 not deterministic")
	}
	c := sha256Hex([]byte("world"))
	if a == c {
		t.Error("different inputs should produce different hashes")
	}
	if len(a) != 64 {
		t.Errorf("hash length = %d, want 64", len(a))
	}
}
