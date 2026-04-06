package artifacts

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestCanonicalizerNormalize_VerifyOnly(t *testing.T) {
	dir := t.TempDir()

	// Write an unformatted JSON file (extra whitespace).
	unformatted := []byte(`{   "schema_version":"obs.v0.1","generated_by":{"source_type":"test","tool":"test"},"captured_at":"2026-01-01T00:00:00Z","assets":[]}`)
	if err := os.WriteFile(filepath.Join(dir, "snap.json"), unformatted, 0o644); err != nil {
		t.Fatal(err)
	}

	c := &Canonicalizer{}
	_, err := c.Normalize(context.Background(), NormalizationConfig{
		SourcePath: dir,
		VerifyOnly: true,
		Reader:     os.ReadFile,
	})
	if err == nil {
		t.Fatal("expected error for unformatted file in verify mode")
	}
}

func TestCanonicalizerNormalize_Writes(t *testing.T) {
	dir := t.TempDir()

	unformatted := []byte(`{   "schema_version":"obs.v0.1","generated_by":{"source_type":"test","tool":"test"},"captured_at":"2026-01-01T00:00:00Z","assets":[]}`)
	path := filepath.Join(dir, "snap.json")
	if err := os.WriteFile(path, unformatted, 0o644); err != nil {
		t.Fatal(err)
	}

	var written []byte
	c := &Canonicalizer{}
	result, err := c.Normalize(context.Background(), NormalizationConfig{
		SourcePath: dir,
		Reader:     os.ReadFile,
		Writer: func(_ string, data []byte) error {
			written = data
			return nil
		},
	})
	if err != nil {
		t.Fatalf("Normalize error: %v", err)
	}
	if result.ModifiedManifests != 1 {
		t.Fatalf("expected 1 modified manifest, got %d", result.ModifiedManifests)
	}
	if len(written) == 0 {
		t.Fatal("expected Writer to be called")
	}
}

func TestCanonicalizerNormalize_AlreadyCanonical(t *testing.T) {
	dir := t.TempDir()

	formatted := []byte("dsl_version: ctrl.v1\nid: CTL.TEST.001\n")
	if err := os.WriteFile(filepath.Join(dir, "ctl.yaml"), formatted, 0o644); err != nil {
		t.Fatal(err)
	}

	c := &Canonicalizer{}
	result, err := c.Normalize(context.Background(), NormalizationConfig{
		SourcePath: dir,
		VerifyOnly: true,
		Reader:     os.ReadFile,
	})
	if err != nil {
		t.Fatalf("Normalize error: %v", err)
	}
	if result.ModifiedManifests != 0 {
		t.Fatalf("expected 0 modified manifests, got %d", result.ModifiedManifests)
	}
}

func TestDiscoverManifests_Dir(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"a.json", "b.yaml", "c.txt", "d.yml"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	files, err := DiscoverManifests(context.Background(), dir)
	if err != nil {
		t.Fatalf("DiscoverManifests error: %v", err)
	}
	if len(files) != 3 {
		t.Fatalf("expected 3 files (json+yaml+yml), got %d: %v", len(files), files)
	}
}

func TestDiscoverManifests_SingleFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "single.json")
	if err := os.WriteFile(path, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}

	files, err := DiscoverManifests(context.Background(), path)
	if err != nil {
		t.Fatalf("DiscoverManifests error: %v", err)
	}
	if len(files) != 1 || files[0] != path {
		t.Fatalf("expected [%s], got %v", path, files)
	}
}
