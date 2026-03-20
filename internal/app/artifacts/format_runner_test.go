package artifacts

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestFormatterRun_CheckOnly(t *testing.T) {
	dir := t.TempDir()

	// Write an unformatted JSON file (extra whitespace).
	unformatted := []byte(`{   "schema_version":"obs.v0.1","generated_by":{"source_type":"test","tool":"test"},"captured_at":"2026-01-01T00:00:00Z","assets":[]}`)
	if err := os.WriteFile(filepath.Join(dir, "snap.json"), unformatted, 0o644); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	f := NewFormatter()
	_, err := f.Run(FormatConfig{
		Target:    dir,
		CheckOnly: true,
		Stdout:    &buf,
		ReadFile:  os.ReadFile,
	})
	if err == nil {
		t.Fatal("expected error for unformatted file in check mode")
	}
}

func TestFormatterRun_FormatWrites(t *testing.T) {
	dir := t.TempDir()

	unformatted := []byte(`{   "schema_version":"obs.v0.1","generated_by":{"source_type":"test","tool":"test"},"captured_at":"2026-01-01T00:00:00Z","assets":[]}`)
	path := filepath.Join(dir, "snap.json")
	if err := os.WriteFile(path, unformatted, 0o644); err != nil {
		t.Fatal(err)
	}

	var written []byte
	var buf bytes.Buffer
	f := NewFormatter()
	result, err := f.Run(FormatConfig{
		Target:   dir,
		Stdout:   &buf,
		ReadFile: os.ReadFile,
		WriteFile: func(p string, data []byte) error {
			written = data
			return nil
		},
	})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if result.ChangedFiles != 1 {
		t.Fatalf("expected 1 changed file, got %d", result.ChangedFiles)
	}
	if len(written) == 0 {
		t.Fatal("expected WriteFile to be called")
	}
}

func TestFormatterRun_AlreadyFormatted(t *testing.T) {
	dir := t.TempDir()

	// Write a properly formatted YAML file.
	formatted := []byte("dsl_version: ctrl.v1\nid: CTL.TEST.001\n")
	if err := os.WriteFile(filepath.Join(dir, "ctl.yaml"), formatted, 0o644); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	f := NewFormatter()
	result, err := f.Run(FormatConfig{
		Target:    dir,
		CheckOnly: true,
		Stdout:    &buf,
		ReadFile:  os.ReadFile,
	})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if result.ChangedFiles != 0 {
		t.Fatalf("expected 0 changed files, got %d", result.ChangedFiles)
	}
}

func TestCollectFormatTargets_Dir(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"a.json", "b.yaml", "c.txt", "d.yml"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	files, err := CollectFormatTargets(dir)
	if err != nil {
		t.Fatalf("CollectFormatTargets error: %v", err)
	}
	if len(files) != 3 {
		t.Fatalf("expected 3 files (json+yaml+yml), got %d: %v", len(files), files)
	}
}

func TestCollectFormatTargets_SingleFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "single.json")
	if err := os.WriteFile(path, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}

	files, err := CollectFormatTargets(path)
	if err != nil {
		t.Fatalf("CollectFormatTargets error: %v", err)
	}
	if len(files) != 1 || files[0] != path {
		t.Fatalf("expected [%s], got %v", path, files)
	}
}
