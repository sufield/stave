package compliance

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadInput_Stdin(t *testing.T) {
	r := strings.NewReader(`{"checks":{"check-1":{}}}`)
	data, err := readInput("", r)
	if err != nil {
		t.Fatalf("readInput error: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("expected non-empty data")
	}
}

func TestReadInput_MissingFile(t *testing.T) {
	_, err := readInput("/nonexistent/file.json", nil)
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestReadInput_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.yaml")
	if err := os.WriteFile(path, []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := readInput(path, nil)
	if err == nil {
		t.Fatal("expected error for empty file")
	}
}

func TestExtractCheckIDs_JSON(t *testing.T) {
	raw := []byte(`{"checks":{"check-a":{},"check-b":{}}}`)
	ids, err := extractCheckIDs(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ids) != 2 {
		t.Fatalf("expected 2 check IDs, got %d", len(ids))
	}
}

func TestExtractCheckIDs_NonJSON(t *testing.T) {
	raw := []byte("checks:\n  check-a: {}")
	ids, err := extractCheckIDs(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Non-JSON (YAML) returns nil to let full parser handle it
	if ids != nil {
		t.Fatalf("expected nil for non-JSON, got %v", ids)
	}
}
