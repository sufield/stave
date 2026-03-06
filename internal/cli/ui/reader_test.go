package ui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadInput_FilePath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "input.json")
	want := []byte(`{"ok":true}`)
	if err := os.WriteFile(path, want, 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	got, source, err := ReadInput(nil, path)
	if err != nil {
		t.Fatalf("ReadInput(file) error: %v", err)
	}
	if source != path {
		t.Fatalf("source=%q want %q", source, path)
	}
	if string(got) != string(want) {
		t.Fatalf("content=%q want %q", string(got), string(want))
	}
}

func TestReadInput_Stdin(t *testing.T) {
	r := strings.NewReader("hello")

	got, source, err := ReadInput(r, "-")
	if err != nil {
		t.Fatalf("ReadInput(stdin) error: %v", err)
	}
	if source != "stdin" {
		t.Fatalf("source=%q want %q", source, "stdin")
	}
	if string(got) != "hello" {
		t.Fatalf("content=%q want %q", string(got), "hello")
	}
}
