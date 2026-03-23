package evaluation

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoader(t *testing.T) {
	loader := &Loader{}

	t.Run("file loader errors", func(t *testing.T) {
		_, err := loader.LoadFromFile("does-not-exist.json")
		if err == nil || !strings.Contains(err.Error(), "failed to load output file") {
			t.Fatalf("unexpected err: %v", err)
		}
	})

	t.Run("file loader invalid json", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "bad.json")
		if err := os.WriteFile(path, []byte("{bad"), 0o600); err != nil {
			t.Fatalf("write temp file: %v", err)
		}
		_, err := loader.LoadFromFile(path)
		if err == nil || !strings.Contains(err.Error(), "invalid JSON") {
			t.Fatalf("unexpected err: %v", err)
		}
	})

	t.Run("reader parse error", func(t *testing.T) {
		_, err := loader.LoadFromReader(bytes.NewBufferString("{bad"), "stdin")
		if err == nil || !strings.Contains(err.Error(), "invalid JSON") {
			t.Fatalf("unexpected err: %v", err)
		}
	})
}
