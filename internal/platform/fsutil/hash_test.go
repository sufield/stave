package fsutil

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/sufield/stave/pkg/alpha/domain/kernel"
)

func TestHashFile(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "small.txt")
	content := []byte("hello-hash")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := HashFile(path)
	if err != nil {
		t.Fatalf("HashFile() error = %v", err)
	}

	sum := sha256.Sum256(content)
	want := kernel.Digest(hex.EncodeToString(sum[:]))
	if got != want {
		t.Fatalf("HashFile() = %q, want %q", got, want)
	}
}

func TestHashFile_ExceedsLimit(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping: creates sparse file over 256MB")
	}

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "oversized.bin")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	if truncErr := f.Truncate(maxInputFileBytes + 1); truncErr != nil {
		t.Fatalf("truncate sparse file: %v", truncErr)
	}

	_, err = HashFile(path)
	if err == nil {
		t.Fatal("expected error for oversized file")
	}
	if !errors.Is(err, ErrFileTooLarge) {
		t.Fatalf("expected ErrFileTooLarge, got %v", err)
	}
}

func TestHashDirByExt_DeterministicFilteredHash(t *testing.T) {
	tmpDir := t.TempDir()
	files := map[string]string{
		"b.json": `{"b":1}`,
		"a.json": `{"a":1}`,
		"c.txt":  "ignore me",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(tmpDir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	got1, err := HashDirByExt(tmpDir, ".json")
	if err != nil {
		t.Fatalf("HashDirByExt() error = %v", err)
	}
	got2, err := HashDirByExt(tmpDir, ".json")
	if err != nil {
		t.Fatalf("HashDirByExt() error = %v", err)
	}
	if got1 != got2 {
		t.Fatalf("non-deterministic hash: %q != %q", got1, got2)
	}

	want := manualDirectoryHash(map[string]string{
		"a.json": files["a.json"],
		"b.json": files["b.json"],
	})
	if got1 != want {
		t.Fatalf("HashDirByExt() = %q, want %q", got1, want)
	}
}

func TestHashDirByExt_NoExtMatchesAllFiles(t *testing.T) {
	tmpDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmpDir, "a.yaml"), []byte("a"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "b.json"), []byte("b"), 0o600); err != nil {
		t.Fatal(err)
	}

	hashAll, err := HashDirByExt(tmpDir)
	if err != nil {
		t.Fatalf("HashDirByExt(all) error = %v", err)
	}
	hashFiltered, err := HashDirByExt(tmpDir, ".yaml", ".json")
	if err != nil {
		t.Fatalf("HashDirByExt(filtered) error = %v", err)
	}
	if hashAll != hashFiltered {
		t.Fatalf("expected no-ext hash to match explicit ext hash, got %q vs %q", hashAll, hashFiltered)
	}
}

func TestHashDirByExt_TrimmedExtensions(t *testing.T) {
	tmpDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmpDir, "a.json"), []byte("a"), 0o600); err != nil {
		t.Fatal(err)
	}

	hash1, err := HashDirByExt(tmpDir, ".json")
	if err != nil {
		t.Fatalf("HashDirByExt(.json) error = %v", err)
	}
	hash2, err := HashDirByExt(tmpDir, "  .json  ", " ")
	if err != nil {
		t.Fatalf("HashDirByExt(trimmed) error = %v", err)
	}
	if hash1 != hash2 {
		t.Fatalf("trimmed ext matching mismatch: %q != %q", hash1, hash2)
	}
}

func TestHashDirByExt_PropagatesFileSizeLimit(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping: creates sparse file over 256MB")
	}

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "oversized.json")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	if truncErr := f.Truncate(maxInputFileBytes + 1); truncErr != nil {
		t.Fatalf("truncate sparse file: %v", truncErr)
	}

	_, err = HashDirByExt(tmpDir, ".json")
	if err == nil {
		t.Fatal("expected error for oversized file")
	}
	if !errors.Is(err, ErrFileTooLarge) {
		t.Fatalf("expected ErrFileTooLarge, got %v", err)
	}
}

func manualDirectoryHash(files map[string]string) kernel.Digest {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)

	var b strings.Builder
	for _, name := range names {
		sum := sha256.Sum256([]byte(files[name]))
		b.WriteString(name)
		b.WriteByte('=')
		b.WriteString(hex.EncodeToString(sum[:]))
		b.WriteByte('\n')
	}
	total := sha256.Sum256([]byte(b.String()))
	return kernel.Digest(hex.EncodeToString(total[:]))
}
