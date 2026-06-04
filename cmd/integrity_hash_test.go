package cmd

import (
	"fmt"
	"io/fs"
	"testing"
	"testing/fstest"
)

// errOnReadFS wraps an fs.FS and forces Open (hence ReadFile) to fail for a
// designated path, simulating an unreadable embedded control file.
type errOnReadFS struct {
	fs.FS
	failPath string
}

func (e errOnReadFS) Open(name string) (fs.File, error) {
	if name == e.failPath {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrPermission}
	}
	f, err := e.FS.Open(name)
	if err != nil {
		return nil, fmt.Errorf("errOnReadFS open %q: %w", name, err)
	}
	return f, nil
}

func TestPolicyLibraryHash_CompleteSet(t *testing.T) {
	cfs := fstest.MapFS{
		"a/one.yaml": {Data: []byte("id: one")},
		"b/two.yaml": {Data: []byte("id: two")},
		"readme.md":  {Data: []byte("ignored")},
	}
	hash, count, err := policyLibraryHash(cfs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 2 {
		t.Errorf("count: want 2 (yaml only), got %d", count)
	}
	if hash == "" {
		t.Error("expected non-empty hash over the complete set")
	}
}

func TestPolicyLibraryHash_UnreadableFileFailsLoud(t *testing.T) {
	// A .yaml that cannot be read must abort with an error, NOT be
	// silently skipped to produce a hash over the remaining files —
	// that would be a false attestation over a partial control set.
	base := fstest.MapFS{
		"a/one.yaml": {Data: []byte("id: one")},
		"b/two.yaml": {Data: []byte("id: two")},
	}
	cfs := errOnReadFS{FS: base, failPath: "b/two.yaml"}

	hash, _, err := policyLibraryHash(cfs)
	if err == nil {
		t.Fatal("unreadable control file must return an error, got nil")
	}
	if hash != "" {
		t.Errorf("no partial hash may be returned on read failure, got %q", hash)
	}
}

func TestPolicyLibraryHash_EmptySetNoError(t *testing.T) {
	hash, count, err := policyLibraryHash(fstest.MapFS{})
	if err != nil {
		t.Fatalf("empty FS must not error, got %v", err)
	}
	if hash != "" || count != 0 {
		t.Errorf("empty FS must yield ( \"\", 0 ), got (%q, %d)", hash, count)
	}
}
