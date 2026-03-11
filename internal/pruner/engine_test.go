package pruner

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"

	"github.com/sufield/stave/internal/platform/fsutil"
)

func TestApplyDelete(t *testing.T) {
	tmp := t.TempDir()
	a := filepath.Join(tmp, "a.json")
	b := filepath.Join(tmp, "b.json")
	for _, p := range []string{a, b} {
		if err := os.WriteFile(p, []byte(`{}`), 0o644); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}

	var removed []string
	result, err := ApplyDelete(DeleteInput{
		ObservationsDir: tmp,
		Files: []DeleteFile{
			{Path: a},
			{Path: b},
		},
		Remove: func(path string) error {
			removed = append(removed, path)
			return nil
		},
	})
	if err != nil {
		t.Fatalf("ApplyDelete() error = %v", err)
	}
	if result.Deleted != 2 {
		t.Fatalf("deleted = %d, want 2", result.Deleted)
	}
	if !slices.Equal(removed, []string{a, b}) {
		t.Fatalf("removed = %#v", removed)
	}
}

func TestApplyDelete_StopsOnError(t *testing.T) {
	tmp := t.TempDir()
	a := filepath.Join(tmp, "a.json")
	b := filepath.Join(tmp, "b.json")
	for _, p := range []string{a, b} {
		if err := os.WriteFile(p, []byte(`{}`), 0o644); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}

	wantErr := errors.New("boom")
	calls := 0
	result, err := ApplyDelete(DeleteInput{
		ObservationsDir: tmp,
		Files: []DeleteFile{
			{Path: a},
			{Path: b},
		},
		Remove: func(path string) error {
			calls++
			if path == b {
				return wantErr
			}
			return nil
		},
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("err = %v, want wrapped %v", err, wantErr)
	}
	if result.Deleted != 1 {
		t.Fatalf("deleted = %d, want 1", result.Deleted)
	}
	if calls != 2 {
		t.Fatalf("calls = %d, want 2", calls)
	}
}

func TestApplyDelete_RejectsPathTraversal(t *testing.T) {
	tmp := t.TempDir()
	escaped := filepath.Join(tmp, "..", "escaped.json")
	_, err := ApplyDelete(DeleteInput{
		ObservationsDir: tmp,
		Files: []DeleteFile{
			{Path: escaped},
		},
		Remove: func(string) error { return nil },
	})
	if err == nil {
		t.Fatal("expected path traversal error")
	}
	if !errors.Is(err, fsutil.ErrPathTraversal) {
		t.Fatalf("expected ErrPathTraversal, got: %v", err)
	}
}

func TestApplyDelete_RejectsSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks require elevated privileges on Windows")
	}

	tmp := t.TempDir()
	real := filepath.Join(tmp, "real.json")
	if err := os.WriteFile(real, []byte(`{}`), 0o644); err != nil {
		t.Fatalf("write real: %v", err)
	}
	link := filepath.Join(tmp, "link.json")
	if err := os.Symlink(real, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	_, err := ApplyDelete(DeleteInput{
		ObservationsDir: tmp,
		Files:           []DeleteFile{{Path: link}},
	})
	if err == nil {
		t.Fatal("expected symlink rejection error")
	}
	// real.json should still exist.
	if _, statErr := os.Stat(real); statErr != nil {
		t.Fatalf("real.json should not have been deleted: %v", statErr)
	}
}

func TestApplyDelete_SkipsAlreadyRemoved(t *testing.T) {
	tmp := t.TempDir()
	missing := filepath.Join(tmp, "gone.json")

	result, err := ApplyDelete(DeleteInput{
		ObservationsDir: tmp,
		Files:           []DeleteFile{{Path: missing}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Deleted != 0 {
		t.Fatalf("deleted = %d, want 0 (file didn't exist)", result.Deleted)
	}
}
