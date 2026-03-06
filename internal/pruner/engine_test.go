package pruner

import (
	"errors"
	"slices"
	"testing"
)

func TestApplyDelete(t *testing.T) {
	var removed []string
	result, err := ApplyDelete(DeleteInput{
		Files: []DeleteFile{
			{Path: "/tmp/a.json"},
			{Path: "/tmp/b.json"},
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
	if !slices.Equal(removed, []string{"/tmp/a.json", "/tmp/b.json"}) {
		t.Fatalf("removed = %#v", removed)
	}
}

func TestApplyDelete_StopsOnError(t *testing.T) {
	wantErr := errors.New("boom")
	calls := 0
	result, err := ApplyDelete(DeleteInput{
		Files: []DeleteFile{
			{Path: "/tmp/a.json"},
			{Path: "/tmp/b.json"},
		},
		Remove: func(path string) error {
			calls++
			if path == "/tmp/b.json" {
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
