package pathinfer

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/sufield/stave/internal/env"
)

func TestBaseDir_EnvSet(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(env.ProjectRoot.Name, dir)

	got, err := BaseDir()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != dir {
		t.Errorf("got %q, want %q", got, dir)
	}
}

func TestBaseDir_EnvInvalid_FallsBackToCwd(t *testing.T) {
	t.Setenv(env.ProjectRoot.Name, "/nonexistent-path-that-does-not-exist")

	got, err := BaseDir()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cwd, _ := os.Getwd()
	if got != cwd {
		t.Errorf("got %q, want cwd %q", got, cwd)
	}
}

func TestBaseDir_EnvUnset_ReturnsCwd(t *testing.T) {
	t.Setenv(env.ProjectRoot.Name, "")

	got, err := BaseDir()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cwd, _ := os.Getwd()
	if got != cwd {
		t.Errorf("got %q, want cwd %q", got, cwd)
	}
}

func TestUnique(t *testing.T) {
	tests := []struct {
		name       string
		dirs       []string // relative dirs to create under base
		target     string   // directory name to search for
		maxDepth   int
		wantFound  bool
		wantPath   string // relative to base, empty if error expected
		wantNCands int    // expected number of candidates in error case
		wantErr    bool
	}{
		{
			name:      "exact conventional dir found",
			dirs:      []string{"observations"},
			target:    "observations",
			maxDepth:  3,
			wantFound: true,
			wantPath:  "observations",
		},
		{
			name:      "unique nested match",
			dirs:      []string{"project/observations"},
			target:    "observations",
			maxDepth:  3,
			wantFound: true,
			wantPath:  "project/observations",
		},
		{
			name:       "ambiguous matches",
			dirs:       []string{"a/observations", "b/observations"},
			target:     "observations",
			maxDepth:   3,
			wantFound:  false,
			wantNCands: 2,
			wantErr:    true,
		},
		{
			name:      "none found",
			dirs:      []string{"other"},
			target:    "observations",
			maxDepth:  3,
			wantFound: false,
			wantErr:   true,
		},
		{
			name:      "depth limit respected — too deep",
			dirs:      []string{"a/b/c/d/observations"},
			target:    "observations",
			maxDepth:  3,
			wantFound: false,
			wantErr:   true,
		},
		{
			name:      "depth 3 found",
			dirs:      []string{"a/b/c/observations"},
			target:    "observations",
			maxDepth:  3,
			wantFound: true,
			wantPath:  "a/b/c/observations",
		},
		{
			name:      "depth 1 found",
			dirs:      []string{"a/observations"},
			target:    "observations",
			maxDepth:  1,
			wantFound: true,
			wantPath:  "a/observations",
		},
		{
			name:      "depth 1 too deep at level 2",
			dirs:      []string{"a/b/observations"},
			target:    "observations",
			maxDepth:  1,
			wantFound: false,
			wantErr:   true,
		},
		{
			name:      "conventional dir preferred over nested",
			dirs:      []string{"observations", "project/observations"},
			target:    "observations",
			maxDepth:  3,
			wantFound: true,
			wantPath:  "observations",
		},
		{
			name:      "controls search works too",
			dirs:      []string{"my-project/controls"},
			target:    "controls",
			maxDepth:  3,
			wantFound: true,
			wantPath:  "my-project/controls",
		},
		{
			name:      "empty base dir",
			dirs:      []string{},
			target:    "observations",
			maxDepth:  3,
			wantFound: false,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base := t.TempDir()

			// Create directory structure
			for _, d := range tt.dirs {
				if err := os.MkdirAll(filepath.Join(base, d), 0o755); err != nil {
					t.Fatalf("mkdir %s: %v", d, err)
				}
			}

			got, candidates, err := Unique(base, tt.target, tt.maxDepth)

			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got path %q", got)
				}
				if tt.wantNCands > 0 {
					if len(candidates) != tt.wantNCands {
						t.Errorf("candidates: got %d, want %d: %v", len(candidates), tt.wantNCands, candidates)
					}
					// Verify candidates are sorted
					if !sort.StringsAreSorted(candidates) {
						t.Errorf("candidates not sorted: %v", candidates)
					}
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			wantAbs := filepath.Join(base, tt.wantPath)
			if got != wantAbs {
				t.Errorf("got %q, want %q", got, wantAbs)
			}
		})
	}
}
