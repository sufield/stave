package status

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewScanner(t *testing.T) {
	sc := NewScanner()
	if sc == nil {
		t.Fatal("NewScanner returned nil")
	}
}

func TestScanner_Scan_EmptyDir(t *testing.T) {
	root := t.TempDir()
	sc := NewScanner()
	state, err := sc.Scan(root)
	if err != nil {
		t.Fatalf("Scan empty dir: %v", err)
	}
	if state.Root != root {
		t.Fatalf("Root=%q, want %q", state.Root, root)
	}
	if state.Controls.Count != 0 {
		t.Fatalf("Controls.Count=%d, want 0", state.Controls.Count)
	}
	if state.Observations.Count != 0 {
		t.Fatalf("Observations.Count=%d, want 0", state.Observations.Count)
	}
	if state.RawSnapshots.Count != 0 {
		t.Fatalf("RawSnapshots.Count=%d, want 0", state.RawSnapshots.Count)
	}
	if state.HasEval {
		t.Fatal("HasEval should be false for empty dir")
	}
}

func TestScanner_Scan_WithControls(t *testing.T) {
	root := t.TempDir()
	ctlDir := filepath.Join(root, "controls")
	if err := os.MkdirAll(ctlDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"a.yaml", "b.yml", "c.txt"} {
		if err := os.WriteFile(filepath.Join(ctlDir, name), []byte("test"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	sc := NewScanner()
	state, err := sc.Scan(root)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	// Only .yaml and .yml should be counted.
	if state.Controls.Count != 2 {
		t.Fatalf("Controls.Count=%d, want 2", state.Controls.Count)
	}
	if !state.Controls.HasLatest {
		t.Fatal("Controls.HasLatest should be true")
	}
}

func TestScanner_Scan_WithObservations(t *testing.T) {
	root := t.TempDir()
	obsDir := filepath.Join(root, "observations")
	if err := os.MkdirAll(obsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"snap1.json", "snap2.json", "readme.txt"} {
		if err := os.WriteFile(filepath.Join(obsDir, name), []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	sc := NewScanner()
	state, err := sc.Scan(root)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if state.Observations.Count != 2 {
		t.Fatalf("Observations.Count=%d, want 2", state.Observations.Count)
	}
}

func TestScanner_Scan_WithRawSnapshots(t *testing.T) {
	root := t.TempDir()
	rawDir := filepath.Join(root, "snapshots", "raw", "subdir")
	if err := os.MkdirAll(rawDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"a.json", "b.json"} {
		if err := os.WriteFile(filepath.Join(rawDir, name), []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Also put one in the parent directory.
	if err := os.WriteFile(filepath.Join(root, "snapshots", "raw", "c.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}

	sc := NewScanner()
	state, err := sc.Scan(root)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if state.RawSnapshots.Count != 3 {
		t.Fatalf("RawSnapshots.Count=%d, want 3", state.RawSnapshots.Count)
	}
}

func TestScanner_Scan_WithEval(t *testing.T) {
	root := t.TempDir()
	outDir := filepath.Join(root, "output")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatal(err)
	}
	evalPath := filepath.Join(outDir, "evaluation.json")
	if err := os.WriteFile(evalPath, []byte(`{"summary":{}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	sc := NewScanner()
	state, err := sc.Scan(root)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if !state.HasEval {
		t.Fatal("HasEval should be true")
	}
	if state.EvalTime.IsZero() {
		t.Fatal("EvalTime should not be zero")
	}
}

func TestScanner_Scan_SkipsDirs(t *testing.T) {
	root := t.TempDir()
	ctlDir := filepath.Join(root, "controls")
	if err := os.MkdirAll(ctlDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Create a subdirectory inside controls — it should be skipped (summarize is non-recursive).
	subDir := filepath.Join(ctlDir, "subdir")
	if err := os.MkdirAll(subDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(subDir, "nested.yaml"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ctlDir, "top.yaml"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	sc := NewScanner()
	state, err := sc.Scan(root)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	// Only the top-level .yaml should be counted.
	if state.Controls.Count != 1 {
		t.Fatalf("Controls.Count=%d, want 1 (should not include nested)", state.Controls.Count)
	}
}

func TestMatchesExtension(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		exts     []string
		want     bool
	}{
		{"match yaml", "file.yaml", []string{".yaml", ".yml"}, true},
		{"match yml", "file.yml", []string{".yaml", ".yml"}, true},
		{"no match", "file.txt", []string{".yaml", ".yml"}, false},
		{"empty exts", "file.json", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchesExtension(tt.filename, tt.exts)
			if got != tt.want {
				t.Fatalf("matchesExtension(%q, %v)=%v, want %v", tt.filename, tt.exts, got, tt.want)
			}
		})
	}
}

// state_test.go tests

func TestProjectState_RecommendNext_NoControls(t *testing.T) {
	s := ProjectState{Root: "/project"}
	next := s.RecommendNext()
	if next == "" {
		t.Fatal("RecommendNext should not be empty")
	}
}

func TestProjectState_RecommendNext_NoObservations(t *testing.T) {
	s := ProjectState{
		Root:     "/project",
		Controls: Summary{Count: 3, HasLatest: true},
	}
	next := s.RecommendNext()
	if next == "" {
		t.Fatal("RecommendNext should not be empty")
	}
}

func TestProjectState_RecommendNext_NeedsReevaluation(t *testing.T) {
	now := time.Now()
	s := ProjectState{
		Root:         "/project",
		Controls:     Summary{Count: 3, HasLatest: true, Latest: now},
		Observations: Summary{Count: 2, HasLatest: true, Latest: now},
		HasEval:      true,
		EvalTime:     now.Add(-time.Hour), // Eval is older than inputs.
	}
	next := s.RecommendNext()
	if next == "" {
		t.Fatal("empty")
	}
}

func TestProjectState_RecommendNext_Diagnose(t *testing.T) {
	now := time.Now()
	s := ProjectState{
		Root:         "/project",
		Controls:     Summary{Count: 3, HasLatest: true, Latest: now.Add(-2 * time.Hour)},
		Observations: Summary{Count: 2, HasLatest: true, Latest: now.Add(-time.Hour)},
		HasEval:      true,
		EvalTime:     now, // Eval is newer than all inputs.
	}
	next := s.RecommendNext()
	if next == "" {
		t.Fatal("empty")
	}
}

func TestProjectState_RecommendNext_RawNewerThanObs(t *testing.T) {
	now := time.Now()
	s := ProjectState{
		Root:         "/project",
		Controls:     Summary{Count: 3, HasLatest: true},
		RawSnapshots: Summary{Count: 5, HasLatest: true, Latest: now},
		Observations: Summary{Count: 2, HasLatest: true, Latest: now.Add(-time.Hour)},
		HasEval:      true,
		EvalTime:     now,
	}
	next := s.RecommendNext()
	if next == "" {
		t.Fatal("empty")
	}
}

func TestProjectState_NeedsReevaluation(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name string
		s    ProjectState
		want bool
	}{
		{
			"no eval",
			ProjectState{HasEval: false},
			true,
		},
		{
			"controls newer than eval",
			ProjectState{
				HasEval:  true,
				EvalTime: now.Add(-time.Hour),
				Controls: Summary{HasLatest: true, Latest: now},
			},
			true,
		},
		{
			"observations newer than eval",
			ProjectState{
				HasEval:      true,
				EvalTime:     now.Add(-time.Hour),
				Controls:     Summary{HasLatest: true, Latest: now.Add(-2 * time.Hour)},
				Observations: Summary{HasLatest: true, Latest: now},
			},
			true,
		},
		{
			"eval is current",
			ProjectState{
				HasEval:      true,
				EvalTime:     now,
				Controls:     Summary{HasLatest: true, Latest: now.Add(-time.Hour)},
				Observations: Summary{HasLatest: true, Latest: now.Add(-time.Minute)},
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.s.NeedsReevaluation(); got != tt.want {
				t.Fatalf("NeedsReevaluation()=%v, want %v", got, tt.want)
			}
		})
	}
}

func TestProjectState_isRawNewerThanObs(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name string
		s    ProjectState
		want bool
	}{
		{
			"raw newer",
			ProjectState{
				RawSnapshots: Summary{HasLatest: true, Latest: now},
				Observations: Summary{HasLatest: true, Latest: now.Add(-time.Hour)},
			},
			true,
		},
		{
			"obs newer",
			ProjectState{
				RawSnapshots: Summary{HasLatest: true, Latest: now.Add(-time.Hour)},
				Observations: Summary{HasLatest: true, Latest: now},
			},
			false,
		},
		{
			"no raw latest",
			ProjectState{
				RawSnapshots: Summary{HasLatest: false},
				Observations: Summary{HasLatest: true, Latest: now},
			},
			false,
		},
		{
			"no obs latest",
			ProjectState{
				RawSnapshots: Summary{HasLatest: true, Latest: now},
				Observations: Summary{HasLatest: false},
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.s.isRawNewerThanObs(); got != tt.want {
				t.Fatalf("isRawNewerThanObs()=%v, want %v", got, tt.want)
			}
		})
	}
}
