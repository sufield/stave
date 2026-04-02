package eval

import (
	"testing"

	"github.com/sufield/stave/internal/core/evaluation"
)

func TestWithGitMetadata(t *testing.T) {
	cfg := NewConfig(EvaluationPlan{ControlsPath: "/ctl"}, WithGitMetadata(&evaluation.GitInfo{
		RepoRoot:  "/repo",
		Head:      "abc123",
		Dirty:     true,
		DirtyList: []evaluation.FilePath{"a.txt"},
	}))
	if cfg.Metadata.Git == nil {
		t.Fatal("expected Git metadata to be set")
	}
	if cfg.Metadata.Git.RepoRoot != "/repo" {
		t.Fatalf("Git.RepoRoot = %q", cfg.Metadata.Git.RepoRoot)
	}
	if cfg.Metadata.Git.Head != "abc123" {
		t.Fatalf("Git.Head = %q", cfg.Metadata.Git.Head)
	}
	if !cfg.Metadata.Git.Dirty {
		t.Fatal("Git.Dirty = false, want true")
	}
	if len(cfg.Metadata.Git.DirtyList) != 1 {
		t.Fatalf("Git.DirtyList = %#v", cfg.Metadata.Git.DirtyList)
	}
}
