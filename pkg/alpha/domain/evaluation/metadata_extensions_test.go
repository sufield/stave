package evaluation

import (
	"testing"

	"github.com/sufield/stave/pkg/alpha/domain/kernel"
)

func TestToExtensions_EmptySource(t *testing.T) {
	m := Metadata{}
	if got := m.ToExtensions(); got != nil {
		t.Fatalf("expected nil for empty source, got %+v", got)
	}
}

func TestToExtensions_DirSourceNoGit(t *testing.T) {
	m := Metadata{
		ContextName: "test-ctx",
		ControlSource: ControlSourceInfo{
			Source: ControlSourceDir,
		},
		ResolvedPaths: ResolvedPaths{
			Controls:     "/ctl",
			Observations: "/obs",
		},
	}
	ext := m.ToExtensions()
	if ext == nil {
		t.Fatal("expected non-nil extensions")
	}
	if ext.SelectedSource != "dir" {
		t.Fatalf("SelectedSource = %q, want %q", ext.SelectedSource, "dir")
	}
	if ext.ContextName != "test-ctx" {
		t.Fatalf("ContextName = %q, want %q", ext.ContextName, "test-ctx")
	}
	if ext.ResolvedPaths["controls"] != "/ctl" {
		t.Fatalf("ResolvedPaths[controls] = %q, want %q", ext.ResolvedPaths["controls"], "/ctl")
	}
	if ext.ResolvedPaths["observations"] != "/obs" {
		t.Fatalf("ResolvedPaths[observations] = %q, want %q", ext.ResolvedPaths["observations"], "/obs")
	}
	if len(ext.EnabledPacks) != 0 {
		t.Fatalf("EnabledPacks should be empty for dir source, got %v", ext.EnabledPacks)
	}
	if ext.Git != nil {
		t.Fatalf("Git should be nil when no git metadata, got %+v", ext.Git)
	}
}

func TestToExtensions_PacksSourceWithGit(t *testing.T) {
	m := Metadata{
		ControlSource: ControlSourceInfo{
			Source:             ControlSourcePacks,
			EnabledPacks:       []string{"core", "hipaa"},
			ResolvedControlIDs: []kernel.ControlID{"CTL.001", "CTL.002"},
			RegistryVersion:    "v1.0",
			RegistryHash:       "abc123",
		},
		Git: &GitInfo{
			RepoRoot:  "/repo",
			Head:      "deadbeef",
			Dirty:     true,
			DirtyList: []string{"a.tf", "b.tf"},
		},
		ResolvedPaths: ResolvedPaths{
			Controls:     "/ctl",
			Observations: "/obs",
		},
	}
	ext := m.ToExtensions()
	if ext == nil {
		t.Fatal("expected non-nil extensions")
	}
	if len(ext.EnabledPacks) != 2 || ext.EnabledPacks[0] != "core" {
		t.Fatalf("EnabledPacks = %v, want [core hipaa]", ext.EnabledPacks)
	}
	if len(ext.ResolvedControlIDs) != 2 {
		t.Fatalf("ResolvedControlIDs = %v, want 2 items", ext.ResolvedControlIDs)
	}
	if ext.PackRegistryVersion != "v1.0" {
		t.Fatalf("PackRegistryVersion = %q, want %q", ext.PackRegistryVersion, "v1.0")
	}
	if ext.PackRegistryHash != "abc123" {
		t.Fatalf("PackRegistryHash = %q, want %q", ext.PackRegistryHash, "abc123")
	}
	if ext.Git == nil {
		t.Fatal("Git should be non-nil")
	}
	if ext.Git.RepoRoot != "/repo" {
		t.Fatalf("Git.RepoRoot = %q, want %q", ext.Git.RepoRoot, "/repo")
	}
	if ext.Git.Head != "deadbeef" {
		t.Fatalf("Git.Head = %q, want %q", ext.Git.Head, "deadbeef")
	}
	if !ext.Git.Dirty {
		t.Fatal("Git.Dirty should be true")
	}
	if len(ext.Git.Modified) != 2 {
		t.Fatalf("Git.Modified = %v, want 2 items", ext.Git.Modified)
	}
}

func TestToExtensions_GitDirtyListDeepCopy(t *testing.T) {
	dirty := []string{"a.tf", "b.tf"}
	m := Metadata{
		ControlSource: ControlSourceInfo{Source: "dir"},
		Git: &GitInfo{
			DirtyList: dirty,
			Dirty:     true,
		},
		ResolvedPaths: ResolvedPaths{},
	}
	ext := m.ToExtensions()
	ext.Git.Modified[0] = "mutated.tf"
	if dirty[0] != "a.tf" {
		t.Fatalf("mutation leaked to input: dirty[0] = %q", dirty[0])
	}
}
