package evaluation

import (
	"testing"

	"github.com/sufield/stave/internal/core/kernel"
)

func TestEvaluationMetadataToMap_EmptySourceReturnsEmptyMap(t *testing.T) {
	meta := Metadata{}
	got := meta.ToMap()
	if got == nil {
		t.Fatalf("ToMap() = nil, want empty initialized map")
	}
	if len(got) != 0 {
		t.Fatalf("ToMap() len = %d, want 0", len(got))
	}

	// Caller safety: writing to the returned map must not panic.
	got["x"] = "y"
}

func TestEvaluationMetadataToMap_DirSource(t *testing.T) {
	meta := Metadata{
		ContextName: "stave",
		ControlSource: ControlSourceInfo{
			Source: ControlSourceDir,
		},
		ResolvedPaths: ResolvedPaths{
			Controls:     "/repo/controls",
			Observations: "/repo/observations",
		},
	}

	got := meta.ToMap()
	if got["selected_controls_source"] != "dir" {
		t.Fatalf("selected_controls_source = %v, want dir", got["selected_controls_source"])
	}
	if got["context_name"] != "stave" {
		t.Fatalf("context_name = %v, want stave", got["context_name"])
	}

	rp, ok := got["resolved_paths"].(map[string]any)
	if !ok {
		t.Fatalf("resolved_paths type = %T, want map[string]any", got["resolved_paths"])
	}
	if rp["controls"] != "/repo/controls" {
		t.Fatalf("resolved_paths.controls = %v, want /repo/controls", rp["controls"])
	}
	if rp["observations"] != "/repo/observations" {
		t.Fatalf("resolved_paths.observations = %v, want /repo/observations", rp["observations"])
	}

	if _, exists := got["enabled_control_packs"]; exists {
		t.Fatalf("enabled_control_packs should be omitted for dir source")
	}
}

func TestEvaluationMetadataToMap_PacksAndGit(t *testing.T) {
	meta := Metadata{
		ContextName: "stave",
		ControlSource: ControlSourceInfo{
			Source:             ControlSourcePacks,
			EnabledPacks:       []string{"s3"},
			ResolvedControlIDs: []kernel.ControlID{"CTL.S3.PUBLIC.001"},
			RegistryVersion:    "v1",
			RegistryHash:       "abc123",
		},
		Git: &GitInfo{
			RepoRoot:  "/repo",
			Head:      "deadbeef",
			Dirty:     false,
			DirtyList: []string{"stave.yaml"},
		},
		ResolvedPaths: ResolvedPaths{
			Controls:     "/repo/controls",
			Observations: "/repo/observations",
		},
	}

	got := meta.ToMap()

	if got["pack_registry_version"] != "v1" {
		t.Fatalf("pack_registry_version = %v, want v1", got["pack_registry_version"])
	}
	if got["pack_registry_hash"] != "abc123" {
		t.Fatalf("pack_registry_hash = %v, want abc123", got["pack_registry_hash"])
	}

	gitMap, ok := got["git"].(map[string]any)
	if !ok {
		t.Fatalf("git type = %T, want map[string]any", got["git"])
	}
	if gitMap["repo_root"] != "/repo" {
		t.Fatalf("git.repo_root = %v, want /repo", gitMap["repo_root"])
	}
	if gitMap["head_commit"] != "deadbeef" {
		t.Fatalf("git.head_commit = %v, want deadbeef", gitMap["head_commit"])
	}

	dirty, ok := gitMap["dirty"].(bool)
	if !ok {
		t.Fatalf("git.dirty type = %T, want bool", gitMap["dirty"])
	}
	if dirty {
		t.Fatalf("git.dirty = true, want false")
	}

	paths, ok := gitMap["modified_paths"].([]any)
	if !ok {
		t.Fatalf("git.modified_paths type = %T, want []any", gitMap["modified_paths"])
	}
	if len(paths) != 1 || paths[0] != "stave.yaml" {
		t.Fatalf("git.modified_paths = %#v, want [stave.yaml]", paths)
	}
}
