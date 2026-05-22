package evaluation

import (
	"testing"

	"github.com/sufield/stave/internal/core/kernel"
)

func TestToExtensions_EmptySource(t *testing.T) {
	m := Metadata{}
	if got := m.ToExtensions(); got != nil {
		t.Fatalf("expected nil for empty source, got %+v", got)
	}
}

func TestToExtensions_DirSource(t *testing.T) {
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
}

func TestToExtensions_PacksSourceRegistryFields(t *testing.T) {
	m := Metadata{
		ControlSource: ControlSourceInfo{
			Source:             ControlSourcePacks,
			EnabledPacks:       []kernel.PackName{"core", "hipaa"},
			ResolvedControlIDs: []kernel.ControlID{"CTL.001", "CTL.002"},
			RegistryVersion:    "v1.0",
			RegistryHash:       "abc123",
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
}
