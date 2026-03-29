package evidence

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFreshnessFromTime(t *testing.T) {
	ts := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	f := FreshnessFromTime(ts)
	if string(f) != "2026-01-15T12:00:00Z" {
		t.Errorf("FreshnessFromTime = %q", f)
	}
}

func TestAllSBOMFormats(t *testing.T) {
	formats := AllSBOMFormats()
	if len(formats) != 2 {
		t.Fatalf("len = %d, want 2", len(formats))
	}
	// Should be sorted
	if formats[0] != "cyclonedx" {
		t.Errorf("first format = %q", formats[0])
	}
}

func TestAllVulnSources(t *testing.T) {
	sources := AllVulnSources()
	if len(sources) != 3 {
		t.Fatalf("len = %d, want 3", len(sources))
	}
}

func TestParseSBOMFormat_Valid(t *testing.T) {
	tests := []struct {
		input string
		want  SBOMFormat
	}{
		{"spdx", SBOMFormatSPDX},
		{"cyclonedx", SBOMFormatCycloneDX},
	}
	for _, tt := range tests {
		got, err := ParseSBOMFormat(tt.input)
		if err != nil {
			t.Errorf("ParseSBOMFormat(%q) error = %v", tt.input, err)
		}
		if got != tt.want {
			t.Errorf("ParseSBOMFormat(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestParseSBOMFormat_Invalid(t *testing.T) {
	_, err := ParseSBOMFormat("xml")
	if err == nil {
		t.Fatal("expected error for invalid format")
	}
}

func TestParseVulnSource_Valid(t *testing.T) {
	tests := []struct {
		input string
		want  VulnSource
	}{
		{"hybrid", VulnSourceHybrid},
		{"local", VulnSourceLocal},
		{"ci", VulnSourceCI},
	}
	for _, tt := range tests {
		got, err := ParseVulnSource(tt.input)
		if err != nil {
			t.Errorf("ParseVulnSource(%q) error = %v", tt.input, err)
		}
		if got != tt.want {
			t.Errorf("ParseVulnSource(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestParseVulnSource_Invalid(t *testing.T) {
	_, err := ParseVulnSource("remote")
	if err == nil {
		t.Fatal("expected error for invalid source")
	}
}

func TestNewCollectors(t *testing.T) {
	c := NewCollectors(Deps{})
	if c.BuildInfo == nil {
		t.Error("expected non-nil BuildInfo")
	}
	if c.SBOM == nil {
		t.Error("expected non-nil SBOM")
	}
}

func TestFindRepoRootWith_Success(t *testing.T) {
	dir := t.TempDir()
	// Create go.mod
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module test"), 0o600)

	root, err := findRepoRootWith(dir, os.Getwd, os.Stat)
	if err != nil {
		t.Fatalf("findRepoRootWith error = %v", err)
	}
	if root != dir {
		t.Errorf("root = %q, want %q", root, dir)
	}
}

func TestFindRepoRootWith_NoGoMod(t *testing.T) {
	dir := t.TempDir()
	_, err := findRepoRootWith(dir, os.Getwd, os.Stat)
	if err == nil {
		t.Fatal("expected error when no go.mod found")
	}
}

func TestFindRepoRootWith_EmptyStart(t *testing.T) {
	// When start is empty, uses getwd
	root, err := findRepoRootWith("", os.Getwd, os.Stat)
	// May or may not find go.mod depending on cwd, just ensure no panic.
	_ = root
	_ = err
}

func TestFindRepoRootWith_GetwdError(t *testing.T) {
	_, err := findRepoRootWith("", func() (string, error) {
		return "", os.ErrNotExist
	}, func(s string) (fs.FileInfo, error) {
		return nil, os.ErrNotExist
	})
	if err == nil {
		t.Fatal("expected error from getwd failure")
	}
}
