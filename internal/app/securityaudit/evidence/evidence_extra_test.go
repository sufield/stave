package evidence

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/securityaudit"
)

// ---------------------------------------------------------------------------
// SBOM Generator
// ---------------------------------------------------------------------------

func TestSBOMGenerator_SPDX(t *testing.T) {
	gen := DefaultSBOMGenerator{}
	input := BuildInfoSnapshot{
		Main: BuildModuleSnapshot{Path: "github.com/test/app", Version: "v1.0.0"},
		Deps: []BuildModuleSnapshot{
			{Path: "github.com/test/dep", Version: "v0.1.0", Sum: "h1:abc"},
		},
	}
	snap, err := gen.Generate(input, SBOMFormatSPDX, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("generate SPDX: %v", err)
	}
	if snap.FileName != "sbom.spdx.json" {
		t.Fatalf("FileName = %q", snap.FileName)
	}
	if snap.DependencyCount != 2 {
		t.Fatalf("DependencyCount = %d", snap.DependencyCount)
	}
	if !bytes.Contains(snap.RawJSON, []byte("SPDX-2.3")) {
		t.Fatal("missing SPDX version")
	}
}

func TestSBOMGenerator_CycloneDX(t *testing.T) {
	gen := DefaultSBOMGenerator{}
	input := BuildInfoSnapshot{
		Main: BuildModuleSnapshot{Path: "github.com/test/app", Version: "v1.0.0"},
		Deps: []BuildModuleSnapshot{
			{Path: "github.com/test/dep", Version: "v0.1.0"},
		},
	}
	snap, err := gen.Generate(input, SBOMFormatCycloneDX, time.Now().UTC())
	if err != nil {
		t.Fatalf("generate CycloneDX: %v", err)
	}
	if snap.FileName != "sbom.cdx.json" {
		t.Fatalf("FileName = %q", snap.FileName)
	}
	if !bytes.Contains(snap.RawJSON, []byte("CycloneDX")) {
		t.Fatal("missing CycloneDX marker")
	}
}

func TestSBOMGenerator_NoModules(t *testing.T) {
	gen := DefaultSBOMGenerator{}
	_, err := gen.Generate(BuildInfoSnapshot{}, SBOMFormatSPDX, time.Now().UTC())
	if err == nil {
		t.Fatal("expected error for empty modules")
	}
}

func TestSBOMGenerator_UnsupportedFormat(t *testing.T) {
	gen := DefaultSBOMGenerator{}
	input := BuildInfoSnapshot{
		Main: BuildModuleSnapshot{Path: "github.com/test/app", Version: "v1.0.0"},
	}
	_, err := gen.Generate(input, "xml", time.Now().UTC())
	if err == nil {
		t.Fatal("expected error for unsupported format")
	}
}

// ---------------------------------------------------------------------------
// normalizeVersion / toGoPURL
// ---------------------------------------------------------------------------

func TestNormalizeVersion(t *testing.T) {
	if got := normalizeVersion(""); got != "unknown" {
		t.Fatalf("empty = %q", got)
	}
	if got := normalizeVersion("  "); got != "unknown" {
		t.Fatalf("whitespace = %q", got)
	}
	if got := normalizeVersion(" v1.0.0 "); got != "v1.0.0" {
		t.Fatalf("trimmed = %q", got)
	}
}

func TestToGoPURL(t *testing.T) {
	purl := toGoPURL("github.com/test/dep", "v1.0.0")
	if purl != "pkg:golang/github.com/test/dep@v1.0.0" {
		t.Fatalf("purl = %q", purl)
	}
}

// ---------------------------------------------------------------------------
// countGovulncheckFindings
// ---------------------------------------------------------------------------

func TestCountGovulncheckFindings(t *testing.T) {
	stream := []byte(`{"finding":{"id":"GO-2024-001"}}
{"finding":{"id":"GO-2024-002"}}
{"config":{"vuln":"check"}}
`)
	count, err := countGovulncheckFindings(stream)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if count != 2 {
		t.Fatalf("count = %d, want 2", count)
	}
}

func TestCountGovulncheckFindings_Empty(t *testing.T) {
	count, err := countGovulncheckFindings([]byte{})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if count != 0 {
		t.Fatalf("count = %d, want 0", count)
	}
}

func TestCountGovulncheckFindings_InvalidJSON(t *testing.T) {
	_, err := countGovulncheckFindings([]byte(`{not json`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

// ---------------------------------------------------------------------------
// inferVulnCount
// ---------------------------------------------------------------------------

func TestInferVulnCount_FindingCount(t *testing.T) {
	raw := []byte(`{"finding_count": 5}`)
	if got := inferVulnCount(raw); got != 5 {
		t.Fatalf("count = %d, want 5", got)
	}
}

func TestInferVulnCount_FindingsArray(t *testing.T) {
	raw := []byte(`{"findings": [{"id":"a"},{"id":"b"}]}`)
	if got := inferVulnCount(raw); got != 2 {
		t.Fatalf("count = %d, want 2", got)
	}
}

func TestInferVulnCount_FallbackByteCount(t *testing.T) {
	raw := []byte(`"finding" appears twice: "finding"`)
	if got := inferVulnCount(raw); got != 2 {
		t.Fatalf("count = %d, want 2", got)
	}
}

// ---------------------------------------------------------------------------
// toInt
// ---------------------------------------------------------------------------

func TestToInt(t *testing.T) {
	if v, ok := toInt(42); !ok || v != 42 {
		t.Fatalf("int: %d, %v", v, ok)
	}
	if v, ok := toInt(int64(99)); !ok || v != 99 {
		t.Fatalf("int64: %d, %v", v, ok)
	}
	if v, ok := toInt(3.14); !ok || v != 3 {
		t.Fatalf("float64: %d, %v", v, ok)
	}
	if _, ok := toInt("nope"); ok {
		t.Fatal("string should not convert")
	}
}

// ---------------------------------------------------------------------------
// compactPaths
// ---------------------------------------------------------------------------

func TestCompactPaths(t *testing.T) {
	result := compactPaths("/a/b", "/a/b", "", " ", "/c/d")
	if len(result) != 2 {
		t.Fatalf("len = %d", len(result))
	}
}

// ---------------------------------------------------------------------------
// shouldAttemptLiveCheck
// ---------------------------------------------------------------------------

func TestShouldAttemptLiveCheck(t *testing.T) {
	tests := []struct {
		name     string
		params   Params
		expected bool
	}{
		{"no live", Params{LiveVulnCheck: false, VulnSource: VulnSourceLocal}, false},
		{"local live", Params{LiveVulnCheck: true, VulnSource: VulnSourceLocal}, true},
		{"hybrid live", Params{LiveVulnCheck: true, VulnSource: VulnSourceHybrid}, true},
		{"ci live", Params{LiveVulnCheck: true, VulnSource: VulnSourceCI}, false},
	}
	for _, tt := range tests {
		if got := shouldAttemptLiveCheck(tt.params); got != tt.expected {
			t.Errorf("%s: got %v, want %v", tt.name, got, tt.expected)
		}
	}
}

// ---------------------------------------------------------------------------
// ensureVulnRawJSON
// ---------------------------------------------------------------------------

func TestEnsureVulnRawJSON_AlreadyHasJSON(t *testing.T) {
	snap := VulnerabilitySnapshot{RawJSON: []byte(`{}`)}
	result := ensureVulnRawJSON(snap, time.Now())
	if string(result.RawJSON) != `{}` {
		t.Fatalf("should not overwrite existing RawJSON")
	}
}

func TestEnsureVulnRawJSON_GeneratesJSON(t *testing.T) {
	snap := VulnerabilitySnapshot{
		Available:  false,
		SourceUsed: VulnSourceUsedNone,
		Details:    "no evidence",
	}
	result := ensureVulnRawJSON(snap, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if len(result.RawJSON) == 0 {
		t.Fatal("expected generated RawJSON")
	}
}

// ---------------------------------------------------------------------------
// evaluateBuildHardening
// ---------------------------------------------------------------------------

func TestEvaluateBuildHardening_PIE(t *testing.T) {
	status, _ := evaluateBuildHardening(BuildInfoSnapshot{
		Settings: map[string]string{"-buildmode": "pie"},
	})
	if status != securityaudit.StatusPass {
		t.Fatalf("status = %v, want pass", status)
	}
}

func TestEvaluateBuildHardening_GOFLAGS(t *testing.T) {
	status, _ := evaluateBuildHardening(BuildInfoSnapshot{
		Settings: map[string]string{"GOFLAGS": "-buildmode=pie -trimpath"},
	})
	if status != securityaudit.StatusPass {
		t.Fatalf("status = %v, want pass", status)
	}
}

func TestEvaluateBuildHardening_NoPIE(t *testing.T) {
	status, _ := evaluateBuildHardening(BuildInfoSnapshot{
		Settings: map[string]string{"-buildmode": "exe"},
	})
	if status != securityaudit.StatusWarn {
		t.Fatalf("status = %v, want warn", status)
	}
}

func TestEvaluateBuildHardening_NoSettings(t *testing.T) {
	status, _ := evaluateBuildHardening(BuildInfoSnapshot{})
	if status != securityaudit.StatusWarn {
		t.Fatalf("status = %v, want warn", status)
	}
}

// ---------------------------------------------------------------------------
// matchChecksumEntry
// ---------------------------------------------------------------------------

func TestMatchChecksumEntry_Match(t *testing.T) {
	raw := []byte("abc123  *stave\ndef456  *other\n")
	msg, ok := matchChecksumEntry(raw, "stave", "abc123")
	if !ok {
		t.Fatalf("expected match, got: %q", msg)
	}
}

func TestMatchChecksumEntry_Mismatch(t *testing.T) {
	raw := []byte("abc123  *stave\n")
	msg, ok := matchChecksumEntry(raw, "stave", "wrong")
	if ok {
		t.Fatal("expected mismatch")
	}
	if msg == "" {
		t.Fatal("expected non-empty message")
	}
}

func TestMatchChecksumEntry_NotFound(t *testing.T) {
	raw := []byte("abc123  *other\n")
	msg, ok := matchChecksumEntry(raw, "stave", "abc123")
	if ok {
		t.Fatal("expected not found")
	}
	if msg == "" {
		t.Fatal("expected non-empty message")
	}
}

// ---------------------------------------------------------------------------
// shouldInspectPath
// ---------------------------------------------------------------------------

func TestShouldInspectPath(t *testing.T) {
	excluded := map[string]bool{"vendor": true}
	if shouldInspectPath("vendor/dep.go", excluded) {
		t.Fatal("vendor should be excluded")
	}
	if !shouldInspectPath("internal/app/run.go", excluded) {
		t.Fatal("internal should be inspected")
	}
}

// ---------------------------------------------------------------------------
// setProxyVars
// ---------------------------------------------------------------------------

func TestSetProxyVars(t *testing.T) {
	getenv := func(key string) string {
		if key == "HTTPS_PROXY" {
			return "http://proxy:3128"
		}
		return ""
	}
	vars := setProxyVars(getenv)
	found := false
	for _, v := range vars {
		if v == "HTTPS_PROXY" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected HTTPS_PROXY in result: %v", vars)
	}
}

func TestSetProxyVars_None(t *testing.T) {
	vars := setProxyVars(func(string) string { return "" })
	if len(vars) != 0 {
		t.Fatalf("expected 0 vars, got %d", len(vars))
	}
}

// ---------------------------------------------------------------------------
// findRepoRootWith edge cases
// ---------------------------------------------------------------------------

func TestFindRepoRootWith_NestedDir(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module test"), 0o600)
	nested := filepath.Join(dir, "a", "b")
	os.MkdirAll(nested, 0o755)

	root, err := findRepoRootWith(nested, os.Getwd, os.Stat)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if root != dir {
		t.Fatalf("root = %q, want %q", root, dir)
	}
}

// ---------------------------------------------------------------------------
// DefaultBuildInfoProvider
// ---------------------------------------------------------------------------

func TestDefaultBuildInfoProvider(t *testing.T) {
	provider := DefaultBuildInfoProvider{}
	snap, err := provider.Collect(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	if len(snap.RawJSON) == 0 {
		t.Fatal("expected non-empty RawJSON")
	}
	// In test binary, build info should be available
	if !snap.Available {
		t.Log("build info not available (expected in some test environments)")
	}
}

// ---------------------------------------------------------------------------
// DefaultBinaryInspector
// ---------------------------------------------------------------------------

func TestDefaultBinaryInspector_EmptyPath(t *testing.T) {
	insp := DefaultBinaryInspector{}
	_, err := insp.Inspect(Params{BinaryPath: ""}, BuildInfoSnapshot{})
	if err == nil {
		t.Fatal("expected error for empty binary path")
	}
}

// ---------------------------------------------------------------------------
// DefaultCrosswalkResolver
// ---------------------------------------------------------------------------

func TestDefaultCrosswalkResolver_NoGoMod(t *testing.T) {
	dir := t.TempDir()
	resolver := DefaultCrosswalkResolver{
		ReadFile: os.ReadFile,
		StatFile: os.Stat,
	}
	_, err := resolver.Resolve(context.TODO(), Params{Cwd: dir}, nil)
	if err == nil {
		t.Fatal("expected error when no go.mod found")
	}
}

// Compile time: verify interface satisfactions from types.go
var _ BuildInfoProvider = DefaultBuildInfoProvider{}
var _ SBOMGenerator = DefaultSBOMGenerator{}
