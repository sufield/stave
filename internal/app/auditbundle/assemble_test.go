package auditbundle

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	policy "github.com/sufield/stave/internal/core/controldef"
)

func TestAssemble_ProducesAllComponents(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "audit-pkg")

	pkg, err := Assemble(AssembleInput{
		Framework:      policy.ComplianceFramework("hipaa"),
		Period:         "2026-Q1",
		OutputDir:      dir,
		ReportJSON:     []byte(`{"posture":{"score":81.2}}`),
		ReportMarkdown: []byte("# Executive Summary\nScore: 81.2\n"),
		Continuity:     []byte(`{"verdict":"PASS"}`),
		TrendJSON:      []byte(`{"direction":"improving"}`),
		ExemptionsJSON: []byte(`{"total_active":3}`),
		GeneratedAt:    time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("assemble failed: %v", err)
	}

	if pkg.Framework != policy.ComplianceFramework("hipaa") {
		t.Errorf("framework = %q, want hipaa", pkg.Framework)
	}
	if pkg.Period != "2026-Q1" {
		t.Errorf("period = %q, want 2026-Q1", pkg.Period)
	}

	// Check all expected files exist on disk.
	expected := []string{
		"00-manifest.json",
		"01-executive-summary.md",
		"02-posture-report.json",
		"04-continuity-attestation.json",
		"06-remediation-trend.json",
		"07-exemption-register.json",
	}
	for _, name := range expected {
		path := filepath.Join(dir, name)
		if _, statErr := os.Stat(path); statErr != nil {
			t.Errorf("missing component: %s", name)
		}
	}

	// Check component count.
	if len(pkg.Components) != 5 {
		t.Errorf("components = %d, want 5", len(pkg.Components))
	}
}

func TestAssemble_NilComponentsSkipped(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "minimal-pkg")

	pkg, err := Assemble(AssembleInput{
		Framework:   "soc2",
		Period:      "2026-Q1",
		OutputDir:   dir,
		ReportJSON:  []byte(`{}`),
		GeneratedAt: time.Now(),
		// All other components nil — should be skipped.
	})
	if err != nil {
		t.Fatalf("assemble failed: %v", err)
	}

	if len(pkg.Components) != 1 {
		t.Errorf("components = %d, want 1 (only report JSON)", len(pkg.Components))
	}
}

func TestComponents_CollectionMethods(t *testing.T) {
	cs := Components{
		{Filename: "01-executive-summary.md", SHA256: "abc123"},
		{Filename: "02-posture-report.json", SHA256: "def456"},
	}

	if cs.Len() != 2 {
		t.Errorf("cs.Len() = %d, want 2", cs.Len())
	}

	found := cs.ByFilename("01-executive-summary.md")
	if found == nil || found.SHA256 != "abc123" {
		t.Errorf("ByFilename = %v, want sha abc123", found)
	}

	if !cs.HasIntegrityHashes() {
		t.Error("expected HasIntegrityHashes = true")
	}

	incomplete := Components{
		{Filename: "file1.txt", SHA256: ""},
	}
	if incomplete.HasIntegrityHashes() {
		t.Error("expected HasIntegrityHashes = false for empty sha")
	}
}
