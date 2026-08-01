package auditbundle

import (
	"testing"
	"time"
)

func TestAssemble_EmptyByteSlicesNotWrittenAsFiles(t *testing.T) {
	outDir := t.TempDir()

	input := AssembleInput{
		Framework:      "nist_800_53",
		Period:         "2026-Q1",
		OutputDir:      outDir,
		ReportMarkdown: []byte("# Summary"),
		ReportJSON:     []byte{}, // empty non-nil slice
		Continuity:     []byte{}, // empty non-nil slice
		GeneratedAt:    time.Now(),
	}

	pkg, err := Assemble(input)
	if err != nil {
		t.Fatalf("Assemble failed: %v", err)
	}

	// Should only contain 1 component (ReportMarkdown), skipping 0-byte empty components
	if len(pkg.Components) != 1 {
		t.Errorf("expected 1 component in manifest, got %d", len(pkg.Components))
	}
}
