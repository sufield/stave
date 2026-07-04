package auditbundle

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"testing"
	"time"
)

func TestBugHunt_AuditBundle_SHA256Populated(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "audit-pkg")

	reportData := []byte(`{"posture":{"score":81.2}}`)
	pkg, err := Assemble(AssembleInput{
		Framework:   "hipaa",
		Period:      "2026-Q1",
		OutputDir:   dir,
		ReportJSON:  reportData,
		GeneratedAt: time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("assemble failed: %v", err)
	}

	if len(pkg.Components) != 1 {
		t.Fatalf("expected 1 component, got %d", len(pkg.Components))
	}

	c := pkg.Components[0]
	if c.SHA256 == "" {
		t.Errorf("expected SHA256 field to be populated for component %s, but was empty", c.Filename)
	}

	h := sha256.New()
	h.Write(reportData)
	expectedSha := hex.EncodeToString(h.Sum(nil))

	if c.SHA256 != expectedSha {
		t.Errorf("expected component SHA256 to be %q, got %q", expectedSha, c.SHA256)
	}
}
