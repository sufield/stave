package securityaudit

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	policy "github.com/sufield/stave/internal/core/controldef"

	"github.com/sufield/stave/internal/cli/ui"
)

func TestRunSecurityAudit_WritesBundleAndReport(t *testing.T) {
	tmp := t.TempDir()
	outPath := filepath.Join(tmp, "security-report.json")
	outDir := filepath.Join(tmp, "bundle")

	runner := &auditRunner{}
	err := runner.Run(context.Background(), auditConfig{
		Format:  "json",
		OutPath: outPath,
		OutDir:  outDir,
		SeverityFilter: []policy.Severity{
			policy.SeverityCritical,
			policy.SeverityHigh,
			policy.SeverityMedium,
			policy.SeverityLow,
		},
		SBOMFormat: "spdx",
		VulnSource: "hybrid",
		FailOn:     policy.SeverityNone,
		Now:        time.Now().UTC(),
		Force:      true,
		Quiet:      true,
		Stdout:     io.Discard,
	})
	if err != nil {
		t.Fatalf("audit.Run returned error: %v", err)
	}

	required := []string{
		outPath,
		filepath.Join(outDir, "security-report.json"),
		filepath.Join(outDir, "build_info.json"),
		filepath.Join(outDir, "binary_checksums.json"),
		filepath.Join(outDir, "network_egress_declaration.json"),
		filepath.Join(outDir, "filesystem_access_declaration.json"),
		filepath.Join(outDir, "control_crosswalk_resolution.json"),
		filepath.Join(outDir, "run_manifest.json"),
	}
	for _, path := range required {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected artifact %s: %v", path, err)
		}
	}
}

func TestRunSecurityAudit_FailOnHighReturnsSentinel(t *testing.T) {
	tmp := t.TempDir()

	runner := &auditRunner{}
	err := runner.Run(context.Background(), auditConfig{
		Format:  "json",
		OutPath: filepath.Join(tmp, "security-report.json"),
		OutDir:  filepath.Join(tmp, "bundle"),
		SeverityFilter: []policy.Severity{
			policy.SeverityCritical,
			policy.SeverityHigh,
			policy.SeverityMedium,
			policy.SeverityLow,
		},
		SBOMFormat: "spdx",
		VulnSource: "hybrid",
		FailOn:     policy.SeverityHigh,
		Now:        time.Now().UTC(),
		Force:      true,
		Quiet:      true,
		Stdout:     io.Discard,
	})
	if !errors.Is(err, ui.ErrSecurityAuditFindings) {
		t.Fatalf("expected ErrSecurityAuditFindings, got %v", err)
	}
}

func TestParseFormat(t *testing.T) {
	if _, err := parseFormat("json"); err != nil {
		t.Fatalf("parse format json: %v", err)
	}
	if _, err := parseFormat("markdown"); err != nil {
		t.Fatalf("parse format markdown: %v", err)
	}
	if _, err := parseFormat("sarif"); err != nil {
		t.Fatalf("parse format sarif: %v", err)
	}
	if _, err := parseFormat("bogus"); err == nil {
		t.Fatal("expected invalid format error")
	}
}
