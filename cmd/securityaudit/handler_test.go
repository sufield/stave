package securityaudit

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/cli/ui"
)

func TestRunSecurityAudit_WritesBundleAndReport(t *testing.T) {
	tmp := t.TempDir()
	outPath := filepath.Join(tmp, "security-report.json")
	outDir := filepath.Join(tmp, "bundle")

	restore := preserveAuditGlobals()
	defer restore()

	audit.flags.format = "json"
	audit.flags.out = outPath
	audit.flags.outDir = outDir
	audit.flags.severity = "CRITICAL,HIGH,MEDIUM,LOW"
	audit.flags.sbom = "spdx"
	audit.flags.frameworks = nil
	audit.flags.vulnSource = "hybrid"
	audit.flags.liveVulnCheck = false
	audit.flags.releaseBundleDir = ""
	audit.flags.privacyMode = false
	audit.flags.failOn = "NONE"

	root := newTestRootCmd()
	cmd := &cobra.Command{}
	root.AddCommand(cmd)
	if err := audit.run(cmd, nil); err != nil {
		t.Fatalf("audit.run returned error: %v", err)
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

	restore := preserveAuditGlobals()
	defer restore()

	audit.flags.format = "json"
	audit.flags.out = filepath.Join(tmp, "security-report.json")
	audit.flags.outDir = filepath.Join(tmp, "bundle")
	audit.flags.severity = "CRITICAL,HIGH,MEDIUM,LOW"
	audit.flags.sbom = "spdx"
	audit.flags.frameworks = nil
	audit.flags.vulnSource = "hybrid"
	audit.flags.liveVulnCheck = false
	audit.flags.releaseBundleDir = ""
	audit.flags.privacyMode = false
	audit.flags.failOn = "HIGH"

	root := newTestRootCmd()
	cmd := &cobra.Command{}
	root.AddCommand(cmd)
	err := audit.run(cmd, nil)
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

func preserveAuditGlobals() func() {
	saved := audit.flags
	saved.frameworks = append([]string(nil), audit.flags.frameworks...)
	return func() {
		audit.flags = saved
	}
}

func newTestRootCmd() *cobra.Command {
	root := &cobra.Command{}
	root.PersistentFlags().String("log-file", "", "")
	root.PersistentFlags().Bool("quiet", true, "")
	root.PersistentFlags().Bool("force", true, "")
	root.PersistentFlags().Bool("allow-symlink-output", false, "")
	return root
}
