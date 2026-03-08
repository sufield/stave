package bugreport

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

	restore := preserveSecurityAuditGlobals()
	defer restore()

	securityAudit.flags.format = "json"
	securityAudit.flags.out = outPath
	securityAudit.flags.outDir = outDir
	securityAudit.flags.severity = "CRITICAL,HIGH,MEDIUM,LOW"
	securityAudit.flags.sbom = "spdx"
	securityAudit.flags.frameworks = nil
	securityAudit.flags.vulnSource = "hybrid"
	securityAudit.flags.liveVulnCheck = false
	securityAudit.flags.releaseBundleDir = ""
	securityAudit.flags.privacyMode = false
	securityAudit.flags.failOn = "NONE"

	root := newTestRootCmd()
	cmd := &cobra.Command{}
	root.AddCommand(cmd)
	if err := securityAudit.run(cmd, nil); err != nil {
		t.Fatalf("securityAudit.run returned error: %v", err)
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

	restore := preserveSecurityAuditGlobals()
	defer restore()

	securityAudit.flags.format = "json"
	securityAudit.flags.out = filepath.Join(tmp, "security-report.json")
	securityAudit.flags.outDir = filepath.Join(tmp, "bundle")
	securityAudit.flags.severity = "CRITICAL,HIGH,MEDIUM,LOW"
	securityAudit.flags.sbom = "spdx"
	securityAudit.flags.frameworks = nil
	securityAudit.flags.vulnSource = "hybrid"
	securityAudit.flags.liveVulnCheck = false
	securityAudit.flags.releaseBundleDir = ""
	securityAudit.flags.privacyMode = false
	securityAudit.flags.failOn = "HIGH"

	root := newTestRootCmd()
	cmd := &cobra.Command{}
	root.AddCommand(cmd)
	err := securityAudit.run(cmd, nil)
	if !errors.Is(err, ui.ErrSecurityAuditFindings) {
		t.Fatalf("expected ErrSecurityAuditFindings, got %v", err)
	}
}

func TestParseSecurityAuditFormat(t *testing.T) {
	if _, err := parseSecurityAuditFormat("json"); err != nil {
		t.Fatalf("parse format json: %v", err)
	}
	if _, err := parseSecurityAuditFormat("markdown"); err != nil {
		t.Fatalf("parse format markdown: %v", err)
	}
	if _, err := parseSecurityAuditFormat("sarif"); err != nil {
		t.Fatalf("parse format sarif: %v", err)
	}
	if _, err := parseSecurityAuditFormat("bogus"); err == nil {
		t.Fatal("expected invalid format error")
	}
}

func preserveSecurityAuditGlobals() func() {
	saved := securityAudit.flags
	saved.frameworks = append([]string(nil), securityAudit.flags.frameworks...)
	return func() {
		securityAudit.flags = saved
	}
}

// newTestRootCmd creates a root cobra.Command with the persistent flags
// that cmdutil helpers (ForceEnabled, QuietEnabled, etc.) read from.
func newTestRootCmd() *cobra.Command {
	root := &cobra.Command{}
	root.PersistentFlags().String("log-file", "", "")
	root.PersistentFlags().Bool("quiet", true, "")
	root.PersistentFlags().Bool("force", true, "")
	root.PersistentFlags().Bool("allow-symlink-output", false, "")
	return root
}
