package bugreport

import (
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/compliance"
	"github.com/sufield/stave/internal/metadata"
)

var Cmd = &cobra.Command{
	Use:   "bug-report",
	Short: "Collect a sanitized diagnostic bundle for support and issue filing",
	Long: `Bug-report collects a local diagnostics bundle that is safe to share in most
cases. The bundle includes doctor checks, build info, selected environment
variables, and optional sanitized project config/log tail.

Examples:
  # Generate bundle in current directory
  stave bug-report

  # Write bundle to a specific path
  stave bug-report --out ./artifacts/stave-diag.zip

  # Include only last 200 log lines
  stave bug-report --tail-lines 200` + metadata.OfflineHelpSuffix,
	Args:          cobra.NoArgs,
	RunE:          runReport,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	Cmd.Flags().StringVar(&reportOut, "out", "", "Path to output bundle zip (default: ./stave-diag-<timestamp>.zip)")
	Cmd.Flags().IntVar(&tailLines, "tail-lines", 1000, "Number of trailing log lines to include")
	Cmd.Flags().BoolVar(&includeConfig, "include-config", true, "Include project stave.yaml with sensitive values sanitized")
	Cmd.AddCommand(InspectCmd)
}

var InspectCmd = &cobra.Command{
	Use:   "inspect <bundle.zip>",
	Short: "Dump diagnostic bundle contents to stdout",
	Long: `Inspect opens a bug-report bundle zip and prints each file with a separator
header. Output goes to stdout so it can be piped to less, grep, jq, etc.

Examples:
  stave bug-report inspect stave-diag-20260306T120000Z.zip
  stave bug-report inspect bundle.zip | grep -A5 manifest
  stave bug-report inspect bundle.zip | less` + metadata.OfflineHelpSuffix,
	Args:          cobra.ExactArgs(1),
	RunE:          runInspect,
	SilenceUsage:  true,
	SilenceErrors: true,
}

var DoctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Check local environment readiness for Stave workflows",
	Long: `Doctor runs a quick local readiness check for first-time usage and day-to-day
developer workflows.

It validates local prerequisites and reports copy-paste fixes when something is
missing.

Examples:
  stave doctor
  stave doctor --format json` + metadata.OfflineHelpSuffix,
	Args:          cobra.NoArgs,
	RunE:          runDoctor,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	DoctorCmd.Flags().StringVarP(&doctorFormat, "format", "f", "text", "Output format: text or json")
}

var SecurityAuditCmd = &cobra.Command{
	Use:   "security-audit",
	Short: "Generate enterprise security posture evidence for Stave",
	Long: `Security-audit generates auditor-ready artifacts for supply-chain, runtime,
privacy, and internal security controls.

It produces deterministic evidence bundles by default and supports JSON, markdown,
and SARIF output formats.

Examples:
  stave security-audit --format json
  stave security-audit --format markdown --out ./audit/security-report.md
  stave security-audit --format sarif --out-dir ./audit --fail-on CRITICAL` + metadata.OfflineHelpSuffix,
	Args:          cobra.NoArgs,
	RunE:          securityAudit.run,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	SecurityAuditCmd.Flags().StringVar(&securityAudit.flags.format, "format", "json", "Report format: json, markdown, or sarif")
	SecurityAuditCmd.Flags().StringVar(&securityAudit.flags.out, "out", "", "Main report output file path (default: <out-dir>/security-report.<ext>)")
	SecurityAuditCmd.Flags().StringVar(&securityAudit.flags.outDir, "out-dir", "", "Artifact bundle output directory (default: ./security-audit-<timestamp>)")
	SecurityAuditCmd.Flags().StringVar(&securityAudit.flags.severity, "severity", "CRITICAL,HIGH", "Comma-separated severities to include: CRITICAL,HIGH,MEDIUM,LOW")
	SecurityAuditCmd.Flags().StringVar(&securityAudit.flags.sbom, "sbom", "spdx", "SBOM format: spdx or cyclonedx")
	SecurityAuditCmd.Flags().StringSliceVar(
		&securityAudit.flags.frameworks,
		"compliance-framework",
		nil,
		"Compliance frameworks (repeatable): "+strings.Join(
			compliance.FrameworkStrings(compliance.SupportedFrameworks()), ", ",
		),
	)
	SecurityAuditCmd.Flags().StringVar(&securityAudit.flags.vulnSource, "vuln-source", "hybrid", "Vulnerability evidence source: hybrid, local, or ci")
	SecurityAuditCmd.Flags().BoolVar(&securityAudit.flags.liveVulnCheck, "live-vuln-check", false, "Run local govulncheck live check (opt-in)")
	SecurityAuditCmd.Flags().StringVar(&securityAudit.flags.releaseBundleDir, "release-bundle-dir", "", "Directory with release verification artifacts (SHA256SUMS and signatures)")
	SecurityAuditCmd.Flags().BoolVar(&securityAudit.flags.privacyMode, "privacy-mode", false, "Enable strict privacy assertions")
	SecurityAuditCmd.Flags().StringVar(&securityAudit.flags.failOn, "fail-on", "HIGH", "Gate threshold: CRITICAL, HIGH, MEDIUM, LOW, or NONE")
	SecurityAuditCmd.Flags().StringVar(&securityAudit.flags.nowTime, "now", "", "Override current time (RFC3339). Required for deterministic output")
}
