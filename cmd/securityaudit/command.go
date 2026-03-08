package securityaudit

import (
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/compliance"
	"github.com/sufield/stave/internal/metadata"
)

var Cmd = &cobra.Command{
	Use:   "security-audit",
	Short: "Generate enterprise security posture evidence for Stave",
	Long: `Security-audit generates auditor-ready artifacts for supply-chain, runtime,
privacy, and internal security controls.

It produces deterministic evidence bundles when --now is set and supports JSON, markdown,
and SARIF output formats.

Examples:
  stave security-audit --format json
  stave security-audit --format markdown --out ./audit/security-report.md
  stave security-audit --format sarif --out-dir ./audit --fail-on CRITICAL` + metadata.OfflineHelpSuffix,
	Args:          cobra.NoArgs,
	RunE:          audit.run,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	Cmd.Flags().StringVar(&audit.flags.format, "format", "json", "Report format: json, markdown, or sarif")
	Cmd.Flags().StringVar(&audit.flags.out, "out", "", "Main report output file path (default: <out-dir>/security-report.<ext>)")
	Cmd.Flags().StringVar(&audit.flags.outDir, "out-dir", "", "Artifact bundle output directory (default: ./security-audit-<timestamp>)")
	Cmd.Flags().StringVar(&audit.flags.severity, "severity", "CRITICAL,HIGH,MEDIUM,LOW", "Comma-separated severities to include: CRITICAL,HIGH,MEDIUM,LOW")
	Cmd.Flags().StringVar(&audit.flags.sbom, "sbom", "spdx", "SBOM format: spdx or cyclonedx")
	Cmd.Flags().StringSliceVar(
		&audit.flags.frameworks,
		"compliance-framework",
		nil,
		"Compliance frameworks (repeatable): "+strings.Join(
			compliance.FrameworkStrings(compliance.SupportedFrameworks()), ", ",
		),
	)
	Cmd.Flags().StringVar(&audit.flags.vulnSource, "vuln-source", "hybrid", "Vulnerability evidence source: hybrid, local, or ci")
	Cmd.Flags().BoolVar(&audit.flags.liveVulnCheck, "live-vuln-check", false, "Run local govulncheck live check (opt-in)")
	Cmd.Flags().StringVar(&audit.flags.releaseBundleDir, "release-bundle-dir", "", "Directory with release verification artifacts (SHA256SUMS and signatures)")
	Cmd.Flags().BoolVar(&audit.flags.privacyMode, "privacy-mode", false, "Enable strict privacy assertions")
	Cmd.Flags().StringVar(&audit.flags.failOn, "fail-on", "HIGH", "Gate threshold: CRITICAL, HIGH, MEDIUM, LOW, or NONE")
	Cmd.Flags().StringVar(&audit.flags.nowTime, "now", "", "Override current time (RFC3339). Required for deterministic output")
}
