package securityaudit

import (
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/compliance"
	"github.com/sufield/stave/internal/metadata"
)

// NewCmd constructs the security-audit command with closure-scoped flags.
func NewCmd() *cobra.Command {
	c := &auditCmd{}

	cmd := &cobra.Command{
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
		RunE:          c.run,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.Flags().StringVar(&c.flags.format, "format", "json", "Report format: json, markdown, or sarif")
	cmd.Flags().StringVar(&c.flags.out, "out", "", "Main report output file path (default: <out-dir>/security-report.<ext>)")
	cmd.Flags().StringVar(&c.flags.outDir, "out-dir", "", "Artifact bundle output directory (default: ./security-audit-<timestamp>)")
	cmd.Flags().StringVar(&c.flags.severity, "severity", "CRITICAL,HIGH,MEDIUM,LOW", "Comma-separated severities to include: CRITICAL,HIGH,MEDIUM,LOW")
	cmd.Flags().StringVar(&c.flags.sbom, "sbom", "spdx", "SBOM format: spdx or cyclonedx")
	cmd.Flags().StringSliceVar(
		&c.flags.frameworks,
		"compliance-framework",
		nil,
		"Compliance frameworks (repeatable): "+strings.Join(
			compliance.FrameworkStrings(compliance.SupportedFrameworks()), ", ",
		),
	)
	cmd.Flags().StringVar(&c.flags.vulnSource, "vuln-source", "hybrid", "Vulnerability evidence source: hybrid, local, or ci")
	cmd.Flags().BoolVar(&c.flags.liveVulnCheck, "live-vuln-check", false, "Run local govulncheck live check (opt-in)")
	cmd.Flags().StringVar(&c.flags.releaseBundleDir, "release-bundle-dir", "", "Directory with release verification artifacts (SHA256SUMS and signatures)")
	cmd.Flags().BoolVar(&c.flags.privacyMode, "privacy-mode", false, "Enable strict privacy assertions")
	cmd.Flags().StringVar(&c.flags.failOn, "fail-on", "HIGH", "Gate threshold: CRITICAL, HIGH, MEDIUM, LOW, or NONE")
	cmd.Flags().StringVar(&c.flags.nowTime, "now", "", "Override current time (RFC3339). Required for deterministic output")

	return cmd
}
