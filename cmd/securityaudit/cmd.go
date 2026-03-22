package securityaudit

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	appsa "github.com/sufield/stave/internal/app/securityaudit"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/compliance"
	"github.com/sufield/stave/internal/metadata"
	"github.com/sufield/stave/internal/platform/fsutil"
	domainsecurityaudit "github.com/sufield/stave/pkg/alpha/domain/securityaudit"
)

// NewCmd constructs the security-audit command.
func NewCmd() *cobra.Command {
	var (
		formatRaw   string
		outPath     string
		outDir      string
		severityRaw string
		sbomFormat  string
		frameworks  []string
		vulnSource  string
		liveVuln    bool
		releaseDir  string
		privacy     bool
		failOn      string
		nowRaw      string
	)

	cmd := &cobra.Command{
		Use:   "security-audit",
		Short: "Generate enterprise security posture evidence for Stave",
		Long: `Generate enterprise security posture evidence for auditors and compliance workflows.

Security-audit produces auditor-ready artifacts covering supply-chain integrity,
runtime security controls, vulnerability assessments, and optional privacy assertions.
It produces deterministic evidence bundles when --now is set and supports JSON,
markdown, and SARIF output formats.

Inputs:
  --format                   Report format: json, markdown, or sarif (default: json)
  --out                      Main report output file path
  --out-dir                  Artifact bundle output directory
  --severity                 Comma-separated severities to include (default: CRITICAL,HIGH,MEDIUM,LOW)
  --sbom                     SBOM format: spdx or cyclonedx (default: spdx)
  --compliance-framework     Compliance frameworks (repeatable)
  --vuln-source              Vulnerability evidence source: hybrid, local, or ci (default: hybrid)
  --live-vuln-check          Run local govulncheck live check (opt-in)
  --release-bundle-dir       Directory with release verification artifacts
  --privacy-mode             Enable strict privacy assertions
  --fail-on                  Gate threshold: CRITICAL, HIGH, MEDIUM, LOW, or NONE (default: HIGH)
  --now                      Override current time (RFC3339) for deterministic output

Outputs:
  stdout                     Security report (when --out is not set)
  --out / --out-dir          Written report file(s) and artifact bundle
  stderr                     Error messages (if any)

Exit Codes:
  0   - Audit passed; no findings at or above the --fail-on threshold
  1   - Gated findings detected at or above the --fail-on threshold
  2   - Invalid input or configuration error
  130 - Interrupted (SIGINT)

Examples:
  stave security-audit --format json
  stave security-audit --format markdown --out ./audit/security-report.md
  stave security-audit --format sarif --out-dir ./audit --fail-on CRITICAL` + metadata.OfflineHelpSuffix,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			gf := cmdutil.GetGlobalFlags(cmd)

			format, err := parseFormat(formatRaw)
			if err != nil {
				return err
			}
			severityFilter, err := domainsecurityaudit.ParseSeverityList(severityRaw)
			if err != nil {
				return &ui.UserError{Err: fmt.Errorf("invalid --severity: %w", err)}
			}
			failOnSev, err := domainsecurityaudit.ParseSeverity(failOn)
			if err != nil {
				return &ui.UserError{Err: fmt.Errorf("invalid --fail-on: %w", err)}
			}
			now, err := compose.ResolveNow(nowRaw)
			if err != nil {
				return &ui.UserError{Err: err}
			}

			parsedSBOM, err := appsa.ParseSBOMFormat(sbomFormat)
			if err != nil {
				return &ui.UserError{Err: err}
			}
			parsedVuln, err := appsa.ParseVulnSource(vulnSource)
			if err != nil {
				return &ui.UserError{Err: err}
			}

			runner := &AuditRunner{}
			return runner.Run(cmd.Context(), AuditConfig{
				Format:           format,
				OutPath:          outPath,
				OutDir:           outDir,
				SeverityFilter:   severityFilter,
				SBOMFormat:       parsedSBOM,
				Frameworks:       frameworks,
				VulnSource:       parsedVuln,
				LiveVulnCheck:    liveVuln,
				ReleaseBundleDir: fsutil.CleanUserPath(releaseDir),
				PrivacyEnabled:   privacy,
				FailOn:           failOnSev,
				Now:              now,
				Force:            gf.Force,
				AllowSymlink:     gf.AllowSymlinkOut,
				Quiet:            gf.Quiet,
				RequireOffline:   gf.RequireOffline,
				Stdout:           cmd.OutOrStdout(),
			})
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	f := cmd.Flags()
	f.StringVar(&formatRaw, "format", "json", "Report format: json, markdown, or sarif")
	f.StringVar(&outPath, "out", "", "Main report output file path (default: <out-dir>/security-report.<ext>)")
	f.StringVar(&outDir, "out-dir", "", "Artifact bundle output directory (default: ./security-audit-<timestamp>)")
	f.StringVar(&severityRaw, "severity", "CRITICAL,HIGH,MEDIUM,LOW", "Comma-separated severities to include: CRITICAL,HIGH,MEDIUM,LOW")
	f.StringVar(&sbomFormat, "sbom", "spdx", "SBOM format: spdx or cyclonedx")
	f.StringSliceVar(&frameworks, "compliance-framework", nil,
		"Compliance frameworks (repeatable): "+strings.Join(
			compliance.FrameworkStrings(compliance.SupportedFrameworks()), ", ",
		),
	)
	f.StringVar(&vulnSource, "vuln-source", "hybrid", "Vulnerability evidence source: hybrid, local, or ci")
	f.BoolVar(&liveVuln, "live-vuln-check", false, "Run local govulncheck live check (opt-in)")
	f.StringVar(&releaseDir, "release-bundle-dir", "", "Directory with release verification artifacts (SHA256SUMS and signatures)")
	f.BoolVar(&privacy, "privacy-mode", false, "Enable strict privacy assertions")
	f.StringVar(&failOn, "fail-on", "HIGH", "Gate threshold: CRITICAL, HIGH, MEDIUM, LOW, or NONE")
	f.StringVar(&nowRaw, "now", "", "Override current time (RFC3339). Required for deterministic output")

	return cmd
}
