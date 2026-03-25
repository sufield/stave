// Package securityaudit implements the security-audit command.
package securityaudit

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	appsa "github.com/sufield/stave/internal/app/securityaudit"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/metadata"
	domainsecurityaudit "github.com/sufield/stave/pkg/alpha/domain/securityaudit"
)

// NewCmd constructs the security-audit command.
func NewCmd() *cobra.Command {
	opts := &options{
		FormatRaw:   "json",
		SeverityRaw: "CRITICAL,HIGH,MEDIUM,LOW",
		SBOMFormat:  "spdx",
		VulnSource:  "hybrid",
		FailOn:      "HIGH",
	}

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
  # Print JSON report to stdout (pipe to jq for filtering)
  stave security-audit --format json

  # Write markdown report to a file
  stave security-audit --format markdown --out ./audit/security-report.md

  # Write SARIF report and full evidence bundle, gate on CRITICAL only
  stave security-audit --format sarif --out-dir ./audit --fail-on CRITICAL` + metadata.OfflineHelpSuffix,
		Args: cobra.NoArgs,
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			return opts.Prepare(cmd)
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			gf := cliflags.GetGlobalFlags(cmd)

			format, err := parseFormat(opts.FormatRaw)
			if err != nil {
				return err
			}
			severityFilter, err := domainsecurityaudit.ParseSeverityList(opts.SeverityRaw)
			if err != nil {
				return &ui.UserError{Err: fmt.Errorf("invalid --severity: %w", err)}
			}
			failOnSev, err := domainsecurityaudit.ParseSeverity(opts.FailOn)
			if err != nil {
				return &ui.UserError{Err: fmt.Errorf("invalid --fail-on: %w", err)}
			}
			now, err := compose.ResolveNow(opts.NowRaw)
			if err != nil {
				return &ui.UserError{Err: err}
			}

			parsedSBOM, err := appsa.ParseSBOMFormat(opts.SBOMFormat)
			if err != nil {
				return &ui.UserError{Err: err}
			}
			parsedVuln, err := appsa.ParseVulnSource(opts.VulnSource)
			if err != nil {
				return &ui.UserError{Err: err}
			}

			runner := &auditRunner{}
			return runner.Run(cmd.Context(), auditConfig{
				Format:           format,
				OutPath:          opts.OutPath,
				OutDir:           opts.OutDir,
				SeverityFilter:   severityFilter,
				SBOMFormat:       parsedSBOM,
				Frameworks:       opts.Frameworks,
				VulnSource:       parsedVuln,
				LiveVulnCheck:    opts.LiveVuln,
				ReleaseBundleDir: opts.ReleaseDir,
				PrivacyEnabled:   opts.Privacy,
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

	opts.BindFlags(cmd)

	return cmd
}
