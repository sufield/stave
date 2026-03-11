package securityaudit

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/internal/adapters/govulncheck"
	securityout "github.com/sufield/stave/internal/adapters/output/securityaudit"
	appsa "github.com/sufield/stave/internal/app/securityaudit"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/compliance"
	"github.com/sufield/stave/internal/doctor"
	"github.com/sufield/stave/internal/domain/kernel"
	domainsecurityaudit "github.com/sufield/stave/internal/domain/securityaudit"
	platformcrypto "github.com/sufield/stave/internal/platform/crypto"
	"github.com/sufield/stave/internal/platform/fsutil"
	staveversion "github.com/sufield/stave/internal/version"
)

type auditFlagsType struct {
	format, out, outDir        string
	severity, sbom, vulnSource string
	failOn, releaseBundleDir   string
	nowTime                    string
	frameworks                 []string
	liveVulnCheck, privacyMode bool
}

type auditCmd struct {
	flags auditFlagsType
}

func (c *auditCmd) run(cmd *cobra.Command, _ []string) error {
	format, err := parseFormat(c.flags.format)
	if err != nil {
		return err
	}
	severityFilter, err := domainsecurityaudit.ParseSeverityList(c.flags.severity)
	if err != nil {
		return &ui.InputError{Err: fmt.Errorf("invalid --severity: %w", err)}
	}
	failOn, err := domainsecurityaudit.ParseFailOnSeverity(c.flags.failOn)
	if err != nil {
		return &ui.InputError{Err: fmt.Errorf("invalid --fail-on: %w", err)}
	}

	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("resolve current directory: %w", err)
	}
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve executable path: %w", err)
	}
	now, err := compose.ResolveNow(c.flags.nowTime)
	if err != nil {
		return &ui.InputError{Err: err}
	}
	bundleDir := c.resolveOutDir(now)

	runner := appsa.NewSecurityAuditRunner(appsa.RunnerDeps{
		ReadFile: fsutil.ReadFileLimited,
		HashFile: fsutil.HashFile,
		HashBytes: func(data []byte) kernel.Digest {
			return platformcrypto.HashBytes(data)
		},
		GovulncheckRunner: govulncheck.Run,
		SignatureVerifier: nil,
		RunDiagnostics: func(cwd, binaryPath, staveVersion string) {
			_, _ = doctor.Run(doctor.Context{
				Cwd:          cwd,
				BinaryPath:   binaryPath,
				StaveVersion: staveVersion,
			})
		},
		ResolveCrosswalk: func(raw []byte, frameworks, checkIDs []string, now time.Time) (appsa.CrosswalkResult, error) {
			resolved, resolveErr := compliance.ResolveControlCrosswalk(raw, frameworks, checkIDs, now)
			if resolveErr != nil {
				return appsa.CrosswalkResult{}, resolveErr
			}
			return appsa.CrosswalkResult{
				ByCheck:        resolved.ByCheck,
				MissingChecks:  resolved.MissingChecks,
				ResolutionJSON: resolved.ResolutionJSON,
			}, nil
		},
	})
	report, artifacts, err := runner.Run(cmd.Context(), appsa.SecurityAuditRequest{
		Now:                  now,
		ToolVersion:          staveversion.Version,
		Cwd:                  cwd,
		BinaryPath:           exe,
		OutDir:               bundleDir,
		SeverityFilter:       severityFilter,
		SBOMFormat:           appsa.SBOMFormat(c.flags.sbom),
		ComplianceFrameworks: c.flags.frameworks,
		VulnSource:           appsa.VulnSource(c.flags.vulnSource),
		LiveVulnCheck:        c.flags.liveVulnCheck,
		ReleaseBundleDir:     fsutil.CleanUserPath(c.flags.releaseBundleDir),
		PrivacyMode:          c.flags.privacyMode,
		FailOn:               failOn,
		RequireOffline:       cmdutil.RequireOfflineEnabled(cmd),
	})
	if err != nil {
		return fmt.Errorf("run security audit: %w", err)
	}

	mainData, mainName, err := renderReport(format, report)
	if err != nil {
		return err
	}

	mainOutPath, err := securityout.WriteBundle(
		securityout.BundleWriteOpts{
			Force:        cmdutil.ForceEnabled(cmd),
			AllowSymlink: cmdutil.AllowSymlinkOutEnabled(cmd),
		},
		now, bundleDir, mainName, mainData, report, artifacts, c.resolveOutPath,
	)
	if err != nil {
		return err
	}

	if !cmdutil.QuietEnabled(cmd) {
		if err := printSummary(cmd.OutOrStdout(), mainOutPath, bundleDir, report.Summary); err != nil {
			return err
		}
	}

	if report.Summary.Gated {
		return ui.ErrSecurityAuditFindings
	}
	return nil
}

func printSummary(w io.Writer, mainOutPath, bundleDir string, summary domainsecurityaudit.Summary) error {
	if _, err := fmt.Fprintf(w, "security-audit report: %s\n", mainOutPath); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "security-audit bundle: %s\n", bundleDir); err != nil {
		return err
	}
	_, err := fmt.Fprintf(w, "summary: total=%d pass=%d warn=%d fail=%d gated=%t threshold=%s\n",
		summary.Total, summary.Pass, summary.Warn, summary.Fail, summary.Gated, summary.FailOn)
	return err
}

func parseFormat(raw string) (string, error) {
	normalized := ui.NormalizeToken(raw)
	switch normalized {
	case "json", "markdown", "sarif":
		return normalized, nil
	default:
		return "", &ui.InputError{Err: ui.EnumError("--format", raw, []string{"json", "markdown", "sarif"})}
	}
}

func renderReport(format string, report domainsecurityaudit.Report) ([]byte, string, error) {
	switch format {
	case "json":
		data, err := securityout.MarshalJSONReport(report)
		return data, "security-report.json", err
	case "markdown":
		data, err := securityout.MarshalMarkdownReport(report)
		return data, "security-report.md", err
	case "sarif":
		data, err := securityout.MarshalSARIFReport(report)
		return data, "security-report.sarif", err
	default:
		return nil, "", fmt.Errorf("unsupported report format %q", format)
	}
}

func (c *auditCmd) resolveOutDir(now time.Time) string {
	outDir := fsutil.CleanUserPath(c.flags.outDir)
	if strings.TrimSpace(outDir) != "" {
		return outDir
	}
	return fmt.Sprintf("security-audit-%s", now.UTC().Format("20060102T150405Z"))
}

func (c *auditCmd) resolveOutPath(defaultPath string) string {
	outPath := fsutil.CleanUserPath(c.flags.out)
	if strings.TrimSpace(outPath) == "" {
		return defaultPath
	}
	return outPath
}
