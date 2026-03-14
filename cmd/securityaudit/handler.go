package securityaudit

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

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

// AuditConfig defines the resolved parameters for a security audit.
type AuditConfig struct {
	Format           string
	OutPath          string
	OutDir           string
	SeverityFilter   []domainsecurityaudit.Severity
	SBOMFormat       string
	Frameworks       []string
	VulnSource       string
	LiveVulnCheck    bool
	ReleaseBundleDir string
	PrivacyMode      bool
	FailOn           domainsecurityaudit.Severity
	Now              time.Time

	Force          bool
	AllowSymlink   bool
	Quiet          bool
	RequireOffline bool
	Stdout         io.Writer
}

// AuditRunner orchestrates security evidence collection.
type AuditRunner struct{}

// Run executes the security audit workflow.
func (r *AuditRunner) Run(ctx context.Context, cfg AuditConfig) error {
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("resolve current directory: %w", err)
	}
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve executable path: %w", err)
	}

	bundleDir := resolveOutDir(cfg.OutDir, cfg.Now)

	runner := appsa.NewSecurityAuditRunner(appsa.RunnerDeps{
		ReadFile: fsutil.ReadFileLimited,
		HashFile: fsutil.HashFile,
		HashBytes: func(data []byte) kernel.Digest {
			return platformcrypto.HashBytes(data)
		},
		GovulncheckRunner: govulncheck.Run,
		SignatureVerifier: nil,
		RunDiagnostics: func(cwd, binaryPath, staveVersion string) {
			_, _ = doctor.Run(&doctor.Context{
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

	report, artifacts, err := runner.Run(ctx, appsa.SecurityAuditRequest{
		Now:                  cfg.Now,
		ToolVersion:          staveversion.Version,
		Cwd:                  cwd,
		BinaryPath:           exe,
		OutDir:               bundleDir,
		SeverityFilter:       cfg.SeverityFilter,
		SBOMFormat:           appsa.SBOMFormat(cfg.SBOMFormat),
		ComplianceFrameworks: cfg.Frameworks,
		VulnSource:           appsa.VulnSource(cfg.VulnSource),
		LiveVulnCheck:        cfg.LiveVulnCheck,
		ReleaseBundleDir:     cfg.ReleaseBundleDir,
		PrivacyMode:          cfg.PrivacyMode,
		FailOn:               cfg.FailOn,
		RequireOffline:       cfg.RequireOffline,
	})
	if err != nil {
		return fmt.Errorf("run security audit: %w", err)
	}

	mainData, mainName, err := renderReport(cfg.Format, report)
	if err != nil {
		return err
	}

	outPathResolver := func(defaultPath string) string {
		p := fsutil.CleanUserPath(cfg.OutPath)
		if strings.TrimSpace(p) == "" {
			return defaultPath
		}
		return p
	}

	mainOutPath, err := securityout.WriteBundle(
		securityout.BundleWriteOpts{
			Force:        cfg.Force,
			AllowSymlink: cfg.AllowSymlink,
		},
		cfg.Now, bundleDir, mainName, mainData, report, artifacts, outPathResolver,
	)
	if err != nil {
		return err
	}

	if !cfg.Quiet {
		if err := printSummary(cfg.Stdout, mainOutPath, bundleDir, report.Summary); err != nil {
			return err
		}
	}

	if report.Summary.Gated {
		return ui.ErrSecurityAuditFindings
	}
	return nil
}

// --- Helpers ---

func resolveOutDir(raw string, now time.Time) string {
	outDir := fsutil.CleanUserPath(raw)
	if strings.TrimSpace(outDir) != "" {
		return outDir
	}
	return fmt.Sprintf("security-audit-%s", now.UTC().Format("20060102T150405Z"))
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
		return "", &ui.UserError{Err: ui.EnumError("--format", raw, []string{"json", "markdown", "sarif"})}
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
