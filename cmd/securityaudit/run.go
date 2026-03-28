package securityaudit

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	securityout "github.com/sufield/stave/internal/adapters/output/securityaudit"
	appsa "github.com/sufield/stave/internal/app/securityaudit"
	"github.com/sufield/stave/internal/cli/ui"
	domainsecurityaudit "github.com/sufield/stave/internal/core/securityaudit"
	"github.com/sufield/stave/internal/platform/fsutil"
	staveversion "github.com/sufield/stave/internal/version"
)

// auditConfig defines the resolved parameters for a security audit.
type auditConfig struct {
	Format           string
	OutPath          string
	OutDir           string
	SeverityFilter   []domainsecurityaudit.Severity
	SBOMFormat       appsa.SBOMFormat
	Frameworks       []string
	VulnSource       appsa.VulnSource
	LiveVulnCheck    bool
	ReleaseBundleDir string
	PrivacyEnabled   bool
	FailOn           domainsecurityaudit.Severity
	Now              time.Time

	Force          bool
	AllowSymlink   bool
	Quiet          bool
	RequireOffline bool
	Stdout         io.Writer
}

// auditRunner orchestrates security evidence collection.
type auditRunner struct{}

// Run executes the security audit workflow as a 3-step pipeline:
// resolve environment, execute audit, write output and gate.
func (r *auditRunner) Run(ctx context.Context, cfg auditConfig) error {
	cwd, exe, err := resolveAuditEnvironment()
	if err != nil {
		return err
	}

	bundleDir := resolveOutDir(cfg.OutDir, cfg.Now)

	report, artifacts, err := executeAudit(ctx, cfg, cwd, exe, bundleDir)
	if err != nil {
		return err
	}

	return outputReport(cfg, report, artifacts, bundleDir)
}

// resolveAuditEnvironment resolves the working directory and executable path.
func resolveAuditEnvironment() (cwd string, exe string, err error) {
	cwd, err = os.Getwd()
	if err != nil {
		return "", "", fmt.Errorf("resolve current directory: %w", err)
	}
	exe, err = os.Executable()
	if err != nil {
		return "", "", fmt.Errorf("resolve executable path: %w", err)
	}
	return cwd, exe, nil
}

// executeAudit builds the runner and executes the audit, returning the report
// and artifact manifest.
func executeAudit(ctx context.Context, cfg auditConfig, cwd, exe, bundleDir string) (domainsecurityaudit.Report, domainsecurityaudit.ArtifactManifest, error) {
	runner := appsa.NewRunner(buildRunnerDeps())

	report, artifacts, err := runner.Run(ctx, appsa.Request{
		Now:                  cfg.Now,
		StaveVersion:         staveversion.String,
		Cwd:                  cwd,
		BinaryPath:           exe,
		OutDir:               bundleDir,
		SeverityFilter:       cfg.SeverityFilter,
		SBOMFormat:           cfg.SBOMFormat,
		ComplianceFrameworks: cfg.Frameworks,
		VulnSource:           cfg.VulnSource,
		LiveVulnCheck:        cfg.LiveVulnCheck,
		ReleaseBundleDir:     cfg.ReleaseBundleDir,
		PrivacyEnabled:       cfg.PrivacyEnabled,
		FailOn:               cfg.FailOn,
		RequireOffline:       cfg.RequireOffline,
	})
	if err != nil {
		return domainsecurityaudit.Report{}, domainsecurityaudit.ArtifactManifest{}, fmt.Errorf("run security audit: %w", err)
	}
	return report, artifacts, nil
}

// outputReport renders the report, writes the bundle, prints the summary,
// and returns a gating error if findings exceed the threshold.
//
// When neither --out nor --out-dir is set: report goes to stdout (matching
// how apply --format json works). No bundle is written.
// When --out or --out-dir is set: report goes to file, summary to stdout.
func outputReport(cfg auditConfig, report domainsecurityaudit.Report, artifacts domainsecurityaudit.ArtifactManifest, bundleDir string) error {
	mainData, mainName, err := renderReport(cfg.Format, report)
	if err != nil {
		return err
	}

	// Stdout mode: no explicit output file, write report to stdout directly.
	if strings.TrimSpace(cfg.OutPath) == "" && strings.TrimSpace(cfg.OutDir) == "" {
		if _, writeErr := cfg.Stdout.Write(mainData); writeErr != nil {
			return fmt.Errorf("write report to stdout: %w", writeErr)
		}
		if _, writeErr := cfg.Stdout.Write([]byte("\n")); writeErr != nil {
			return writeErr
		}
		if report.Summary.Gated {
			return ui.ErrSecurityAuditFindings
		}
		return nil
	}

	// File mode: write bundle to disk, summary to stdout.
	outPathResolver := func(defaultPath string) string {
		p := fsutil.CleanUserPath(cfg.OutPath)
		if strings.TrimSpace(p) == "" {
			return defaultPath
		}
		return p
	}

	mainOutPath, err := securityout.WriteBundle(securityout.BundleRequest{
		Opts: securityout.BundleWriteOpts{
			Force:        cfg.Force,
			AllowSymlink: cfg.AllowSymlink,
		},
		Now:            cfg.Now,
		BundleDir:      bundleDir,
		MainName:       mainName,
		MainData:       mainData,
		Report:         report,
		Artifacts:      artifacts,
		ResolveOutPath: outPathResolver,
	})
	if err != nil {
		return err
	}

	if !cfg.Quiet {
		displayDir := bundleDir
		if abs, absErr := filepath.Abs(bundleDir); absErr == nil {
			displayDir = abs
		}
		if err := printSummary(cfg.Stdout, mainOutPath, displayDir, report.Summary); err != nil {
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
