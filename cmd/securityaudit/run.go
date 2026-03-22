package securityaudit

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	securityout "github.com/sufield/stave/internal/adapters/output/securityaudit"
	appsa "github.com/sufield/stave/internal/app/securityaudit"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/platform/fsutil"
	staveversion "github.com/sufield/stave/internal/version"
	domainsecurityaudit "github.com/sufield/stave/pkg/alpha/domain/securityaudit"
)

// AuditConfig defines the resolved parameters for a security audit.
type AuditConfig struct {
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

// AuditRunner orchestrates security evidence collection.
type AuditRunner struct{}

// Run executes the security audit workflow as a 3-step pipeline:
// resolve environment, execute audit, write output and gate.
func (r *AuditRunner) Run(ctx context.Context, cfg AuditConfig) error {
	cwd, exe, err := resolveAuditEnvironment()
	if err != nil {
		return err
	}

	bundleDir := resolveOutDir(cfg.OutDir, cfg.Now)

	report, artifacts, err := executeAudit(ctx, cfg, cwd, exe, bundleDir)
	if err != nil {
		return err
	}

	return writeAndReport(cfg, report, artifacts, bundleDir)
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
func executeAudit(ctx context.Context, cfg AuditConfig, cwd, exe, bundleDir string) (domainsecurityaudit.Report, domainsecurityaudit.ArtifactManifest, error) {
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

// writeAndReport renders the report, writes the bundle, prints the summary,
// and returns a gating error if findings exceed the threshold.
func writeAndReport(cfg AuditConfig, report domainsecurityaudit.Report, artifacts domainsecurityaudit.ArtifactManifest, bundleDir string) error {
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
