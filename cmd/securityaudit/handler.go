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

	runner := appsa.NewSecurityAuditRunner(buildRunnerDeps())

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
