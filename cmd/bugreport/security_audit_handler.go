package bugreport

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/internal/adapters/govulncheck"
	securityout "github.com/sufield/stave/internal/adapters/output/securityaudit"
	appsa "github.com/sufield/stave/internal/app/securityaudit"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/securityaudit"
	platformcrypto "github.com/sufield/stave/internal/platform/crypto"
	"github.com/sufield/stave/internal/platform/fsutil"
	staveversion "github.com/sufield/stave/internal/version"
)

type securityAuditFlagsType struct {
	format, out, outDir        string
	severity, sbom, vulnSource string
	failOn, releaseBundleDir   string
	frameworks                 []string
	liveVulnCheck, privacyMode bool
}

type securityAuditCmd struct {
	flags securityAuditFlagsType
}

type fileWriteOpts struct {
	force        bool
	allowSymlink bool
}

type writtenFile struct {
	name    string
	content []byte
}

var securityAudit = &securityAuditCmd{}

func (c *securityAuditCmd) run(cmd *cobra.Command, _ []string) error {
	format, err := parseSecurityAuditFormat(c.flags.format)
	if err != nil {
		return err
	}
	severityFilter, err := securityaudit.ParseSeverityList(c.flags.severity)
	if err != nil {
		return &ui.InputError{Err: fmt.Errorf("invalid --severity: %w", err)}
	}
	failOn, err := securityaudit.ParseFailOnSeverity(c.flags.failOn)
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
	now := time.Now().UTC()
	bundleDir := c.resolveOutDir(now)

	opts := fileWriteOpts{
		force:        cmdutil.ForceEnabled(cmd),
		allowSymlink: cmdutil.AllowSymlinkOutEnabled(cmd),
	}

	runner := appsa.NewSecurityAuditRunner(govulncheck.Run)
	report, artifacts, err := runner.Run(context.Background(), appsa.SecurityAuditRequest{
		Now:                  now,
		ToolVersion:          staveversion.Version,
		Cwd:                  cwd,
		BinaryPath:           exe,
		OutDir:               bundleDir,
		SeverityFilter:       severityFilter,
		SBOMFormat:           c.flags.sbom,
		ComplianceFrameworks: c.flags.frameworks,
		VulnSource:           c.flags.vulnSource,
		LiveVulnCheck:        c.flags.liveVulnCheck,
		ReleaseBundleDir:     fsutil.CleanUserPath(c.flags.releaseBundleDir),
		PrivacyMode:          c.flags.privacyMode,
		FailOn:               failOn,
		RequireOffline:       cmdutil.RequireOfflineEnabled(cmd),
	})
	if err != nil {
		return fmt.Errorf("run security audit: %w", err)
	}

	mainData, mainName, err := renderSecurityAuditReport(format, report)
	if err != nil {
		return err
	}

	mainOutPath, err := writeSecurityAuditBundle(opts, bundleDir, mainName, mainData, report, artifacts, c.resolveOutPath)
	if err != nil {
		return err
	}

	if !cmdutil.QuietEnabled(cmd) {
		printSecurityAuditSummary(cmd.OutOrStdout(), mainOutPath, bundleDir, report.Summary)
	}

	if report.Summary.Gated {
		return ui.ErrSecurityAuditFindings
	}
	return nil
}

func writeSecurityAuditBundle(opts fileWriteOpts, bundleDir, mainName string, mainData []byte, report securityaudit.Report, artifacts securityaudit.ArtifactManifest, resolveOutPath func(string) string) (string, error) {
	if err := fsutil.SafeMkdirAll(bundleDir, fsutil.WriteOptions{
		Perm:         0o700,
		AllowSymlink: opts.allowSymlink,
	}); err != nil {
		return "", fmt.Errorf("create bundle directory: %w", err)
	}

	var written []writtenFile

	mainBundlePath := filepath.Join(bundleDir, mainName)
	if err := writeOutputFile(opts, mainBundlePath, mainData); err != nil {
		return "", err
	}
	written = append(written, writtenFile{name: mainName, content: mainData})

	mainOutPath := resolveOutPath(mainBundlePath)
	if mainOutPath != mainBundlePath {
		if err := writeOutputFile(opts, mainOutPath, mainData); err != nil {
			return "", err
		}
	}

	for _, artifact := range artifacts.Files {
		target := filepath.Join(bundleDir, artifact.Path)
		if err := writeOutputFile(opts, target, artifact.Content); err != nil {
			return "", err
		}
		written = append(written, writtenFile{name: artifact.Path, content: artifact.Content})
	}

	runManifestPath := filepath.Join(bundleDir, "run_manifest.json")
	if err := writeRunManifest(opts, runManifestPath, bundleDir, mainName, written, report); err != nil {
		return "", err
	}

	return mainOutPath, nil
}

func printSecurityAuditSummary(w io.Writer, mainOutPath, bundleDir string, summary securityaudit.Summary) {
	fmt.Fprintf(w, "security-audit report: %s\n", mainOutPath)
	fmt.Fprintf(w, "security-audit bundle: %s\n", bundleDir)
	fmt.Fprintf(w, "summary: total=%d pass=%d warn=%d fail=%d gated=%t threshold=%s\n",
		summary.Total, summary.Pass, summary.Warn, summary.Fail, summary.Gated, summary.FailOn)
}

func parseSecurityAuditFormat(raw string) (string, error) {
	normalized := ui.NormalizeToken(raw)
	switch normalized {
	case "json", "markdown", "sarif":
		return normalized, nil
	default:
		valid := []string{"json", "markdown", "sarif"}
		if suggestion := ui.ClosestToken(normalized, valid); suggestion != "" {
			return "", &ui.InputError{Err: fmt.Errorf("invalid --format %q (use json, markdown, or sarif)\nDid you mean %q?", raw, suggestion)}
		}
		return "", &ui.InputError{Err: fmt.Errorf("invalid --format %q (use json, markdown, or sarif)", raw)}
	}
}

func renderSecurityAuditReport(format string, report securityaudit.Report) ([]byte, string, error) {
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

func (c *securityAuditCmd) resolveOutDir(now time.Time) string {
	outDir := fsutil.CleanUserPath(c.flags.outDir)
	if strings.TrimSpace(outDir) != "" {
		return outDir
	}
	return fmt.Sprintf("security-audit-%s", now.UTC().Format("20060102T150405Z"))
}

func (c *securityAuditCmd) resolveOutPath(defaultPath string) string {
	outPath := fsutil.CleanUserPath(c.flags.out)
	if strings.TrimSpace(outPath) == "" {
		return defaultPath
	}
	return outPath
}

func writeOutputFile(opts fileWriteOpts, path string, data []byte) error {
	parent := filepath.Dir(path)
	if strings.TrimSpace(parent) != "" && parent != "." {
		if err := fsutil.SafeMkdirAll(parent, fsutil.WriteOptions{
			Perm:         0o700,
			AllowSymlink: opts.allowSymlink,
		}); err != nil {
			return fmt.Errorf("create output directory %q: %w", parent, err)
		}
	}
	wopts := fsutil.DefaultWriteOpts()
	wopts.Overwrite = opts.force
	wopts.AllowSymlink = opts.allowSymlink
	if err := fsutil.SafeWriteFile(path, data, wopts); err != nil {
		return fmt.Errorf("write output %q: %w", path, err)
	}
	return nil
}

type manifestFile struct {
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
}

func writeRunManifest(opts fileWriteOpts, path string, bundleDir string, mainReport string, written []writtenFile, report securityaudit.Report) error {
	files := make([]manifestFile, 0, len(written))
	for _, w := range written {
		files = append(files, manifestFile{
			Path:      w.name,
			SHA256:    string(platformcrypto.HashBytes(w.content)),
			SizeBytes: int64(len(w.content)),
		})
	}
	sort.Slice(files, func(i, j int) bool {
		return files[i].Path < files[j].Path
	})

	runManifest := map[string]any{
		"schema_version":     string(kernel.SchemaSecurityAuditRunManifest),
		"generated_at":       time.Now().UTC().Format(time.RFC3339),
		"main_report":        mainReport,
		"bundle_dir":         bundleDir,
		"tool_version":       report.ToolVersion,
		"fail_on":            report.Summary.FailOn,
		"gated":              report.Summary.Gated,
		"gated_findings":     report.Summary.GatedFindingCount,
		"files":              files,
		"evidence_freshness": report.Summary.EvidenceFreshness,
		"vuln_source_used":   report.Summary.VulnSourceUsed,
	}
	data, err := json.MarshalIndent(runManifest, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal run manifest: %w", err)
	}
	wopts := fsutil.DefaultWriteOpts()
	wopts.Overwrite = true
	wopts.AllowSymlink = opts.allowSymlink
	if err := fsutil.SafeWriteFile(path, append(data, '\n'), wopts); err != nil {
		return fmt.Errorf("write run manifest: %w", err)
	}
	return nil
}
