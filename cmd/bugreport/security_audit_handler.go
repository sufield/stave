package bugreport

import (
	"context"
	"encoding/json"
	"fmt"
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

var securityAuditFlags securityAuditFlagsType

func runSecurityAudit(cmd *cobra.Command, _ []string) error {
	format, err := parseSecurityAuditFormat(securityAuditFlags.format)
	if err != nil {
		return err
	}
	severityFilter, err := securityaudit.ParseSeverityList(securityAuditFlags.severity)
	if err != nil {
		return &ui.InputError{Err: fmt.Errorf("invalid --severity: %w", err)}
	}
	failOn, err := securityaudit.ParseFailOnSeverity(securityAuditFlags.failOn)
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
	bundleDir := resolveSecurityAuditOutDir(now)

	runner := appsa.NewSecurityAuditRunner(govulncheck.Run)
	report, artifacts, err := runner.Run(context.Background(), appsa.SecurityAuditRequest{
		Now:                  now,
		ToolVersion:          staveversion.Version,
		Cwd:                  cwd,
		BinaryPath:           exe,
		OutDir:               bundleDir,
		SeverityFilter:       severityFilter,
		SBOMFormat:           securityAuditFlags.sbom,
		ComplianceFrameworks: securityAuditFlags.frameworks,
		VulnSource:           securityAuditFlags.vulnSource,
		LiveVulnCheck:        securityAuditFlags.liveVulnCheck,
		ReleaseBundleDir:     fsutil.CleanUserPath(securityAuditFlags.releaseBundleDir),
		PrivacyMode:          securityAuditFlags.privacyMode,
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

	mainOutPath, err := writeSecurityAuditBundle(cmd, bundleDir, mainName, mainData, report, artifacts)
	if err != nil {
		return err
	}

	if !cmdutil.QuietEnabled(cmd) {
		printSecurityAuditSummary(cmd, mainOutPath, bundleDir, report.Summary)
	}

	if report.Summary.Gated {
		return ui.ErrSecurityAuditFindings
	}
	return nil
}

func writeSecurityAuditBundle(cmd *cobra.Command, bundleDir, mainName string, mainData []byte, report securityaudit.Report, artifacts securityaudit.ArtifactManifest) (string, error) {
	if err := fsutil.SafeMkdirAll(bundleDir, fsutil.WriteOptions{
		Perm:         0o700,
		AllowSymlink: cmdutil.AllowSymlinkOutEnabled(cmd),
	}); err != nil {
		return "", fmt.Errorf("create bundle directory: %w", err)
	}

	mainBundlePath := filepath.Join(bundleDir, mainName)
	if err := writeOutputFile(cmd, mainBundlePath, mainData); err != nil {
		return "", err
	}

	mainOutPath := resolveSecurityAuditOutPath(mainBundlePath)
	if mainOutPath != mainBundlePath {
		if err := writeOutputFile(cmd, mainOutPath, mainData); err != nil {
			return "", err
		}
	}

	for _, artifact := range artifacts.Files {
		target := filepath.Join(bundleDir, artifact.Path)
		if err := writeOutputFile(cmd, target, artifact.Content); err != nil {
			return "", err
		}
	}

	runManifestPath := filepath.Join(bundleDir, "run_manifest.json")
	if err := writeRunManifest(cmd, runManifestPath, bundleDir, mainName, report); err != nil {
		return "", err
	}

	return mainOutPath, nil
}

func printSecurityAuditSummary(cmd *cobra.Command, mainOutPath, bundleDir string, summary securityaudit.Summary) {
	w := cmd.OutOrStdout()
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

func resolveSecurityAuditOutDir(now time.Time) string {
	outDir := fsutil.CleanUserPath(securityAuditFlags.outDir)
	if strings.TrimSpace(outDir) != "" {
		return outDir
	}
	return fmt.Sprintf("security-audit-%s", now.UTC().Format("20060102T150405Z"))
}

func resolveSecurityAuditOutPath(defaultPath string) string {
	outPath := fsutil.CleanUserPath(securityAuditFlags.out)
	if strings.TrimSpace(outPath) == "" {
		return defaultPath
	}
	return outPath
}

func writeOutputFile(cmd *cobra.Command, path string, data []byte) error {
	parent := filepath.Dir(path)
	if strings.TrimSpace(parent) != "" && parent != "." {
		if err := fsutil.SafeMkdirAll(parent, fsutil.WriteOptions{
			Perm:         0o700,
			AllowSymlink: cmdutil.AllowSymlinkOutEnabled(cmd),
		}); err != nil {
			return fmt.Errorf("create output directory %q: %w", parent, err)
		}
	}
	opts := fsutil.DefaultWriteOpts()
	opts.Overwrite = cmdutil.ForceEnabled(cmd)
	opts.AllowSymlink = cmdutil.AllowSymlinkOutEnabled(cmd)
	if err := fsutil.SafeWriteFile(path, data, opts); err != nil {
		return fmt.Errorf("write output %q: %w", path, err)
	}
	return nil
}

func writeRunManifest(cmd *cobra.Command, path string, bundleDir string, mainReport string, report securityaudit.Report) error {
	entries, err := os.ReadDir(bundleDir)
	if err != nil {
		return fmt.Errorf("read bundle directory: %w", err)
	}
	type manifestFile struct {
		Path      string `json:"path"`
		SHA256    string `json:"sha256"`
		SizeBytes int64  `json:"size_bytes"`
	}
	files := make([]manifestFile, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		filePath := filepath.Join(bundleDir, entry.Name())
		hash, hashErr := fsutil.HashFile(filePath)
		if hashErr != nil {
			return fmt.Errorf("hash bundle file %q: %w", filePath, hashErr)
		}
		info, infoErr := entry.Info()
		if infoErr != nil {
			return fmt.Errorf("read bundle file info %q: %w", filePath, infoErr)
		}
		files = append(files, manifestFile{
			Path:      entry.Name(),
			SHA256:    string(hash),
			SizeBytes: info.Size(),
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
	opts := fsutil.DefaultWriteOpts()
	opts.Overwrite = true
	opts.AllowSymlink = cmdutil.AllowSymlinkOutEnabled(cmd)
	if err := fsutil.SafeWriteFile(path, append(data, '\n'), opts); err != nil {
		return fmt.Errorf("write run manifest: %w", err)
	}
	return nil
}
