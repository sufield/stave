package securityaudit

import (
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

type fileWriteOpts struct {
	force        bool
	allowSymlink bool
}

type writtenFile struct {
	name    string
	content []byte
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
	now, err := cmdutil.ResolveNow(c.flags.nowTime)
	if err != nil {
		return &ui.InputError{Err: err}
	}
	bundleDir := c.resolveOutDir(now)

	opts := fileWriteOpts{
		force:        cmdutil.ForceEnabled(cmd),
		allowSymlink: cmdutil.AllowSymlinkOutEnabled(cmd),
	}

	runner := appsa.NewSecurityAuditRunner(govulncheck.Run, nil)
	report, artifacts, err := runner.Run(cmd.Context(), appsa.SecurityAuditRequest{
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

	mainData, mainName, err := renderReport(format, report)
	if err != nil {
		return err
	}

	mainOutPath, err := writeBundle(opts, now, bundleDir, mainName, mainData, report, artifacts, c.resolveOutPath)
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

func writeBundle(opts fileWriteOpts, now time.Time, bundleDir, mainName string, mainData []byte, report domainsecurityaudit.Report, artifacts domainsecurityaudit.ArtifactManifest, resolveOutPath func(string) string) (string, error) {
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
	if err := writeRunManifest(opts, runManifestPath, now, bundleDir, mainName, written, report); err != nil {
		return "", err
	}

	return mainOutPath, nil
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

type runManifest struct {
	SchemaVersion     string         `json:"schema_version"`
	GeneratedAt       string         `json:"generated_at"`
	MainReport        string         `json:"main_report"`
	BundleDir         string         `json:"bundle_dir"`
	ToolVersion       string         `json:"tool_version"`
	FailOn            string         `json:"fail_on"`
	Gated             bool           `json:"gated"`
	GatedFindings     int            `json:"gated_findings"`
	Files             []manifestFile `json:"files"`
	EvidenceFreshness string         `json:"evidence_freshness"`
	VulnSourceUsed    string         `json:"vuln_source_used"`
}

func writeRunManifest(opts fileWriteOpts, path string, now time.Time, bundleDir string, mainReport string, written []writtenFile, report domainsecurityaudit.Report) error {
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

	manifest := runManifest{
		SchemaVersion:     string(kernel.SchemaSecurityAuditRunManifest),
		GeneratedAt:       now.Format(time.RFC3339),
		MainReport:        mainReport,
		BundleDir:         bundleDir,
		ToolVersion:       report.ToolVersion,
		FailOn:            string(report.Summary.FailOn),
		Gated:             report.Summary.Gated,
		GatedFindings:     report.Summary.GatedFindingCount,
		Files:             files,
		EvidenceFreshness: report.Summary.EvidenceFreshness,
		VulnSourceUsed:    report.Summary.VulnSourceUsed,
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
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
