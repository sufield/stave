//go:build stavedev

package bugreport

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	appconfig "github.com/sufield/stave/internal/app/config"
	"github.com/sufield/stave/internal/doctor"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/metadata"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/internal/platform/scrub"
	staveversion "github.com/sufield/stave/internal/version"
)

// Config defines the inputs required to generate a bug report.
type Config struct {
	Cwd          string
	BinaryPath   string
	ConfigPath   string
	LogPath      string
	LogTailLines int
	Args         []string
	Env          []string
}

// Generator handles the creation of the diagnostic bundle.
type Generator struct {
	now func() time.Time
}

// NewGenerator returns a generator with default dependencies.
func NewGenerator() *Generator {
	return &Generator{
		now: func() time.Time { return time.Now().UTC() },
	}
}

// Generate orchestrates the collection of artifacts into a zip archive.
func (g *Generator) Generate(_ context.Context, w io.Writer, cfg Config) error {
	zw := zip.NewWriter(w)

	bundle := &bundleWriter{
		zip:      zw,
		files:    make([]string, 0, 8),
		warnings: make([]string, 0, 4),
		now:      g.now,
	}

	if err := g.addCoreArtifacts(bundle, cfg); err != nil {
		return err
	}
	if err := g.addConfigArtifact(bundle, cfg.ConfigPath); err != nil {
		return err
	}
	if err := g.addLogArtifact(bundle, cfg.LogPath, cfg.LogTailLines); err != nil {
		return err
	}
	if err := g.addManifest(bundle); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return fmt.Errorf("finalize bundle: %w", err)
	}
	return nil
}

func (g *Generator) addCoreArtifacts(bundle *bundleWriter, cfg Config) error {
	checks, ok := doctor.Run(&doctor.Context{
		Cwd:          cfg.Cwd,
		BinaryPath:   cfg.BinaryPath,
		StaveVersion: staveversion.Version,
	})
	if err := bundle.addJSON("doctor.json", DoctorResult{Ready: ok, Checks: checks}); err != nil {
		return fmt.Errorf("write doctor.json: %w", err)
	}
	if err := bundle.addJSON("build_info.json", CollectBuildInfo()); err != nil {
		return fmt.Errorf("write build_info.json: %w", err)
	}
	if err := bundle.addJSON("env.json", FilterEnv(cfg.Env)); err != nil {
		return fmt.Errorf("write env.json: %w", err)
	}
	if err := bundle.addJSON("args.json", SanitizeArgs(cfg.Args)); err != nil {
		return fmt.Errorf("write args.json: %w", err)
	}
	return nil
}

func (g *Generator) addConfigArtifact(bundle *bundleWriter, path string) error {
	if path == "" {
		return nil
	}
	cfgBytes, err := fsutil.ReadFileLimited(path)
	if err != nil {
		bundle.addWarning("skipped project config (%s): %v", path, err)
		return nil
	}
	var cfg appconfig.ProjectConfig
	if unmarshalErr := yaml.Unmarshal(cfgBytes, &cfg); unmarshalErr != nil {
		bundle.addWarning("skipped project config (%s): parse error: %v", path, unmarshalErr)
		return nil
	}
	sanitized, marshalErr := yaml.Marshal(&cfg)
	if marshalErr != nil {
		bundle.addWarning("skipped project config (%s): marshal error: %v", path, marshalErr)
		return nil
	}
	if err := bundle.addText("config/stave.yaml", sanitized); err != nil {
		return fmt.Errorf("write config/stave.yaml: %w", err)
	}
	return nil
}

func (g *Generator) addLogArtifact(bundle *bundleWriter, path string, tailCount int) error {
	if path == "" {
		return nil
	}
	logBytes, err := fsutil.ReadFileLimited(path)
	if err != nil {
		bundle.addWarning("skipped log tail (%s): %v", path, err)
		return nil
	}
	sanitized := SanitizeLogTail(logBytes, tailCount)
	if err := bundle.addText("logs/stave.log.tail.txt", sanitized); err != nil {
		return fmt.Errorf("write logs/stave.log.tail.txt: %w", err)
	}
	return nil
}

// SanitizeLogTail truncates log data to the last N lines and scrubs credentials.
func SanitizeLogTail(data []byte, maxLines int) []byte {
	tail := TailBytesByLine(data, maxLines)
	return scrub.Credentials(tail)
}

func (g *Generator) addManifest(bundle *bundleWriter) error {
	sort.Strings(bundle.files)
	manifestFiles := append([]string(nil), bundle.files...)
	m := manifest{
		BundleVersion: kernel.SchemaBugReport,
		GeneratedAt:   g.now(),
		StaveVersion:  staveversion.Version,
		Sanitized:     true,
		Files:         manifestFiles,
		Warnings:      bundle.warnings,
		IssueURL:      metadata.IssuesRef(),
	}
	if err := bundle.addJSON("manifest.json", m); err != nil {
		return fmt.Errorf("write manifest.json: %w", err)
	}
	return nil
}

// --- Internal helpers ---

type bundleWriter struct {
	zip      *zip.Writer
	files    []string
	warnings []string
	now      func() time.Time
}

func (w *bundleWriter) addJSON(name string, payload any) error {
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	return w.addText(name, append(data, '\n'))
}

func (w *bundleWriter) addText(name string, data []byte) error {
	h := &zip.FileHeader{
		Name:     name,
		Method:   zip.Deflate,
		Modified: w.now(),
	}
	h.SetMode(0o600)
	f, err := w.zip.CreateHeader(h)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		return err
	}
	w.files = append(w.files, name)
	return nil
}

func (w *bundleWriter) addWarning(format string, args ...any) {
	w.warnings = append(w.warnings, fmt.Sprintf(format, args...))
}

type manifest struct {
	BundleVersion kernel.Schema `json:"bundle_version"`
	GeneratedAt   time.Time     `json:"generated_at"`
	StaveVersion  string        `json:"stave_version"`
	Sanitized     bool          `json:"sanitized"`
	Files         []string      `json:"files"`
	Warnings      []string      `json:"warnings,omitempty"`
	IssueURL      string        `json:"issue_url"`
}

// ResolveDefaultOutPath generates a timestamped filename for the diagnostic bundle.
// When now is zero, the current wall clock is used.
func ResolveDefaultOutPath(cwd, override string, now time.Time) string {
	if strings.TrimSpace(override) != "" {
		return override
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	name := fmt.Sprintf("stave-diag-%s.zip", now.UTC().Format("20060102T150405Z"))
	return filepath.Join(cwd, name)
}

// WriteSummary outputs a user-friendly completion message to the provided writer.
func WriteSummary(w io.Writer, outPath string) {
	fmt.Fprintf(w, "Created diagnostic bundle: %s\n", outPath)
	fmt.Fprintf(w, "Attach this file when filing an issue: %s\n", metadata.IssuesRef())
	fmt.Fprintf(w, "\nTo view bundle contents:\n  stave bug-report inspect %s\n", outPath)
}
