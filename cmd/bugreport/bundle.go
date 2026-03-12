package bugreport

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	"github.com/sufield/stave/internal/doctor"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/metadata"
	"github.com/sufield/stave/internal/platform/fsutil"
	staveversion "github.com/sufield/stave/internal/version"
)

type manifest struct {
	BundleVersion kernel.Schema `json:"bundle_version"`
	GeneratedAt   string        `json:"generated_at"`
	StaveVersion  string        `json:"stave_version"`
	Sanitized     bool          `json:"sanitized"`
	Files         []string      `json:"files"`
	Warnings      []string      `json:"warnings,omitempty"`
	IssueURL      string        `json:"issue_url"`
}

type bundleWriter struct {
	zip      *zip.Writer
	files    []string
	warnings []string
}

func newBundleWriter(zw *zip.Writer) *bundleWriter {
	return &bundleWriter{
		zip:      zw,
		files:    make([]string, 0, 8),
		warnings: make([]string, 0, 4),
	}
}

func (w *bundleWriter) addJSON(name string, payload any) error {
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := addZipFile(w.zip, name, data); err != nil {
		return err
	}
	w.files = append(w.files, name)
	return nil
}

func (w *bundleWriter) addText(name string, data []byte) error {
	if err := addZipFile(w.zip, name, data); err != nil {
		return err
	}
	w.files = append(w.files, name)
	return nil
}

func (w *bundleWriter) addWarning(format string, args ...any) {
	w.warnings = append(w.warnings, fmt.Sprintf(format, args...))
}

func addZipFile(zw *zip.Writer, name string, data []byte) error {
	h := &zip.FileHeader{
		Name:     name,
		Method:   zip.Deflate,
		Modified: time.Now().UTC(),
	}
	h.SetMode(0o600)
	w, err := zw.CreateHeader(h)
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

func addCoreArtifacts(bundle *bundleWriter, cwd string) error {
	binaryPath, _ := os.Executable()
	checks, ok := doctor.Run(&doctor.Context{
		Cwd:          cwd,
		BinaryPath:   binaryPath,
		StaveVersion: staveversion.Version,
	})
	if err := bundle.addJSON("doctor.json", doctorResult{Ready: ok, Checks: checks}); err != nil {
		return fmt.Errorf("write doctor.json: %w", err)
	}
	if err := bundle.addJSON("build_info.json", collectBuildInfo()); err != nil {
		return fmt.Errorf("write build_info.json: %w", err)
	}
	if err := bundle.addJSON("env.json", collectEnv()); err != nil {
		return fmt.Errorf("write env.json: %w", err)
	}
	if err := bundle.addJSON("args.json", collectArgs()); err != nil {
		return fmt.Errorf("write args.json: %w", err)
	}
	return nil
}

func addConfigArtifact(bundle *bundleWriter) error {
	cfgPath, ok := findConfigPath()
	if !ok {
		return nil
	}
	cfgBytes, err := fsutil.ReadFileLimited(cfgPath)
	if err != nil {
		bundle.addWarning("skipped project config (%s): %v", cfgPath, err)
		return nil
	}
	// Parse into the known ProjectConfig struct and re-serialize.
	// Only recognized fields appear in the output — unknown fields
	// (which might contain secrets) are dropped entirely.
	var cfg projconfig.ProjectConfig
	if err = yaml.Unmarshal(cfgBytes, &cfg); err != nil {
		bundle.addWarning("skipped project config (%s): parse error: %v", cfgPath, err)
		return nil
	}
	sanitized, err := yaml.Marshal(&cfg)
	if err != nil {
		bundle.addWarning("skipped project config (%s): marshal error: %v", cfgPath, err)
		return nil
	}
	if err := bundle.addText("config/stave.yaml", sanitized); err != nil {
		return fmt.Errorf("write config/stave.yaml: %w", err)
	}
	return nil
}

func addLogArtifact(cmd *cobra.Command, bundle *bundleWriter, cwd string, tailLineCount int) error {
	logPath, ok := findLogPath(cmd, cwd)
	if !ok {
		return nil
	}
	logBytes, err := fsutil.ReadFileLimited(logPath)
	if err != nil {
		bundle.addWarning("skipped log tail (%s): %v", logPath, err)
		return nil
	}
	tail := tailBytesByLine(logBytes, tailLineCount)
	tail = redactCredentialFormats(tail)
	if err := bundle.addText("logs/stave.log.tail.txt", tail); err != nil {
		return fmt.Errorf("write logs/stave.log.tail.txt: %w", err)
	}
	return nil
}

func addManifest(bundle *bundleWriter) error {
	sort.Strings(bundle.files)
	manifestFiles := append([]string(nil), bundle.files...)
	m := manifest{
		BundleVersion: kernel.SchemaBugReport,
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
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
