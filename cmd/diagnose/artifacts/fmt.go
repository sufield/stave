//go:build stavedev

package artifacts

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/metadata"
	"github.com/sufield/stave/internal/platform/fsutil"
	"gopkg.in/yaml.v3"
)

// FormatConfig defines the behavior of the formatting operation.
type FormatConfig struct {
	Target        string
	CheckOnly     bool
	AllowSymlinks bool
	Stdout        io.Writer
}

// FormatResult captures the metrics of a formatting run.
type FormatResult struct {
	TotalFiles   int
	ChangedFiles int
}

// Formatter manages the deterministic formatting of Stave artifacts.
type Formatter struct{}

// NewFormatter creates a new Formatter.
func NewFormatter() *Formatter {
	return &Formatter{}
}

// Run executes the formatting process based on the provided configuration.
func (f *Formatter) Run(cfg FormatConfig) (FormatResult, error) {
	files, err := f.collectTargets(cfg.Target)
	if err != nil {
		return FormatResult{}, err
	}

	res := FormatResult{TotalFiles: len(files)}

	for _, path := range files {
		changed, err := f.processFile(path, cfg)
		if err != nil {
			return res, err
		}
		if changed {
			res.ChangedFiles++
		}
	}

	if cfg.CheckOnly {
		if res.ChangedFiles > 0 {
			return res, fmt.Errorf("%d/%d file(s) require formatting", res.ChangedFiles, res.TotalFiles)
		}
		fmt.Fprintf(cfg.Stdout, "All %d file(s) already formatted.\n", res.TotalFiles)
	} else {
		fmt.Fprintf(cfg.Stdout, "Formatted %d/%d file(s).\n", res.ChangedFiles, res.TotalFiles)
	}

	return res, nil
}

func (f *Formatter) processFile(path string, cfg FormatConfig) (bool, error) {
	orig, err := fsutil.ReadFileLimited(path)
	if err != nil {
		return false, fmt.Errorf("reading %s: %w", path, err)
	}

	formatted, err := f.formatByExtension(path, orig)
	if err != nil {
		return false, fmt.Errorf("parsing %s: %w", path, err)
	}
	if formatted == nil {
		return false, nil
	}

	if bytes.Equal(orig, formatted) {
		return false, nil
	}

	if cfg.CheckOnly {
		return true, nil
	}

	opts := fsutil.ConfigWriteOpts()
	opts.AllowSymlink = cfg.AllowSymlinks
	if err := fsutil.SafeWriteFile(path, formatted, opts); err != nil {
		return true, fmt.Errorf("writing %s: %w", path, err)
	}

	return true, nil
}

func (f *Formatter) formatByExtension(path string, data []byte) ([]byte, error) {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		return f.formatJSON(data)
	case ".yaml", ".yml":
		return f.formatYAML(data)
	default:
		return nil, nil
	}
}

func (f *Formatter) collectTargets(target string) ([]string, error) {
	clean := fsutil.CleanUserPath(target)
	info, err := os.Stat(clean)
	if err != nil {
		return nil, err
	}

	if !info.IsDir() {
		return []string{clean}, nil
	}

	var files []string
	err = filepath.WalkDir(clean, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".json" || ext == ".yaml" || ext == ".yml" {
			files = append(files, path)
		}
		return nil
	})

	slices.Sort(files)
	return files, err
}

func (f *Formatter) formatJSON(data []byte) ([]byte, error) {
	var snap asset.Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, fmt.Errorf("parse observation json: %w", err)
	}
	out, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

func (f *Formatter) formatYAML(data []byte) ([]byte, error) {
	var dto any
	if err := yaml.Unmarshal(data, &dto); err != nil {
		return nil, fmt.Errorf("parse control yaml: %w", err)
	}
	out, err := yaml.Marshal(dto)
	if err != nil {
		return nil, fmt.Errorf("parse control yaml: %w", err)
	}
	if len(out) == 0 || out[len(out)-1] != '\n' {
		out = append(out, '\n')
	}
	return out, nil
}

// --- Cobra Command Constructor ---

// NewFmtCmd constructs the fmt command with closure-scoped flags.
func NewFmtCmd() *cobra.Command {
	var checkOnly bool

	cmd := &cobra.Command{
		Use:   "fmt <path>",
		Short: "Format control and observation files deterministically",
		Long: `Fmt normalizes file formatting for control YAML and observation JSON.

Rules:
  - .yaml/.yml files are parsed as ctrl.v1 controls and emitted in canonical field order
  - .json files are parsed as obs.v0.1 snapshots and emitted with stable indentation

Use --check to verify formatting without writing files.` + metadata.OfflineHelpSuffix,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := FormatConfig{
				Target:        args[0],
				CheckOnly:     checkOnly,
				AllowSymlinks: cmdutil.GetGlobalFlags(cmd).AllowSymlinkOut,
				Stdout:        cmd.OutOrStdout(),
			}
			formatter := NewFormatter()
			_, err := formatter.Run(cfg)
			return err
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.Flags().BoolVar(&checkOnly, "check", false, "Check formatting only; do not write files")

	return cmd
}
