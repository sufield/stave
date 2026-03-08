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
	"gopkg.in/yaml.v3"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/policy"
	"github.com/sufield/stave/internal/metadata"
	"github.com/sufield/stave/internal/platform/fsutil"
)

var (
	fmtCheck bool
)

var FmtCmd = &cobra.Command{
	Use:   "fmt <path>",
	Short: "Format control and observation files deterministically",
	Long: `Fmt normalizes file formatting for control YAML and observation JSON.

Rules:
  - .yaml/.yml files are parsed as ctrl.v1 controls and emitted in canonical field order
  - .json files are parsed as obs.v0.1 snapshots and emitted with stable indentation

Use --check to verify formatting without writing files.` + metadata.OfflineHelpSuffix,
	Args:          cobra.ExactArgs(1),
	RunE:          runFmt,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	FmtCmd.Flags().BoolVar(&fmtCheck, "check", false, "Check formatting only; do not write files")
}

func runFmt(cmd *cobra.Command, args []string) error {
	target := fsutil.CleanUserPath(args[0])
	files, err := collectFormatTargets(target)
	if err != nil {
		return err
	}
	changed, checked, err := applyFormattingToTargets(cmd, files, fmtCheck)
	if err != nil {
		return err
	}
	return writeFmtSummary(cmd.OutOrStdout(), changed, checked, fmtCheck)
}

func formatFile(path string) ([]byte, bool, error) {
	ext := strings.ToLower(filepath.Ext(path))
	data, err := fsutil.ReadFileLimited(path)
	if err != nil {
		return nil, false, err
	}
	switch ext {
	case ".json":
		out, err := formatObservationJSON(data)
		return out, false, err
	case ".yaml", ".yml":
		out, err := formatControlYAML(data)
		return out, false, err
	default:
		return nil, true, nil
	}
}

func collectFormatTargets(target string) ([]string, error) {
	info, err := os.Stat(target)
	if err != nil {
		return nil, err
	}
	files := make([]string, 0)
	if !info.IsDir() {
		return append(files, target), nil
	}
	err = filepath.WalkDir(target, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !isFormatSupportedExtension(path) {
			return nil
		}
		files = append(files, path)
		return nil
	})
	if err != nil {
		return nil, err
	}
	slices.Sort(files)
	return files, nil
}

func isFormatSupportedExtension(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".yaml", ".yml", ".json":
		return true
	default:
		return false
	}
}

func applyFormattingToTargets(cmd *cobra.Command, files []string, checkOnly bool) (int, int, error) {
	changed := 0
	checked := 0
	for _, path := range files {
		formatted, skip, err := formatFile(path)
		if err != nil {
			return 0, 0, fmt.Errorf("format %s: %w", path, err)
		}
		if skip {
			continue
		}
		checked++
		orig, err := fsutil.ReadFileLimited(path)
		if err != nil {
			return 0, 0, fmt.Errorf("read %s: %w", path, err)
		}
		if bytes.Equal(orig, formatted) {
			continue
		}
		changed++
		if checkOnly {
			continue
		}
		opts := fsutil.ConfigWriteOpts()
		opts.AllowSymlink = cmdutil.AllowSymlinkOutEnabled(cmd)
		if err := fsutil.SafeWriteFile(path, formatted, opts); err != nil {
			return 0, 0, fmt.Errorf("write %s: %w", path, err)
		}
	}
	return changed, checked, nil
}

func writeFmtSummary(w io.Writer, changed, checked int, checkOnly bool) error {
	if checkOnly {
		if changed > 0 {
			return fmt.Errorf("%d/%d file(s) require formatting", changed, checked)
		}
		fmt.Fprintf(w, "All %d file(s) already formatted.\n", checked)
		return nil
	}
	fmt.Fprintf(w, "Formatted %d/%d file(s).\n", changed, checked)
	return nil
}

func formatObservationJSON(data []byte) ([]byte, error) {
	var snap asset.Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, fmt.Errorf("parse observation json: %w", err)
	}
	out, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return nil, err
	}
	out = append(out, '\n')
	return out, nil
}

func formatControlYAML(data []byte) ([]byte, error) {
	var ctl policy.ControlDefinition
	if err := yaml.Unmarshal(data, &ctl); err != nil {
		return nil, fmt.Errorf("parse control yaml: %w", err)
	}
	out, err := yaml.Marshal(ctl)
	if err != nil {
		return nil, err
	}
	if len(out) == 0 || out[len(out)-1] != '\n' {
		out = append(out, '\n')
	}
	return out, nil
}
