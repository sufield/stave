package artifacts

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// FormatConfig defines the behavior of the formatting operation.
type FormatConfig struct {
	Target    string
	CheckOnly bool
	Stdout    io.Writer

	// ReadFile reads a file's contents. Injected by the caller to abstract
	// platform-specific read behavior (e.g. size limits).
	ReadFile func(path string) ([]byte, error)

	// WriteFile writes formatted data to a file. Injected by the caller
	// to abstract platform-specific write behavior (e.g. safe writes, symlink policy).
	// Only called when CheckOnly is false.
	WriteFile func(path string, data []byte) error
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
	files, err := CollectFormatTargets(cfg.Target)
	if err != nil {
		return FormatResult{}, err
	}

	readFn := cfg.ReadFile
	if readFn == nil {
		readFn = os.ReadFile
	}

	res := FormatResult{TotalFiles: len(files)}

	for _, path := range files {
		changed, procErr := f.processFile(path, cfg, readFn)
		if procErr != nil {
			return res, procErr
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

func (f *Formatter) processFile(path string, cfg FormatConfig, readFn func(string) ([]byte, error)) (bool, error) {
	orig, err := readFn(path)
	if err != nil {
		return false, fmt.Errorf("reading %s: %w", path, err)
	}

	formatted, err := FormatByExtension(path, orig)
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

	if cfg.WriteFile != nil {
		if err := cfg.WriteFile(path, formatted); err != nil {
			return true, fmt.Errorf("writing %s: %w", path, err)
		}
	}

	return true, nil
}

// CollectFormatTargets discovers JSON and YAML files under the given path.
func CollectFormatTargets(target string) ([]string, error) {
	info, err := os.Stat(target)
	if err != nil {
		return nil, err
	}

	if !info.IsDir() {
		return []string{target}, nil
	}

	var files []string
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
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".json" || ext == ".yaml" || ext == ".yml" {
			files = append(files, path)
		}
		return nil
	})

	slices.Sort(files)
	return files, err
}
