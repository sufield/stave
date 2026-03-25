package status

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Scanner collects project artifact metadata from the filesystem.
type Scanner struct{}

// NewScanner creates a scanner instance.
func NewScanner() *Scanner {
	return &Scanner{}
}

// Scan inspects a project root and returns the aggregate artifact state.
// Session info (LastCommand, LastCommandTime) is not set by Scan — the
// caller is responsible for populating those fields from the CLI layer.
func (sc *Scanner) Scan(root string) (ProjectState, error) {
	controls, err := sc.summarize(filepath.Join(root, "controls"), ".yaml", ".yml")
	if err != nil && !os.IsNotExist(err) {
		return ProjectState{}, fmt.Errorf("scan controls: %w", err)
	}
	raw, err := sc.summarizeRecursive(filepath.Join(root, "snapshots", "raw"), ".json")
	if err != nil && !os.IsNotExist(err) {
		return ProjectState{}, fmt.Errorf("scan raw snapshots: %w", err)
	}
	obs, err := sc.summarize(filepath.Join(root, "observations"), ".json")
	if err != nil && !os.IsNotExist(err) {
		return ProjectState{}, fmt.Errorf("scan observations: %w", err)
	}

	evalPath := filepath.Join(root, "output", "evaluation.json")
	evalTime, hasEval := sc.fileModTime(evalPath)

	return ProjectState{
		Root:         root,
		Controls:     controls,
		RawSnapshots: raw,
		Observations: obs,
		EvalTime:     evalTime,
		HasEval:      hasEval,
	}, nil
}

func (sc *Scanner) summarize(dir string, exts ...string) (Summary, error) {
	var s Summary
	entries, err := os.ReadDir(dir)
	if err != nil {
		return s, err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if len(exts) > 0 && !matchesExtension(e.Name(), exts) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			return s, fmt.Errorf("stat %s: %w", e.Name(), err)
		}
		s.Count++
		if !s.HasLatest || info.ModTime().After(s.Latest) {
			s.Latest = info.ModTime()
			s.HasLatest = true
		}
	}
	return s, nil
}

func (sc *Scanner) summarizeRecursive(dir string, exts ...string) (Summary, error) {
	var s Summary
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if d.IsDir() {
			return nil
		}
		if len(exts) > 0 && !matchesExtension(d.Name(), exts) {
			return nil
		}
		info, infoErr := d.Info()
		if infoErr != nil {
			return fmt.Errorf("stat %s: %w", path, infoErr)
		}
		s.Count++
		if !s.HasLatest || info.ModTime().After(s.Latest) {
			s.Latest = info.ModTime()
			s.HasLatest = true
		}
		return nil
	})
	return s, err
}

func matchesExtension(name string, exts []string) bool {
	for _, ext := range exts {
		if strings.HasSuffix(name, ext) {
			return true
		}
	}
	return false
}

func (sc *Scanner) fileModTime(path string) (time.Time, bool) {
	fi, err := os.Stat(path)
	if err != nil || fi.IsDir() {
		return time.Time{}, false
	}
	return fi.ModTime(), true
}
