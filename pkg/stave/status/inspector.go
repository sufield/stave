package status

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Inspector collects project artifact metadata from the filesystem.
type Inspector struct {
	// StatFn abstracts os.Stat for testing. Defaults to os.Stat.
	StatFn func(string) (os.FileInfo, error)
}

// NewInspector creates an inspector with default OS filesystem access.
func NewInspector() *Inspector {
	return &Inspector{StatFn: os.Stat}
}

func (in *Inspector) stat(path string) (os.FileInfo, error) {
	if in.StatFn != nil {
		return in.StatFn(path)
	}
	return os.Stat(path) //nolint:wrapcheck // os.Stat returns *PathError; callers check os.IsNotExist
}

// Inspect inspects a project root and returns the aggregate artifact state.
// Session info (LastCommand, LastCommandTime) is not set by Inspect — the
// caller is responsible for populating those fields from the CLI layer.
func (in *Inspector) Inspect(root string) (ProjectState, error) {
	controls, err := in.summarize(filepath.Join(root, "controls"), ".yaml", ".yml")
	if err != nil && !os.IsNotExist(err) {
		return ProjectState{}, fmt.Errorf("inspect controls: %w", err)
	}
	raw, err := in.summarizeRecursive(filepath.Join(root, "snapshots", "raw"), ".json")
	if err != nil && !os.IsNotExist(err) {
		return ProjectState{}, fmt.Errorf("inspect raw snapshots: %w", err)
	}
	obs, err := in.summarize(filepath.Join(root, "observations"), ".json")
	if err != nil && !os.IsNotExist(err) {
		return ProjectState{}, fmt.Errorf("inspect observations: %w", err)
	}

	evalPath := filepath.Join(root, "output", "evaluation.json")
	evalTime, hasEval := in.fileModTime(evalPath)

	return ProjectState{
		Root:         root,
		Controls:     controls,
		RawSnapshots: raw,
		Observations: obs,
		EvalTime:     evalTime,
		HasEval:      hasEval,
	}, nil
}

func (in *Inspector) summarize(dir string, exts ...string) (Summary, error) {
	var s Summary
	entries, err := os.ReadDir(dir)
	if err != nil {
		return s, err //nolint:wrapcheck // os.ReadDir returns *PathError; callers check os.IsNotExist
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

func (in *Inspector) summarizeRecursive(dir string, exts ...string) (Summary, error) {
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
	if err != nil {
		return s, fmt.Errorf("walk dir: %w", err)
	}
	return s, nil
}

func matchesExtension(name string, exts []string) bool {
	for _, ext := range exts {
		if strings.HasSuffix(strings.ToLower(name), strings.ToLower(ext)) {
			return true
		}
	}
	return false
}

func (in *Inspector) fileModTime(path string) (time.Time, bool) {
	fi, err := in.stat(path)
	if err != nil || fi.IsDir() {
		return time.Time{}, false
	}
	return fi.ModTime(), true
}
