package status

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sufield/stave/cmd/cmdutil/projctx"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/pkg/jsonutil"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// Config defines the parameters for the status check.
type Config struct {
	Dir    string
	Format ui.OutputFormat
	Stdout io.Writer
	Stderr io.Writer
}

// --- Domain Models ---

// Summary captures metadata about a group of files (e.g., controls or observations).
type Summary struct {
	Count     int       `json:"count"`
	Latest    time.Time `json:"latest"`
	HasLatest bool      `json:"has_latest"`
}

// State represents the point-in-time health and progress of a project.
type State struct {
	Root         string                `json:"project_root"`
	LastSession  *projctx.SessionState `json:"last_session,omitempty"`
	Controls     Summary               `json:"controls"`
	RawSnapshots Summary               `json:"snapshots_raw"`
	Observations Summary               `json:"observations"`
	EvalTime     time.Time             `json:"evaluation_time"`
	HasEval      bool                  `json:"has_evaluation"`
}

// RecommendNext returns a string command suggesting the most logical next step.
func (s State) RecommendNext() string {
	ctlDir := filepath.Join(s.Root, "controls")
	obsDir := filepath.Join(s.Root, "observations")
	outPath := filepath.Join(s.Root, "output", "evaluation.json")

	if s.RawSnapshots.Count > 0 && (s.Observations.Count == 0 || s.isRawNewerThanObs()) {
		return fmt.Sprintf("Create observation snapshots in %s from your AWS environment data", obsDir)
	}
	if s.Controls.Count == 0 {
		return fmt.Sprintf("stave generate control --id CTL.S3.PUBLIC.901 --out %s", filepath.Join(ctlDir, "CTL.S3.PUBLIC.901.yaml"))
	}
	if s.Observations.Count == 0 {
		return fmt.Sprintf("Create observation snapshots in %s from your AWS environment data", obsDir)
	}
	if s.needsReevaluation() {
		return fmt.Sprintf("stave validate --controls %s --observations %s && stave apply --controls %s --observations %s --format json > %s",
			ctlDir, obsDir, ctlDir, obsDir, outPath)
	}
	return fmt.Sprintf("stave diagnose --controls %s --observations %s --previous-output %s",
		ctlDir, obsDir, outPath)
}

func (s State) isRawNewerThanObs() bool {
	return s.RawSnapshots.HasLatest &&
		s.Observations.HasLatest &&
		s.RawSnapshots.Latest.After(s.Observations.Latest)
}

func (s State) needsReevaluation() bool {
	if !s.HasEval {
		return true
	}
	latestInput := s.Controls.Latest
	if s.Observations.HasLatest && s.Observations.Latest.After(latestInput) {
		latestInput = s.Observations.Latest
	}
	return latestInput.After(s.EvalTime)
}

// --- Logic Runner ---

// Runner orchestrates the collection of project state and its presentation.
type Runner struct {
	Resolver *projctx.Resolver
}

// NewRunner initializes a status runner with the provided context resolver.
func NewRunner(r *projctx.Resolver) *Runner {
	return &Runner{Resolver: r}
}

// Run executes the project inspection and writes the report to the output stream.
func (r *Runner) Run(_ context.Context, cfg Config) error {
	dir := fsutil.CleanUserPath(cfg.Dir)

	root, err := r.Resolver.DetectProjectRoot(dir)
	if err != nil {
		return ui.WithNextCommand(err, "stave init")
	}

	state, err := r.Scan(root)
	if err != nil {
		return fmt.Errorf("scanning project: %w", err)
	}

	result := statusResult{
		State:       state,
		NextCommand: state.RecommendNext(),
	}

	if cfg.Format.IsJSON() {
		return jsonutil.WriteIndented(cfg.Stdout, result)
	}
	return r.presentText(cfg.Stdout, result.State, result.NextCommand)
}

// statusResult is the JSON-serializable output combining state and recommendation.
type statusResult struct {
	State       State  `json:"state"`
	NextCommand string `json:"next_command"`
}

// --- Infrastructure: Filesystem Scanner ---

// Scan collects project artifact metadata from the filesystem.
// Missing directories are treated as empty (valid for new projects).
// Permission or other filesystem errors are surfaced.
func (r *Runner) Scan(root string) (State, error) {
	controls, err := r.summarize(filepath.Join(root, "controls"), ".yaml", ".yml")
	if err != nil && !os.IsNotExist(err) {
		return State{}, fmt.Errorf("scan controls: %w", err)
	}
	raw, err := r.summarizeRecursive(filepath.Join(root, "snapshots", "raw"), ".json")
	if err != nil && !os.IsNotExist(err) {
		return State{}, fmt.Errorf("scan raw snapshots: %w", err)
	}
	obs, err := r.summarize(filepath.Join(root, "observations"), ".json")
	if err != nil && !os.IsNotExist(err) {
		return State{}, fmt.Errorf("scan observations: %w", err)
	}

	evalPath := filepath.Join(root, "output", "evaluation.json")
	evalTime, hasEval := r.fileModTime(evalPath)

	last, sessErr := projctx.LoadSession(root)
	if sessErr != nil && !os.IsNotExist(sessErr) {
		return State{}, fmt.Errorf("load session: %w", sessErr)
	}

	return State{
		Root:         root,
		LastSession:  last,
		Controls:     controls,
		RawSnapshots: raw,
		Observations: obs,
		EvalTime:     evalTime,
		HasEval:      hasEval,
	}, nil
}

func (r *Runner) summarize(dir string, exts ...string) (Summary, error) {
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

// summarizeRecursive walks a directory tree and counts files matching the given extensions.
func (r *Runner) summarizeRecursive(dir string, exts ...string) (Summary, error) {
	var s Summary
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err // surface permission and other real errors
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

func (r *Runner) fileModTime(path string) (time.Time, bool) {
	fi, err := os.Stat(path)
	if err != nil || fi.IsDir() {
		return time.Time{}, false
	}
	return fi.ModTime(), true
}

// --- Presentation ---

func (r *Runner) presentText(w io.Writer, s State, next string) error {
	fmt.Fprintf(w, "Summary\n-------\n")
	fmt.Fprintf(w, "Project: %s\n", s.Root)

	if s.LastSession != nil {
		fmt.Fprintf(w, "Last command: %s (%s)\n",
			s.LastSession.LastCommand,
			s.LastSession.WhenUTC.Format(time.RFC3339))
	}

	fmt.Fprintln(w, "Artifacts:")
	fmt.Fprintf(w, "  - controls: %d\n", s.Controls.Count)
	fmt.Fprintf(w, "  - snapshots/raw: %d\n", s.RawSnapshots.Count)
	fmt.Fprintf(w, "  - observations: %d\n", s.Observations.Count)
	fmt.Fprintf(w, "  - output/evaluation.json: %v\n", s.HasEval)

	label := ui.SeverityLabel("info", fmt.Sprintf("Next: %s", next), w)
	fmt.Fprintf(w, "\n%s\n", label)
	return nil
}
