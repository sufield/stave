package status

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sufield/stave/cmd/cmdutil/projctx"
	appstatus "github.com/sufield/stave/internal/app/status"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/pkg/jsonutil"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// config defines the parameters for the status check.
type config struct {
	Dir    string
	Format ui.OutputFormat
	Stdout io.Writer
	Stderr io.Writer
}

// State extends the domain ProjectState with CLI-specific session info.
type State struct {
	appstatus.ProjectState
	LastSession *projctx.SessionState `json:"last_session,omitempty"`
}

// Runner orchestrates the collection of project state and its presentation.
type Runner struct {
	Resolver *projctx.Resolver
}

// NewRunner initializes a status runner with the provided context resolver.
func NewRunner(r *projctx.Resolver) *Runner {
	return &Runner{Resolver: r}
}

// Run executes the project inspection and writes the report to the output stream.
func (r *Runner) Run(cfg config) error {
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
	return r.presentText(cfg.Stdout, state, result.NextCommand)
}

// statusResult is the JSON-serializable output combining state and recommendation.
type statusResult struct {
	State       State  `json:"state"`
	NextCommand string `json:"next_command"`
}

// Scan collects project artifact metadata from the filesystem.
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
		ProjectState: appstatus.ProjectState{
			Root:         root,
			Controls:     appstatus.Summary(controls),
			RawSnapshots: appstatus.Summary(raw),
			Observations: appstatus.Summary(obs),
			EvalTime:     evalTime,
			HasEval:      hasEval,
		},
		LastSession: last,
	}, nil
}

type localSummary struct {
	Count     int
	Latest    time.Time
	HasLatest bool
}

func (r *Runner) summarize(dir string, exts ...string) (localSummary, error) {
	var s localSummary
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

func (r *Runner) summarizeRecursive(dir string, exts ...string) (localSummary, error) {
	var s localSummary
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
