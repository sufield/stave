// Package projctx provides project context resolution, path inference,
// and session state management for cmd sub-packages.
package projctx

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	contexts "github.com/sufield/stave/internal/config"
	"github.com/sufield/stave/internal/pathinfer"
	"github.com/sufield/stave/internal/platform/fsutil"
)

const SessionFileRel = ".stave/session.json"

// ErrNotInProject is returned when the current directory is not inside a Stave project.
var ErrNotInProject = errors.New("not inside a Stave project; run `stave init` first")

const InferMaxDepth = 3

// SessionState holds the last command and time for session persistence.
type SessionState struct {
	LastCommand string    `json:"last_command"`
	WhenUTC     time.Time `json:"when_utc"`
}

// InferAttempt records a path inference attempt for diagnostics.
type InferAttempt struct {
	FlagName   string
	DirName    string
	Base       string
	Searched   string
	Candidates []string
	Error      string
	Resolved   string
}

// InferenceLog records path inference attempts for diagnostics.
// Create one per command invocation; it replaces the former package-level map.
type InferenceLog struct {
	attempts map[string]InferAttempt
}

// NewInferenceLog creates an empty inference log.
func NewInferenceLog() *InferenceLog {
	return &InferenceLog{attempts: map[string]InferAttempt{}}
}

// InferControlsDir attempts path inference for the --controls flag.
func (l *InferenceLog) InferControlsDir(cmd *cobra.Command, current string) string {
	return l.inferDir(cmd, "controls", current)
}

// InferObservationsDir attempts path inference for the --observations flag.
func (l *InferenceLog) InferObservationsDir(cmd *cobra.Command, current string) string {
	return l.inferDir(cmd, "observations", current)
}

// inferDir attempts path inference for a flag if the user didn't
// explicitly set it. The flag name doubles as the directory name to search for.
func (l *InferenceLog) inferDir(cmd *cobra.Command, name, current string) string {
	if cmd == nil || cmd.Flags().Changed(name) {
		return current
	}

	record := func(a InferAttempt) {
		a.FlagName = name
		a.DirName = name
		l.attempts[name] = a
	}

	if _, err := ResolveSelectedGlobalContext(); err != nil {
		record(InferAttempt{Error: err.Error()})
		return current
	}

	if ctxDir, ok := ResolveContextDefaultDir("", name); ok {
		record(InferAttempt{Searched: "context default", Resolved: ctxDir})
		return ctxDir
	}

	base, err := pathinfer.BaseDir()
	if err != nil {
		record(InferAttempt{Error: err.Error()})
		return current
	}
	dir, candidates, err := pathinfer.Unique(base, name, InferMaxDepth)
	searched := fmt.Sprintf("%s/%s and nested %s/ within %d levels", base, name, name, InferMaxDepth)
	if err != nil {
		record(InferAttempt{Base: base, Searched: searched, Candidates: candidates, Error: err.Error()})
		return current
	}
	record(InferAttempt{Base: base, Searched: searched, Resolved: dir})
	return dir
}

// ExplainFailure returns a human-readable explanation of a failed inference.
func (l *InferenceLog) ExplainFailure(name string) string {
	if l == nil {
		return ""
	}
	attempt, ok := l.attempts[name]
	if !ok || strings.TrimSpace(attempt.Error) == "" {
		return ""
	}
	candidates := "(none)"
	if len(attempt.Candidates) > 0 {
		candidates = strings.Join(attempt.Candidates, ", ")
	}
	return fmt.Sprintf(
		"Inference details for --%s:\n  missing: could not infer %q directory\n  searched: %s\n  candidates found: %s\n  fix: pass --%s <path> or run `stave context use <name> --%s <path>`",
		name,
		name,
		attempt.Searched,
		candidates,
		name,
		name,
	)
}

// EnsureContextSelectionValid validates the global context selection.
func EnsureContextSelectionValid() error {
	_, err := ResolveSelectedGlobalContext()
	return err
}

// SelectedContext holds the result of resolving the active global context.
type SelectedContext struct {
	Name    string
	Context *contexts.Context
	Active  bool
}

// ResolveSelectedGlobalContext returns the selected context name, context, and active flag.
func ResolveSelectedGlobalContext() (SelectedContext, error) {
	st, _, err := contexts.Load()
	if err != nil {
		return SelectedContext{}, err
	}
	name, ctx, ok, err := st.ResolveSelected()
	if err != nil {
		return SelectedContext{}, err
	}
	return SelectedContext{Name: name, Context: ctx, Active: ok}, nil
}

// RootForContextName returns the project root for the current context.
func RootForContextName() string {
	if sc, err := ResolveSelectedGlobalContext(); err == nil && sc.Active && sc.Context != nil {
		root := strings.TrimSpace(sc.Context.ProjectRoot)
		if root != "" {
			return root
		}
	}
	if root, err := DetectProjectRoot("."); err == nil {
		return root
	}
	wd, _ := os.Getwd()
	return wd
}

// ResolveContextDefaultDir resolves a directory from the active context.
func ResolveContextDefaultDir(_ string, dirName string) (string, bool) {
	sc, err := ResolveSelectedGlobalContext()
	if err != nil || !sc.Active || sc.Context == nil {
		return "", false
	}
	switch dirName {
	case "controls":
		p := strings.TrimSpace(sc.Context.Defaults.ControlsDir)
		if p == "" {
			return "", false
		}
		return sc.Context.AbsPath(p), true
	case "observations":
		p := strings.TrimSpace(sc.Context.Defaults.ObservationsDir)
		if p == "" {
			return "", false
		}
		return sc.Context.AbsPath(p), true
	default:
		return "", false
	}
}

// DetectProjectRoot walks up from start looking for a Stave project root.
func DetectProjectRoot(start string) (string, error) {
	curr, err := filepath.Abs(start)
	if err != nil {
		return "", err
	}
	for {
		if IsProjectRoot(curr) {
			return curr, nil
		}
		parent := filepath.Dir(curr)
		if parent == curr {
			return "", ErrNotInProject
		}
		curr = parent
	}
}

// IsProjectRoot checks if a directory is a Stave project root.
func IsProjectRoot(dir string) bool {
	if _, err := os.Stat(filepath.Join(dir, SessionFileRel)); err == nil {
		return true
	}
	required := []string{"controls", "observations"}
	for _, name := range required {
		fi, err := os.Stat(filepath.Join(dir, name))
		if err != nil || !fi.IsDir() {
			return false
		}
	}
	return true
}

// SaveSessionState persists session state to disk.
func SaveSessionState(projectRoot string, argv []string) error {
	if projectRoot == "" || len(argv) == 0 {
		return nil
	}
	st := SessionState{
		LastCommand: strings.Join(argv, " "),
		WhenUTC:     time.Now().UTC(),
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(projectRoot, SessionFileRel)
	if err := fsutil.SafeMkdirAll(filepath.Dir(path), fsutil.WriteOptions{Perm: 0o700}); err != nil {
		return err
	}
	return fsutil.SafeWriteFile(path, data, fsutil.ConfigWriteOpts())
}

// LoadSessionState reads session state from disk.
func LoadSessionState(projectRoot string) (*SessionState, error) {
	path := filepath.Join(projectRoot, SessionFileRel)
	data, err := fsutil.ReadFileLimited(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var st SessionState
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &st, nil
}
