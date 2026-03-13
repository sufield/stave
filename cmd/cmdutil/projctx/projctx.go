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

	contexts "github.com/sufield/stave/internal/config"
	"github.com/sufield/stave/internal/pathinfer"
	"github.com/sufield/stave/internal/platform/fsutil"
)

const (
	SessionFileRel = ".stave/session.json"
	InferMaxDepth  = 3
)

// ErrNotInProject is returned when the current directory is not inside a Stave project.
var ErrNotInProject = errors.New("not inside a Stave project; run `stave init` first")

// --- Context Resolver ---

// Resolver handles the discovery of the active project and global context settings.
type Resolver struct {
	WorkingDir string
}

// NewResolver creates a Resolver anchored at the current working directory.
func NewResolver() (*Resolver, error) {
	wd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("resolve working directory: %w", err)
	}
	return &Resolver{WorkingDir: wd}, nil
}

// SelectedContext holds the result of resolving the active global context.
type SelectedContext struct {
	Name    string
	Context *contexts.Context
	Active  bool
}

// ResolveSelected returns the currently selected global context.
func (r *Resolver) ResolveSelected() (SelectedContext, error) {
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

// ProjectRoot determines the root of the current project.
// Priority: Active Context -> Discovery from WorkingDir -> WorkingDir fallback.
func (r *Resolver) ProjectRoot() string {
	if sc, err := r.ResolveSelected(); err == nil && sc.Active && sc.Context != nil {
		if root := strings.TrimSpace(sc.Context.ProjectRoot); root != "" {
			return root
		}
	}
	if root, err := r.DetectProjectRoot(r.WorkingDir); err == nil {
		return root
	}
	return r.WorkingDir
}

// DetectProjectRoot walks up from start looking for a Stave project root indicator.
func (r *Resolver) DetectProjectRoot(start string) (string, error) {
	curr, err := filepath.Abs(start)
	if err != nil {
		return "", err
	}
	for {
		if r.IsProjectRoot(curr) {
			return curr, nil
		}
		parent := filepath.Dir(curr)
		if parent == curr {
			return "", ErrNotInProject
		}
		curr = parent
	}
}

// IsProjectRoot checks if a directory contains Stave project indicators.
func (r *Resolver) IsProjectRoot(dir string) bool {
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

// --- Path Inference Engine ---

// InferenceEngine manages the "best effort" discovery of project directories.
type InferenceEngine struct {
	resolver *Resolver
	Log      *InferenceLog
}

// NewInferenceEngine creates an engine backed by the given Resolver.
func NewInferenceEngine(r *Resolver) *InferenceEngine {
	return &InferenceEngine{
		resolver: r,
		Log:      &InferenceLog{attempts: make(map[string]InferAttempt)},
	}
}

// InferDir attempts to find a directory (like "controls" or "observations")
// using context defaults first, then filesystem searching.
// If currentInput is non-empty, it is returned as-is (no inference needed).
func (e *InferenceEngine) InferDir(name, currentInput string) string {
	if currentInput != "" {
		return currentInput
	}

	record := func(a InferAttempt) {
		a.FlagName = name
		e.Log.attempts[name] = a
	}

	// 1. Try Context Defaults
	if e.resolver != nil {
		sc, err := e.resolver.ResolveSelected()
		if err == nil && sc.Active && sc.Context != nil {
			var ctxPath string
			switch name {
			case "controls":
				ctxPath = sc.Context.Defaults.ControlsDir
			case "observations":
				ctxPath = sc.Context.Defaults.ObservationsDir
			}

			if p := strings.TrimSpace(ctxPath); p != "" {
				resolved := sc.Context.AbsPath(p)
				record(InferAttempt{Searched: "context default", Resolved: resolved})
				return resolved
			}
		}
	}

	// 2. Try Filesystem Inference
	base, err := pathinfer.BaseDir()
	if err != nil {
		record(InferAttempt{Error: err.Error()})
		return ""
	}

	dir, candidates, err := pathinfer.Unique(base, name, InferMaxDepth)
	searchDesc := fmt.Sprintf("%s/%s (nested to %d levels)", base, name, InferMaxDepth)

	if err != nil {
		record(InferAttempt{Base: base, Searched: searchDesc, Candidates: candidates, Error: err.Error()})
		return ""
	}

	record(InferAttempt{Base: base, Searched: searchDesc, Resolved: dir})
	return dir
}

// --- Session Management ---

// SessionState holds the last command and time for session persistence.
type SessionState struct {
	LastCommand string    `json:"last_command"`
	WhenUTC     time.Time `json:"when_utc"`
}

// SaveSession persists session state to disk.
func SaveSession(projectRoot string, argv []string) error {
	if projectRoot == "" || len(argv) == 0 {
		return nil
	}
	state := SessionState{
		LastCommand: strings.Join(argv, " "),
		WhenUTC:     time.Now().UTC(),
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(projectRoot, SessionFileRel)
	if err := fsutil.SafeMkdirAll(filepath.Dir(path), fsutil.WriteOptions{Perm: 0o700}); err != nil {
		return err
	}
	return fsutil.SafeWriteFile(path, data, fsutil.ConfigWriteOpts())
}

// LoadSession reads session state from disk.
func LoadSession(projectRoot string) (*SessionState, error) {
	path := filepath.Join(projectRoot, SessionFileRel)
	data, err := fsutil.ReadFileLimited(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var state SessionState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("parse session %s: %w", path, err)
	}
	return &state, nil
}

// --- Diagnostics ---

// InferenceLog records path inference attempts for diagnostics.
type InferenceLog struct {
	attempts map[string]InferAttempt
}

// InferAttempt records a path inference attempt for diagnostics.
type InferAttempt struct {
	FlagName   string
	Base       string
	Searched   string
	Candidates []string
	Error      string
	Resolved   string
}

// Explain returns a human-readable explanation of a failed inference.
func (l *InferenceLog) Explain(name string) string {
	if l == nil {
		return ""
	}
	attempt, ok := l.attempts[name]
	if !ok || attempt.Error == "" {
		return ""
	}
	candidates := "(none)"
	if len(attempt.Candidates) > 0 {
		candidates = strings.Join(attempt.Candidates, ", ")
	}
	return fmt.Sprintf(
		"Inference failed for --%s:\n  searched: %s\n  candidates: %s\n  hint: pass --%s <path> or use `stave context` to set a default",
		name, attempt.Searched, candidates, name,
	)
}
