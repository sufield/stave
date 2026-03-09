package ui

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// Runtime holds process-level CLI output and mode settings.
type Runtime struct {
	Stdout  io.Writer
	Stderr  io.Writer
	Verbose int
	Debug   bool
	Strict  bool
	NoColor bool
	Quiet   bool
	// IsTTY overrides terminal detection in tests when set.
	IsTTY *bool
}

// NewRuntime creates a Runtime with default streams when nil streams are provided.
func NewRuntime(stdout, stderr io.Writer) *Runtime {
	if stdout == nil {
		stdout = os.Stdout
	}
	if stderr == nil {
		stderr = os.Stderr
	}
	return &Runtime{
		Stdout: stdout,
		Stderr: stderr,
	}
}

// IsTerminal reports whether w points to a terminal device.
func IsTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeCharDevice) != 0
}

func (r *Runtime) stderr() io.Writer {
	if r == nil || r.Stderr == nil {
		return os.Stderr
	}
	return r.Stderr
}

func (r *Runtime) isTerminal(w io.Writer) bool {
	if r != nil && r.IsTTY != nil {
		return *r.IsTTY
	}
	return IsTerminal(w)
}

// BeginProgress prints a start and done message on stderr for long-running steps.
func (r *Runtime) BeginProgress(label string) func() {
	if r == nil || r.Quiet {
		return func() {}
	}

	errOut := r.stderr()
	start := time.Now()
	if !r.isTerminal(errOut) {
		_, _ = fmt.Fprintf(errOut, "Running: %s...\n", label)
		var once sync.Once
		return func() {
			once.Do(func() {
				elapsed := time.Since(start).Round(time.Millisecond)
				_, _ = fmt.Fprintf(errOut, "Done:    %s (%s)\n", label, elapsed)
			})
		}
	}

	frames := []string{"|", "/", "-", "\\"}
	stopCh := make(chan struct{})
	finishedCh := make(chan struct{})
	go func() {
		defer close(finishedCh)
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		i := 0
		for {
			select {
			case <-stopCh:
				return
			case <-ticker.C:
				_, _ = fmt.Fprintf(errOut, "\r\033[K%s Running: %s...", frames[i%len(frames)], label)
				i++
			}
		}
	}()

	var once sync.Once
	return func() {
		once.Do(func() {
			close(stopCh)
			<-finishedCh
			elapsed := time.Since(start).Round(time.Millisecond)
			_, _ = fmt.Fprintf(errOut, "\r\033[KDone:    %s (%s)\n", label, elapsed)
		})
	}
}

// WriteHint writes a single "Hint:\n  <command>" line to w.
// Use for single-command follow-up guidance after an operation.
func WriteHint(w io.Writer, command string) {
	if command != "" {
		fmt.Fprintf(w, "Hint:\n  %s\n", command)
	}
}

// PrintNextSteps writes a formatted "Next steps:" block to stderr.
// Hints are always written to stderr so they never contaminate JSON stdout.
func (r *Runtime) PrintNextSteps(steps ...string) {
	if r == nil || r.Quiet || len(steps) == 0 {
		return
	}

	out := r.stderr()
	_, _ = fmt.Fprintln(out)
	_, _ = fmt.Fprintln(out, "Next steps:")
	for i, step := range steps {
		_, _ = fmt.Fprintf(out, "  %d. %s\n", i+1, step)
	}
}

// ShouldShowWorkflowHandoff returns true when the command should print workflow guidance.
func ShouldShowWorkflowHandoff(args []string) bool {
	ignore := map[string]struct{}{
		"-h":         {},
		"--help":     {},
		"help":       {},
		"--version":  {},
		"version":    {},
		"completion": {},
		"status":     {},
	}
	for _, a := range args {
		if _, blocked := ignore[a]; blocked {
			return false
		}
	}
	return true
}

type WorkflowHandoffRequest struct {
	Args        []string
	ProjectRoot string
	NextCommand func(projectRoot string) (string, error)
}

// PrintWorkflowHandoff prints the next workflow command guidance to stderr.
func (r *Runtime) PrintWorkflowHandoff(req WorkflowHandoffRequest) {
	if r == nil || r.Quiet || !ShouldShowWorkflowHandoff(req.Args) || strings.TrimSpace(req.ProjectRoot) == "" {
		return
	}

	next := "stave status"
	if req.NextCommand != nil {
		suggested, err := req.NextCommand(req.ProjectRoot)
		if err == nil && strings.TrimSpace(suggested) != "" {
			next = suggested
		}
	}

	_, _ = fmt.Fprintf(r.stderr(), "Next workflow start: %s\n", next)
}

func IsStderrTTY() bool {
	return IsTerminal(os.Stderr)
}
