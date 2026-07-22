package status

import (
	"fmt"
	"io"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/projctx"
	appstatus "github.com/sufield/stave/pkg/stave/status"
	"github.com/sufield/stave/internal/cli/ui"
)

// config defines the parameters for the status check.
type config struct {
	Dir    string
	Format cmdutil.OutputFormat
	Stdout io.Writer
	Stderr io.Writer
}

// Runner orchestrates the collection of project state and its presentation.
type Runner struct {
	Resolver *projctx.Resolver
}

// NewRunner initializes a status runner with the provided context resolver.
func NewRunner(r *projctx.Resolver) *Runner {
	return &Runner{Resolver: r}
}

// Run detects the project root, delegates inspection to the app layer,
// loads session info, and formats the output.
func (r *Runner) Run(cfg config) error {
	root, err := r.Resolver.DetectProjectRoot(cfg.Dir)
	if err != nil {
		return ui.WithNextCommand(
			fmt.Errorf("project root not found in %s: %w", cfg.Dir, err),
			"stave config context create",
		)
	}

	inspector := appstatus.NewInspector()
	state, err := inspector.Inspect(root)
	if err != nil {
		return fmt.Errorf("inspect project state at %s: %w", root, err)
	}

	// Load CLI session info and attach to domain state.
	if sess, sessErr := projctx.LoadSession(root); sessErr == nil && sess != nil {
		state.LastCommand = sess.LastCommand
		state.LastCommandTime = sess.WhenUTC
	}

	result := appstatus.Result{
		State:       state,
		NextCommand: state.RecommendNext(),
	}

	return r.report(cfg, result)
}

func (r *Runner) report(cfg config, res appstatus.Result) error {
	renderer, err := NewRenderer(cfg.Format)
	if err != nil {
		return err
	}
	if err := renderer.Render(cfg.Stdout, res); err != nil {
		return fmt.Errorf("render output: %w", err)
	}
	return nil
}
