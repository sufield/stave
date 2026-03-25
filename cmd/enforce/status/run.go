package status

import (
	"fmt"
	"io"

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

// Runner orchestrates the collection of project state and its presentation.
type Runner struct {
	Resolver *projctx.Resolver
}

// NewRunner initializes a status runner with the provided context resolver.
func NewRunner(r *projctx.Resolver) *Runner {
	return &Runner{Resolver: r}
}

// Run detects the project root, delegates scanning to the app layer,
// loads session info, and formats the output.
func (r *Runner) Run(cfg config) error {
	dir := fsutil.CleanUserPath(cfg.Dir)

	root, err := r.Resolver.DetectProjectRoot(dir)
	if err != nil {
		return ui.WithNextCommand(err, "stave init")
	}

	scanner := appstatus.NewScanner()
	state, err := scanner.Scan(root)
	if err != nil {
		return fmt.Errorf("scanning project: %w", err)
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

	if cfg.Format.IsJSON() {
		return jsonutil.WriteIndented(cfg.Stdout, result)
	}
	return appstatus.FormatText(cfg.Stdout, result)
}
