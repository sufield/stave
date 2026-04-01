package config

import (
	"fmt"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/pkg/jsonutil"
)

func (r *Runner) presentValue(res ValueResult, format appcontracts.OutputFormat) error {
	if format.IsJSON() {
		return jsonutil.WriteIndented(r.Stdout, res)
	}
	_, err := fmt.Fprintf(r.Stdout, "%s\n", res.Value)
	return err
}

func (r *Runner) presentMutation(opts MutationOpts, res ValueResult, text string, showHint bool) error {
	if opts.Format.IsJSON() {
		return jsonutil.WriteIndented(r.Stdout, res)
	}

	if _, err := fmt.Fprintln(r.Stdout, text); err != nil {
		return err
	}
	if showHint && !opts.Quiet {
		ui.WriteHint(r.Stderr, "stave config show")
	}
	return nil
}
