package config

import (
	"fmt"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/util/jsonutil"
)

func (r *Runner) presentValue(res ValueResult, format appcontracts.OutputFormat) error {
	if format.IsJSON() {
		if err := jsonutil.WriteIndented(r.Stdout, res); err != nil {
			return fmt.Errorf("write output: %w", err)
		}
		return nil
	}
	_, err := fmt.Fprintf(r.Stdout, "%s\n", res.Value)
	return err
}

func (r *Runner) presentMutation(opts MutationOpts, res ValueResult, text string, showHint bool) error {
	if opts.Format.IsJSON() {
		if err := jsonutil.WriteIndented(r.Stdout, res); err != nil {
			return fmt.Errorf("write output: %w", err)
		}
		return nil
	}

	if _, err := fmt.Fprintln(r.Stdout, text); err != nil {
		return err
	}
	if showHint && !opts.Quiet {
		ui.WriteHint(r.Stderr, "stave config show")
	}
	return nil
}
