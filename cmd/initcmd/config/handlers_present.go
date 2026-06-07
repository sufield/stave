package config

import (
	"fmt"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
)

func (r *Runner) presentValue(res ValueResult, format appcontracts.OutputFormat) error {
	renderer, err := NewValueRenderer(format)
	if err != nil {
		return err
	}
	if err := renderer.Render(r.Stdout, res); err != nil {
		return fmt.Errorf("render output: %w", err)
	}
	return nil
}

func (r *Runner) presentMutation(opts MutationOpts, res ValueResult, text string, showHint bool) error {
	renderer, err := NewMutationRenderer(opts.Format, r.Stderr, text, opts, showHint)
	if err != nil {
		return err
	}
	if err := renderer.Render(r.Stdout, res); err != nil {
		return fmt.Errorf("render output: %w", err)
	}
	return nil
}
