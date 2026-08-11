package prove

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/pkg/stave"
)

func runUniversal(cmd *cobra.Command, o *options) error {
	renderer, err := NewUniversalRenderer(o.format)
	if err != nil {
		return err
	}

	result, err := stave.ProveUniversal(cmd.Context(), stave.ProveUniversalConfig{
		SnapshotsDir:  o.observations,
		FormulaDir:    o.formulaDir,
		GroundingPath: o.groundingPath,
	})
	if err != nil {
		return &ui.UserError{Err: err}
	}

	if err := renderer.RenderUniversal(cmd.OutOrStdout(), result); err != nil {
		return fmt.Errorf("render output: %w", err)
	}

	if result.Violated > 0 {
		return ui.ErrViolationsFound
	}
	return nil
}
