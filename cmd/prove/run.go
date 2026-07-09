package prove

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/pkg/stave"
)

func run(cmd *cobra.Command, o *options) error {
	renderer, err := NewRenderer(o.format)
	if err != nil {
		return err
	}

	result, err := stave.Prove(cmd.Context(), stave.ProveConfig{
		SnapshotsDir: o.observations,
		ControlsDir:  o.controls,
		Query:        o.query,
		Principal:    o.principal,
		Action:       o.action,
		Resource:     o.resource,
		InvariantID:  o.invariantID,
	})
	if err != nil {
		return err //nolint:wrapcheck // facade already wrapped ("prove: ..."); preserve exit 4.
	}

	if err := renderer.Render(cmd.OutOrStdout(), result); err != nil {
		return fmt.Errorf("render output: %w", err)
	}
	return nil
}
