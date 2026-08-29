package iam

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/pkg/stave"
)

func runLoop(cmd *cobra.Command, o *loopOptions) error {
	renderer, err := NewRenderer(o.Format)
	if err != nil {
		return err
	}

	result, err := stave.IAMLoop(cmd.Context(), stave.IAMLoopConfig{
		PolicyPath: o.PolicyPath,
	})
	if err != nil {
		return err //nolint:wrapcheck // facade already wrapped ("iam loop: ..."); preserve exit code
	}

	fmt.Fprintf(cmd.ErrOrStderr(), "Cycle: %s\n", result.WallClock.Truncate(100*1e6))

	if err := renderer.Render(cmd.OutOrStdout(), result); err != nil {
		return fmt.Errorf("render iam loop: %w", err)
	}
	return nil
}
