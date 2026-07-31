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

	result, err := stave.NetworkProve(cmd.Context(), stave.NetworkProveConfig{
		SnapshotsDir: o.observations,
		Property:     o.property,
		Port:         o.port,
	})
	if err != nil {
		return fmt.Errorf("network prove: %w", err)
	}

	if err := renderer.Render(cmd.OutOrStdout(), result); err != nil {
		return fmt.Errorf("render output: %w", err)
	}
	return nil
}
