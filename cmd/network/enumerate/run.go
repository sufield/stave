package enumerate

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

	result, err := stave.NetworkEnumerate(cmd.Context(), stave.NetworkEnumerateConfig{
		SnapshotsDir: o.observations,
		Port:         o.port,
	})
	if err != nil {
		return fmt.Errorf("network enumerate: %w", err)
	}

	if err := renderer.Render(cmd.OutOrStdout(), result); err != nil {
		return fmt.Errorf("render output: %w", err)
	}
	return nil
}
