package enumerate

import (
	"context"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/pkg/stave"
)

func run(cmd *cobra.Command, o *options) error {
	renderer, err := NewRenderer(o.format)
	if err != nil {
		return err
	}
	return executeAndRender(cmd.Context(), cmd.OutOrStdout(), o.ToConfig(), renderer)
}

func executeAndRender(ctx context.Context, w io.Writer, cfg stave.NetworkEnumerateConfig, r Renderer) error {
	result, err := stave.NetworkEnumerate(ctx, cfg)
	if err != nil {
		return fmt.Errorf("network enumerate: %w", err)
	}

	if err := r.Render(w, result); err != nil {
		return fmt.Errorf("render output: %w", err)
	}
	return nil
}
