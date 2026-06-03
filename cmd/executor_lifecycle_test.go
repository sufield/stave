package cmd

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/cli/ui"
)

func TestExecute_CommandError_ExitCode(t *testing.T) {
	var gotCode atomic.Int32
	gotCode.Store(-1)

	a := &App{
		ExitFunc: func(code int) { gotCode.Store(int32(code)) },
	}
	a.Root = &cobra.Command{
		Use:           "test",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			return ui.ErrViolationsFound
		},
	}

	a.execute()

	if code := gotCode.Load(); code != int32(ui.ExitViolations) {
		t.Errorf("exit code = %d, want %d (ExitViolations)", code, ui.ExitViolations)
	}
}

func TestExecute_ContextCancellation_ExitCode(t *testing.T) {
	var gotCode atomic.Int32
	gotCode.Store(-1)

	a := &App{
		ExitFunc: func(code int) { gotCode.Store(int32(code)) },
	}

	ctx, cancel := context.WithCancel(context.Background())
	a.Root = &cobra.Command{
		Use:           "test",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			cancel()
			return nil
		},
	}
	a.Root.SetContext(ctx)

	a.execute()

	if code := gotCode.Load(); code != int32(ui.ExitInterrupted) {
		t.Errorf("exit code = %d, want %d (ExitInterrupted)", code, ui.ExitInterrupted)
	}
}
