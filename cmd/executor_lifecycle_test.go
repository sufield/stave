package cmd

import (
	"context"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

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

func TestExecute_SignalAndErrorRaceExit(t *testing.T) {
	var exitCodes []int
	var mu sync.Mutex
	var gotCode atomic.Int32
	gotCode.Store(-1)

	a := &App{}
	a.ExitFunc = func(code int) {
		mu.Lock()
		exitCodes = append(exitCodes, code)
		mu.Unlock()
		gotCode.Store(int32(code))
	}

	// Set up command that blocks until context is cancelled, then returns context.Canceled
	a.Root = &cobra.Command{
		Use:           "test",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			<-cmd.Context().Done()
			return cmd.Context().Err()
		},
	}
	a.Root.PersistentPreRunE = a.bootstrap

	// Run execute in a separate goroutine because it might block, and we will send SIGINT
	go func() {
		a.execute()
	}()

	// Wait a bit for the command to start and context to be set up
	time.Sleep(100 * time.Millisecond)

	// Send SIGINT to our own process
	err := syscall.Kill(syscall.Getpid(), syscall.SIGINT)
	if err != nil {
		t.Fatalf("failed to send SIGINT: %v", err)
	}

	// Wait for execution to finish (exit code is set)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if gotCode.Load() != -1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	code := gotCode.Load()
	if code == -1 {
		t.Fatal("execute did not exit within 2 seconds")
	}

	mu.Lock()
	calls := len(exitCodes)
	mu.Unlock()

	if calls > 1 {
		t.Errorf("ExitFunc called %d times (codes: %v), expected exactly 1 call", calls, exitCodes)
	}
}
