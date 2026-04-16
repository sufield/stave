package collect

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestDaemon_RunsMultipleCycles(t *testing.T) {
	var count atomic.Int32
	opts := DaemonOpts{
		Period: 50 * time.Millisecond,
		RunOnce: func(_ context.Context) error {
			count.Add(1)
			return nil
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Millisecond)
	defer cancel()

	_ = RunDaemon(ctx, opts)

	c := count.Load()
	if c < 2 {
		t.Errorf("run count = %d, want >= 2", c)
	}
}

func TestDaemon_CollectionErrorContinues(t *testing.T) {
	var count atomic.Int32
	opts := DaemonOpts{
		Period: 50 * time.Millisecond,
		RunOnce: func(_ context.Context) error {
			n := count.Add(1)
			if n == 1 {
				return os.ErrInvalid // first call fails
			}
			return nil // second call succeeds
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Millisecond)
	defer cancel()

	_ = RunDaemon(ctx, opts)

	c := count.Load()
	if c < 2 {
		t.Errorf("run count = %d, want >= 2 (error should not stop daemon)", c)
	}
}

func TestDaemon_PIDFileLifecycle(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "test.pid")

	opts := DaemonOpts{
		Period:  50 * time.Millisecond,
		PIDFile: pidFile,
		RunOnce: func(_ context.Context) error { return nil },
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// PID file should not exist before.
	if _, err := os.Stat(pidFile); err == nil {
		t.Fatal("PID file should not exist before daemon start")
	}

	_ = RunDaemon(ctx, opts)

	// PID file should be removed after daemon exits.
	if _, err := os.Stat(pidFile); err == nil {
		t.Error("PID file should be removed after daemon exit")
	}
}

func TestDaemon_SIGTERMCleanExit(t *testing.T) {
	var count atomic.Int32
	opts := DaemonOpts{
		Period: 50 * time.Millisecond,
		RunOnce: func(_ context.Context) error {
			count.Add(1)
			return nil
		},
	}

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		time.Sleep(120 * time.Millisecond)
		cancel() // simulate SIGTERM via context cancellation
	}()

	err := RunDaemon(ctx, opts)
	if err != nil {
		t.Errorf("daemon should exit cleanly: %v", err)
	}
	if count.Load() < 1 {
		t.Error("daemon should have run at least once")
	}
}
