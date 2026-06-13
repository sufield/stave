//go:build unix

// This test drives the signal handler with syscall.Kill, which is unix-only;
// the production signal path (cmd/executor.go) remains cross-platform.
package cmd

import (
	"os"
	"os/signal"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/sufield/stave/internal/cli/ui"
)

// TestRecoverExecutePanic_NoGoroutineLeak verifies that
// recoverExecutePanic invokes the stored cleanupInterrupt closure
// before ExitFunc, so the signal-handler goroutine the executor
// installed is unblocked even when ExitFunc is mocked (i.e. does
// not call os.Exit and therefore does not implicitly terminate
// the goroutine when the process dies).
//
// Prior to the fix, recoverExecutePanic called ExitFunc directly;
// in production the goroutine died with the process, but in tests
// the mocked ExitFunc returned and the handler goroutine stayed
// blocked on its select for the rest of the test run. That broke
// the panic-recovery test isolation against subsequent tests in
// the same package.
func TestRecoverExecutePanic_NoGoroutineLeak(t *testing.T) {
	a := &App{
		ExitFunc: func(int) {},
	}

	// Install the real signal handler closure so we can prove
	// recoverExecutePanic actually invokes it. installInterruptHandler
	// returns a closer that closes the `done` channel, ending the
	// goroutine.
	cleanup := a.installInterruptHandler()
	a.cleanupInterrupt.Store(&cleanup)

	// Track baseline goroutine count *after* the handler is
	// installed so we count a delta against the installed-but-
	// not-yet-cleaned-up state.
	baseline := runtime.NumGoroutine()

	// Drive the panic-recovery path. The deferred recover() inside
	// recoverExecutePanic catches the panic, runs cleanup, and
	// returns (since ExitFunc is mocked).
	func() {
		defer a.recoverExecutePanic()
		panic("synthetic panic for goroutine-leak test")
	}()

	if a.cleanupInterrupt.Load() != nil {
		t.Fatal("cleanupInterrupt was not nil-ed by recoverExecutePanic; production fix regressed")
	}

	// Give the signal-handler goroutine a beat to observe its
	// `done` channel close and exit.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= baseline {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Errorf("goroutine count did not return to baseline (%d) within 2s; current=%d — handler goroutine leaked",
		baseline, runtime.NumGoroutine())
}

// TestRecoverExecutePanic_NoCleanupInterruptIsSafe documents the
// pre-bootstrap path: a panic before installInterruptHandler runs
// reaches recoverExecutePanic with cleanupInterrupt==nil. The
// recovery must not nil-deref in that case.
func TestRecoverExecutePanic_NoCleanupInterruptIsSafe(t *testing.T) {
	var exitCalls atomic.Int32
	a := &App{
		ExitFunc: func(int) { exitCalls.Add(1) },
	}
	// cleanupInterrupt is intentionally left nil to model
	// pre-bootstrap panics.

	func() {
		defer a.recoverExecutePanic()
		panic("synthetic pre-bootstrap panic")
	}()

	if exitCalls.Load() != 1 {
		t.Errorf("ExitFunc called %d times, want 1", exitCalls.Load())
	}
}

func TestRecoverExecutePanic_SignalRace(t *testing.T) {
	var exitCodes []int
	var mu sync.Mutex

	a := &App{}
	a.ExitFunc = func(code int) {
		mu.Lock()
		exitCodes = append(exitCodes, code)
		mu.Unlock()
	}

	cleanup := a.installInterruptHandler()
	a.cleanupInterrupt.Store(&cleanup)

	// Register a local channel to intercept SIGINT so it doesn't terminate the test process
	testSigCh := make(chan os.Signal, 1)
	signal.Notify(testSigCh, os.Interrupt)
	defer signal.Stop(testSigCh)

	// Lock bootstrapMu to block cleanupBeforeExit's log closing phase
	a.bootstrapMu.Lock()

	// Run the panic in a separate goroutine because it will block
	go func() {
		defer a.recoverExecutePanic()
		panic("synthetic panic for signal race test")
	}()

	// Wait a short moment to ensure the panic goroutine has entered cleanupBeforeExit
	// and is blocked on bootstrapMu.Lock()
	time.Sleep(100 * time.Millisecond)

	// Send SIGINT. Since cleanupBeforeExit has run its first lines,
	// a.cancel has been swapped to nil. The signal handler will see it as nil
	// and trigger the pre-bootstrap path, calling ExitFunc(130).
	err := syscall.Kill(syscall.Getpid(), syscall.SIGINT)
	if err != nil {
		t.Fatalf("failed to send SIGINT: %v", err)
	}

	// Wait to make sure the signal handler has run (or would have run)
	time.Sleep(100 * time.Millisecond)

	// Now unlock bootstrapMu to let the panic recovery finish
	a.bootstrapMu.Unlock()

	// Wait for the panic recovery to call ExitFunc
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		hasExited := len(exitCodes) > 0
		mu.Unlock()
		if hasExited {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	mu.Lock()
	codes := append([]int(nil), exitCodes...)
	mu.Unlock()

	if len(codes) == 0 {
		t.Fatal("recoverExecutePanic did not call ExitFunc")
	}

	// Under the bug, the signal handler calls ExitFunc(130) before the panic recovery completes.
	// We want the exit code to be 4 (ExitInternal) and NOT 130 (ExitInterrupted).
	for _, code := range codes {
		if code == ui.ExitInterrupted {
			t.Errorf("process exited with code 130 (interrupted) during panic recovery; want 4 (internal error)")
		}
	}
}
