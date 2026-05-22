// Package watch tests. This file holds regression tests for the
// channel-close contract owned by Monitor.runLoop — closing the
// Events or Errors channel must exit the loop, not spin on the
// zero value. Each test name encodes the invariant it locks in.
package watch

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
)

// loopDeadline is the budget for runLoop to return after the
// triggering condition (channel close, ctx cancellation). A healthy
// loop returns within microseconds; the historical bug (missing
// `, ok`) caused a tight spin that never returned. 250ms is generous
// for any laptop and tight enough to catch a regression quickly.
const loopDeadline = 250 * time.Millisecond

// newTestMonitor returns a Monitor wired with no sinks, no Assess
// hook, and no logger — just enough to exercise the select loop in
// isolation. runLoop reads m.cfg.Logger via a nil check, so leaving
// Logger nil is intentional.
func newTestMonitor() *Monitor {
	return New(Config{
		ObservationsDir: "/dev/null", // never opened by runLoop directly
		Sinks:           nil,
		Assess:          nil,
		Logger:          nil,
	})
}

// runLoopInGoroutine starts m.runLoop with the supplied channels
// and returns a function that blocks until the loop exits, with a
// deadline. If the deadline trips the test fails with a precise
// message — that's exactly the historical bug's signature
// (loop fails to exit on channel close).
func runLoopInGoroutine(
	t *testing.T,
	m *Monitor,
	ctx context.Context,
	events chan fsnotify.Event,
	errs chan error,
) func() {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		done <- m.runLoop(ctx, events, errs, nil)
	}()
	return func() {
		t.Helper()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("runLoop returned error: %v", err)
			}
		case <-time.After(loopDeadline):
			t.Fatalf("runLoop did not exit within %s — channel-close handling has regressed (tight spin)", loopDeadline)
		}
	}
}

// TestRunLoop_EventsChannelCloseExitsLoop is the load-bearing
// regression guard for the original bug: when fsnotify closes
// watcher.Events (Close() called or fd died), the loop MUST exit
// cleanly rather than spin on the zero-value Event delivered by the
// closed channel. If a future contributor drops the `, ok` form
// from `event, ok := <-events`, this test deadlocks and fails the
// 250ms deadline.
func TestRunLoop_EventsChannelCloseExitsLoop(t *testing.T) {
	t.Parallel()
	m := newTestMonitor()
	events := make(chan fsnotify.Event)
	errs := make(chan error)
	ctx := context.Background()

	wait := runLoopInGoroutine(t, m, ctx, events, errs)
	close(events) // the trigger
	wait()
}

// TestRunLoop_ErrorsChannelCloseExitsLoop — mirror of the Events
// test for the Errors channel. Same contract, same regression
// surface: dropping `, ok` from `err, ok := <-errs` causes a
// tight spin on nil errors.
func TestRunLoop_ErrorsChannelCloseExitsLoop(t *testing.T) {
	t.Parallel()
	m := newTestMonitor()
	events := make(chan fsnotify.Event)
	errs := make(chan error)
	ctx := context.Background()

	wait := runLoopInGoroutine(t, m, ctx, events, errs)
	close(errs) // the trigger
	wait()
}

// TestRunLoop_ContextCancelExitsLoop — sanity that the existing
// ctx.Done() branch still works alongside the new channel-close
// branches. Without this, a future refactor that breaks the ctx
// path could be hidden behind a green channel-close test.
func TestRunLoop_ContextCancelExitsLoop(t *testing.T) {
	t.Parallel()
	m := newTestMonitor()
	events := make(chan fsnotify.Event)
	errs := make(chan error)
	ctx, cancel := context.WithCancel(context.Background())

	wait := runLoopInGoroutine(t, m, ctx, events, errs)
	cancel() // the trigger
	wait()
}

// TestRunLoop_NonCloseErrorDoesNotExitLoop — a real (non-nil)
// fsnotify error on the Errors channel must NOT exit the loop;
// errors are logged and the loop continues. Without this guard,
// a tightening of the channel-close handling could overshoot and
// treat every error as terminal.
func TestRunLoop_NonCloseErrorDoesNotExitLoop(t *testing.T) {
	t.Parallel()
	m := newTestMonitor()
	events := make(chan fsnotify.Event, 1)
	errs := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- m.runLoop(ctx, events, errs, nil)
	}()

	// Send a non-close error and verify the loop is still alive
	// after a short tick (i.e. it didn't return).
	errs <- errors.New("transient filesystem hiccup")
	select {
	case err := <-done:
		t.Fatalf("runLoop exited on a non-close error, returning %v — error handling overshot the contract", err)
	case <-time.After(50 * time.Millisecond):
		// Healthy: still running.
	}

	// Now actually trigger an exit so the test cleans up.
	cancel()
	select {
	case <-done:
		// expected
	case <-time.After(loopDeadline):
		t.Fatalf("runLoop did not exit on ctx cancel after a non-close error")
	}
}

// TestRunLoop_NilChannelsBlockForever — a Monitor whose channels
// are nil never fires any case (a nil channel is never ready in
// select), so the loop blocks indefinitely on the other cases.
// This is the negative control: it verifies the deadline mechanism
// in our other tests actually catches a stuck loop. Without this,
// a regression that hangs the loop forever would look identical
// to the "all channels closed" tests above.
func TestRunLoop_NilChannelsBlockForever(t *testing.T) {
	t.Parallel()
	m := newTestMonitor()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- m.runLoop(ctx, nil, nil, nil)
	}()

	// With every channel nil and ctx still live, the loop blocks
	// in select. It must NOT have returned yet.
	select {
	case err := <-done:
		t.Fatalf("runLoop returned %v before ctx cancel — empty/nil channels should leave it blocking", err)
	case <-time.After(50 * time.Millisecond):
		// expected
	}
	cancel()
	select {
	case <-done:
		// expected
	case <-time.After(loopDeadline):
		t.Fatalf("runLoop did not exit on ctx cancel within %s", loopDeadline)
	}
}

// Compile-time guard: runLoop is the function under regression
// test. If it's renamed without updating the tests, the build
// catches it.
var _ = (*Monitor).runLoop
