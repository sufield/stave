package ui

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

// NewPager returns the writer a command should render into, plus a close
// function that MUST be called when rendering is done.
//
// When w is a terminal and paging is enabled, output is piped through a pager
// ($PAGER, then `less -R`, then `more`) and close waits for the pager to exit.
// When w is NOT a terminal (a pipe, a redirect, CI) or paging is disabled, w is
// returned unchanged with a no-op close — so `... | grep` and `... > file`
// behave exactly as without paging, and JSON callers can opt out entirely.
//
// Reuses the existing IsTerminal check (no golang.org/x/term). A user quitting
// the pager early closes its stdin, so writes race against an EPIPE; the
// returned writer swallows that, matching this package's long-standing "a
// broken pipe to a paged less should not bubble up" stance (see WriteHint).
//
// ctx ties the pager to the command's lifecycle: cancelling it (e.g. SIGINT)
// kills the pager. The pager is always waited on (in the returned closer)
// before the command returns, so ctx is live for the pager's whole life.
func NewPager(ctx context.Context, w io.Writer, enabled bool) (io.Writer, func() error) {
	noop := func() error { return nil }
	if !enabled || !IsTerminal(w) {
		return w, noop
	}
	name, args := resolvePager()
	if name == "" {
		return w, noop // no pager on PATH — degrade to plain, do not error
	}

	// G204: launching the user's configured $PAGER (or the standard less/more
	// fallback) with its args is the intended behavior of a pager — the same
	// pattern git/kubectl use. resolvePager only returns a binary found on PATH.
	cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec // intentional: run the user's $PAGER
	cmd.Stdout = w                                 // the terminal file we were handed
	cmd.Stderr = os.Stderr
	pipe, err := cmd.StdinPipe()
	if err != nil {
		return w, noop
	}
	if err := cmd.Start(); err != nil {
		return w, noop
	}
	return epipeSwallowWriter{w: pipe}, func() error {
		// Closing our write end signals EOF so the pager can finish drawing.
		_ = pipe.Close()
		// A pager exiting non-zero (e.g. the user pressed q) is not our error;
		// the output already reached the terminal. Surface only genuinely
		// unexpected failures, never a broken-pipe/exit from early quit.
		if err := cmd.Wait(); err != nil {
			if errors.Is(err, syscall.EPIPE) {
				return nil
			}
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				return nil
			}
			return fmt.Errorf("wait for pager: %w", err)
		}
		return nil
	}
}

// resolvePager picks the pager binary and its args, in order: $PAGER (split on
// spaces, first token must resolve on PATH), then `less -R`, then `more`.
// Returns ("", nil) when none is available — the caller then renders unpaged.
func resolvePager() (string, []string) {
	if p := strings.TrimSpace(os.Getenv("PAGER")); p != "" {
		fields := strings.Fields(p)
		if path, err := exec.LookPath(fields[0]); err == nil {
			return path, fields[1:]
		}
	}
	if path, err := exec.LookPath("less"); err == nil {
		return path, []string{"-R"}
	}
	if path, err := exec.LookPath("more"); err == nil {
		return path, nil
	}
	return "", nil
}

// epipeSwallowWriter forwards writes to w but treats EPIPE as success. When a
// user quits the pager, its stdin closes and further writes return EPIPE; that
// is expected, not a rendering failure, so it must not propagate up through a
// renderer's error return.
type epipeSwallowWriter struct{ w io.Writer }

func (e epipeSwallowWriter) Write(p []byte) (int, error) {
	n, err := e.w.Write(p)
	if err != nil && errors.Is(err, syscall.EPIPE) {
		return len(p), nil
	}
	return n, err
}
