package collect

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// DaemonOpts holds configuration for daemon mode.
type DaemonOpts struct {
	Period     time.Duration
	PIDFile    string
	AuditLabel string
	// RunOnce is called for each collection cycle.
	// Injected by the caller to reuse the existing collection logic.
	RunOnce func(ctx context.Context) error
}

// RunDaemon runs the collection loop until SIGTERM or context cancellation.
func RunDaemon(ctx context.Context, opts DaemonOpts) error {
	if opts.RunOnce == nil {
		return errors.New("runOnce function is required")
	}

	// Open + flock the PID file so a second daemon instance with
	// the same --pid-file fails fast at startup instead of racing
	// with the first. cleanup releases the lock + unlinks the
	// file on shutdown.
	cleanup, pidErr := acquirePIDFile(opts.PIDFile)
	if pidErr != nil {
		return pidErr
	}
	defer cleanup()

	// Handle SIGTERM/SIGINT.
	ctx, cancel := signal.NotifyContext(ctx, syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	slog.Info("collect daemon started",
		"period", opts.Period,
		"pid_file", opts.PIDFile,
		"audit_label", opts.AuditLabel)

	for {
		if err := opts.RunOnce(ctx); err != nil {
			// CRITICAL: log and continue — do NOT return.
			slog.Error("collection failed, continuing",
				"error", err,
				"period", opts.Period)
		} else {
			slog.Info("collection complete",
				"period", opts.Period)
		}

		// time.After(d) leaks the underlying timer until d expires —
		// each loop iteration on shutdown leaves a goroutine parked
		// on the inner runtime timer. NewTimer + explicit Stop on
		// ctx.Done collects the timer immediately so a long-running
		// daemon with a long Period doesn't accumulate dangling
		// timer goroutines on each cancel.
		timer := time.NewTimer(opts.Period)
		select {
		case <-ctx.Done():
			timer.Stop()
			slog.Info("collect daemon stopping")
			return nil
		case <-timer.C:
			// continue to next collection
		}
	}
}

// acquirePIDFile secures an exclusive lock on the PID file and
// writes the current PID. Returns a cleanup closure to defer on
// shutdown. An empty pidFile is a no-op that returns a do-nothing
// cleanup so the caller doesn't have to branch.
func acquirePIDFile(pidFile string) (func(), error) {
	// 1. No-op if no PID file requested.
	if pidFile == "" {
		return func() {}, nil
	}

	// 2. Open the file with read-write permissions. We don't use
	// O_TRUNC yet because we haven't secured the lock.
	f, err := os.OpenFile(pidFile, os.O_RDWR|os.O_CREATE, 0o644) //nolint:gosec // pid file
	if err != nil {
		return nil, fmt.Errorf("open pid file: %w", err)
	}

	// 3. Acquire an exclusive non-blocking lock. If another
	// process has the file open and locked, this fails immediately.
	//
	// Bounds-check the file descriptor before the int cast: on
	// systems with extreme RLIMIT_NOFILE settings (or future Go
	// changes that make Fd return a wider type) a descriptor that
	// overflows int32 would silently truncate to a wrong value
	// and Flock would lock the wrong fd or return ENOENT.
	fd := f.Fd()
	if fd > math.MaxInt32 {
		_ = f.Close()
		return nil, fmt.Errorf("pid file %q descriptor %d exceeds int32 range", pidFile, fd)
	}
	if err := syscall.Flock(int(fd), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, fmt.Errorf("pid file %q is locked by another instance", pidFile)
		}
		return nil, fmt.Errorf("lock pid file: %w", err)
	}

	// 4. Now that we have the lock, safely overwrite the content.
	// Truncation matters because the file may already exist from a
	// prior crashed run; a stale longer PID would otherwise trail
	// the new one.
	if err := f.Truncate(0); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("truncate pid file: %w", err)
	}
	if _, err := f.WriteAt([]byte(strconv.Itoa(os.Getpid())+"\n"), 0); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("write pid file: %w", err)
	}

	// 5. Cleanup: Remove FIRST so a new daemon instance starting
	// concurrently with our shutdown sees a clean slate. The
	// previous "Close before Remove" ordering raced — Close
	// released the flock, a new daemon could OpenFile + Flock
	// the same path, then our Remove deleted its fresh PID file.
	// Removing first makes the new daemon CREATE a new inode at
	// the path; our orphan inode dies on the subsequent Close.
	cleanup := func() {
		_ = os.Remove(pidFile)
		_ = f.Close()
	}
	return cleanup, nil
}

// StatusOpts holds configuration for the status command.
type StatusOpts struct {
	EvidenceDir string
	PIDFile     string
}

// RunStatus reports daemon status and archive coverage.
func RunStatus(opts StatusOpts) string {
	var b strings.Builder

	fmt.Fprintf(&b, "STAVE COLLECT STATUS\n")
	fmt.Fprintf(&b, "Archive: %s\n\n", opts.EvidenceDir)

	// Daemon status from PID file.
	daemonStatus := "NOT RUNNING"
	if opts.PIDFile != "" {
		if data, err := os.ReadFile(opts.PIDFile); err == nil {
			pidStr := strings.TrimSpace(string(data))
			pid, parseErr := strconv.Atoi(pidStr)
			switch {
			case parseErr != nil:
				// Corrupt PID file (whitespace-only, partial write
				// from a crashed daemon, manual edit). Surface as
				// UNKNOWN rather than silently treating as
				// "NOT RUNNING" — operators otherwise assume the
				// daemon stopped cleanly when they should be
				// removing the corrupt PID file.
				daemonStatus = fmt.Sprintf("UNKNOWN (PID file corrupt: %v)", parseErr)
			case pid > 0:
				proc, findErr := os.FindProcess(pid)
				if findErr != nil {
					// FindProcess only fails on platforms that
					// don't return a process handle synthetically
					// (Windows). Surface the cause so operators
					// can tell apart "daemon is gone" from
					// "platform refused to look it up".
					slog.Warn("collect daemon status: os.FindProcess failed",
						"pid", pid, "error", findErr)
					daemonStatus = fmt.Sprintf("UNKNOWN (FindProcess failed for PID %d: %v)", pid, findErr)
					break
				}
				if sigErr := proc.Signal(syscall.Signal(0)); sigErr == nil {
					daemonStatus = fmt.Sprintf("RUNNING (PID %d)", pid)
				} else {
					daemonStatus = fmt.Sprintf("STOPPED (stale PID %d)", pid)
				}
			}
		}
	}
	fmt.Fprintf(&b, "Daemon: %s\n\n", daemonStatus)

	// List runs from manifest.
	archive := &Archive{Path: opts.EvidenceDir}
	manifest, err := archive.LoadManifest()
	if err != nil || len(manifest.Runs) == 0 {
		fmt.Fprintf(&b, "No bundles found.\n")
		return b.String()
	}

	fmt.Fprintf(&b, "PERIOD COVERAGE (last 10)\n")
	start := max(len(manifest.Runs)-10, 0)
	for i := len(manifest.Runs) - 1; i >= start; i-- {
		r := &manifest.Runs[i]
		fmt.Fprintf(&b, "  %s  ✓  %d findings\n", r.CollectedAt, r.FindingCount)
	}

	if len(manifest.Gaps) > 0 {
		fmt.Fprintf(&b, "\nGAPS: %d detected\n", len(manifest.Gaps))
	} else {
		fmt.Fprintf(&b, "\nNo gaps detected.\n")
	}

	fmt.Fprintf(&b, "\nArchive: %d bundles\n", len(manifest.Runs))
	return b.String()
}
