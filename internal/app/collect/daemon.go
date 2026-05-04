package collect

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
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

	// Open + flock the PID file so a second daemon instance with the
	// same --pid-file fails fast at startup instead of racing with
	// the first. The file handle stays open for the lifetime of the
	// daemon — the kernel releases the advisory lock on close
	// (defer below). The previous shape just wrote and closed,
	// leaving nothing to detect a concurrent start.
	if opts.PIDFile != "" {
		f, err := os.OpenFile(opts.PIDFile, os.O_RDWR|os.O_CREATE, 0o644) //nolint:gosec // pid file
		if err != nil {
			return fmt.Errorf("open pid file: %w", err)
		}
		if lockErr := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); lockErr != nil { //nolint:gosec // file descriptors fit in int on every supported platform
			_ = f.Close()
			if errors.Is(lockErr, syscall.EWOULDBLOCK) {
				return fmt.Errorf("pid file %s is locked by another daemon instance", opts.PIDFile)
			}
			return fmt.Errorf("acquire pid file lock: %w", lockErr)
		}
		// Truncate + write the current PID. Truncation matters because
		// the file may already exist (left over from a prior run that
		// crashed without cleanup); a stale longer PID would otherwise
		// trail the new one.
		if truncErr := f.Truncate(0); truncErr != nil {
			_ = f.Close()
			return fmt.Errorf("truncate pid file: %w", truncErr)
		}
		if _, writeErr := f.WriteAt([]byte(strconv.Itoa(os.Getpid())+"\n"), 0); writeErr != nil {
			_ = f.Close()
			return fmt.Errorf("write pid file: %w", writeErr)
		}
		defer func() {
			// Close releases the flock; unlink so a future daemon
			// can start cleanly. Order matters: close before unlink
			// so an inflight signal handler can still see the file.
			_ = f.Close()
			_ = os.Remove(opts.PIDFile)
		}()
	}

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
		if data, err := os.ReadFile(opts.PIDFile); err == nil { //nolint:gosec
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
				if findErr == nil {
					if sigErr := proc.Signal(syscall.Signal(0)); sigErr == nil {
						daemonStatus = fmt.Sprintf("RUNNING (PID %d)", pid)
					} else {
						daemonStatus = fmt.Sprintf("STOPPED (stale PID %d)", pid)
					}
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
